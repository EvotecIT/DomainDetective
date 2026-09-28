using MimeKit;
using MimeKit.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.IO;
using System.Text;

namespace DomainDetective.Tests;

public class TestMessageSignatureVerification {
    private static readonly Lazy<AsymmetricCipherKeyPair> Keys = new(() => {
        var generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        return generator.GenerateKeyPair();
    });

    private static (byte[] Bytes, MessageVerificationOptions Options) SignedMessage() {
        var message = new MimeMessage();
        message.From.Add(new MailboxAddress("Sender", "sender@example.com"));
        message.To.Add(new MailboxAddress("Recipient", "recipient@example.net"));
        message.Subject = "Original signed content";
        message.Date = DateTimeOffset.UtcNow;
        message.Body = new TextPart("plain") { Text = "Original body\r\n" };
        message.Prepare(EncodingConstraint.SevenBit);
        var signer = new DkimSigner(Keys.Value.Private, "example.com", "s1") {
            SignatureAlgorithm = DkimSignatureAlgorithm.RsaSha256,
            HeaderCanonicalizationAlgorithm = DkimCanonicalizationAlgorithm.Relaxed,
            BodyCanonicalizationAlgorithm = DkimCanonicalizationAlgorithm.Relaxed
        };
        signer.Sign(message, new[] { HeaderId.From, HeaderId.To, HeaderId.Subject, HeaderId.Date });
        using var stream = new MemoryStream();
        message.WriteTo(stream);
        var options = new MessageVerificationOptions();
        options.PublicKeyRecords["s1._domainkey.example.com"] = "v=DKIM1; k=rsa; p=" + Convert.ToBase64String(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(Keys.Value.Public).GetDerEncoded());
        return (stream.ToArray(), options);
    }

    [Fact]
    public async Task OriginalMessageVerifiesOfflineWithoutDns() {
        var sample = SignedMessage();
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, _) => throw new InvalidOperationException("Offline verification must not access DNS.");
        var analysis = await health.AnalyzeMessageAsync(sample.Bytes, sample.Options);
        var signature = Assert.Single(analysis.SignatureVerification);
        Assert.True(signature.Status == MessageSignatureStatus.Valid, signature.Explanation);
        Assert.False(signature.UsedDns);
        Assert.Null(analysis.DkimResult);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnsupportedQueryMethodCannotUseOfflineOrCachedDnsKey(bool cachedDns) {
        var sample = SignedMessage();
        var key = sample.Options.PublicKeyRecords.Single().Value;
        using var health = new DomainHealthCheck();
        var queries = 0;
        health.DnsConfiguration.QueryDnsOverride = (_, _) => {
            queries++;
            return Task.FromResult(new[] { new DnsClientX.DnsAnswer { DataRaw = key, Type = DnsClientX.DnsRecordType.TXT } });
        };
        if (cachedDns) { sample.Options.PublicKeyRecords.Clear(); sample.Options.AllowDnsLookups = true; }
        var locator = new MessagePublicKeyLocator(sample.Options, health.DnsConfiguration);
        if (cachedDns) { await locator.LocatePublicKeyAsync("dns/txt", "example.com", "s1"); }
        locator.BeginVerification();
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => locator.LocatePublicKeyAsync("unsupported", "example.com", "s1"));
        Assert.Contains("Only dns/txt", error.Message);
        Assert.Equal(cachedDns ? 1 : 0, queries);
        Assert.False(locator.UsedDns);
        await locator.LocatePublicKeyAsync("dns/txt", "example.com", "s1");
        Assert.Equal(cachedDns ? 1 : 0, queries);
    }

    [Theory]
    [InlineData("Original body", "Tampered body")]
    [InlineData("Original signed content", "Tampered signed content")]
    public async Task ModifiedSignedContentDoesNotVerify(string original, string replacement) {
        var sample = SignedMessage();
        var bytes = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(sample.Bytes).Replace(original, replacement));
        using var health = new DomainHealthCheck();
        var analysis = await health.AnalyzeMessageAsync(bytes, sample.Options);
        Assert.Equal(MessageSignatureStatus.Invalid, Assert.Single(analysis.SignatureVerification).Status);
    }

    [Fact]
    public async Task MissingOfflineKeyIsInconclusiveRatherThanInvalid() {
        var sample = SignedMessage();
        using var health = new DomainHealthCheck();
        var analysis = await health.AnalyzeMessageAsync(sample.Bytes);
        Assert.Equal(MessageSignatureStatus.Inconclusive, Assert.Single(analysis.SignatureVerification).Status);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedDnsKeyIsQueriedOnceAndDoesNotConsumeAnotherSelectorsBudget(bool malformed) {
        var sample = SignedMessage();
        var key = sample.Options.PublicKeyRecords.Single().Value;
        sample.Options.PublicKeyRecords.Clear();
        sample.Options.AllowDnsLookups = true;
        sample.Options.MaximumDnsQueries = 2;
        using var health = new DomainHealthCheck();
        var queries = new List<string>();
        health.DnsConfiguration.QueryDnsOverride = (host, _) => {
            queries.Add(host);
            return Task.FromResult(host.StartsWith("s1.", StringComparison.Ordinal) ? new[] { new DnsClientX.DnsAnswer { DataRaw = key, Type = DnsClientX.DnsRecordType.TXT } }
                : malformed ? new[] { new DnsClientX.DnsAnswer { DataRaw = "not a public key", Type = DnsClientX.DnsRecordType.TXT } } : Array.Empty<DnsClientX.DnsAnswer>());
        };
        using var input = new MemoryStream(sample.Bytes);
        var message = MimeMessage.Load(input);
        var signature = message.Headers.First(header => header.Id == HeaderId.DkimSignature);
        var missingSelector = signature.Value.Replace("s=s1", "s=missing");
        Assert.NotEqual(signature.Value, missingSelector);
        message.Headers.Insert(0, new Header(HeaderId.DkimSignature, missingSelector));
        message.Headers.Insert(0, new Header(HeaderId.DkimSignature, missingSelector));
        using var output = new MemoryStream();
        message.WriteTo(output);
        var analysis = await health.AnalyzeMessageAsync(output.ToArray(), sample.Options);
        Assert.Equal(new[] { "missing._domainkey.example.com", "s1._domainkey.example.com" }, queries);
        Assert.Equal(new[] { MessageSignatureStatus.Inconclusive, MessageSignatureStatus.Inconclusive, MessageSignatureStatus.Valid }, analysis.SignatureVerification.Select(value => value.Status));
    }

    [Fact]
    public async Task DnsKeyAcquisitionRequiresExplicitOptIn() {
        var sample = SignedMessage();
        var key = sample.Options.PublicKeyRecords.Single().Value;
        var queries = new List<string>();
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (host, _) => {
            queries.Add(host);
            return Task.FromResult(new[] { new DnsClientX.DnsAnswer { DataRaw = key, Type = DnsClientX.DnsRecordType.TXT } });
        };
        var result = await health.AnalyzeMessageAsync(sample.Bytes, new MessageVerificationOptions { AllowDnsLookups = true });
        Assert.True(queries.Count == 1, Assert.Single(result.SignatureVerification).Explanation);
        Assert.Equal("s1._domainkey.example.com", Assert.Single(queries));
        Assert.Equal(MessageSignatureStatus.Valid, Assert.Single(result.SignatureVerification).Status);
    }

    [Fact]
    public async Task SplitDnsTxtChunksVerifyTheOriginalMessage() {
        var sample = SignedMessage();
        var key = sample.Options.PublicKeyRecords.Single().Value;
        sample.Options.PublicKeyRecords.Clear();
        sample.Options.AllowDnsLookups = true;
        var split = 180;
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, _) => Task.FromResult(new[] {
            new DnsClientX.DnsAnswer { Type = DnsClientX.DnsRecordType.TXT,
                DataRaw = "\"" + key.Substring(0, split) + "\" \"" + key.Substring(split) + "\"" }
        });
        var result = await health.AnalyzeMessageAsync(sample.Bytes, sample.Options);
        Assert.Equal(MessageSignatureStatus.Valid, Assert.Single(result.SignatureVerification).Status);
    }

    [Fact]
    public async Task CompleteUnsignedMimeMessageIsReportedAsInspected() {
        var bytes = Encoding.UTF8.GetBytes("From: sender@example.org\r\nSubject: unsigned\r\n\r\nOriginal body\r\n");
        using var health = new DomainHealthCheck();
        var result = await health.AnalyzeMessageAsync(bytes);
        Assert.Empty(result.SignatureVerification);
        Assert.True(result.OriginalMessageInspectedForSignatures);
        var brief = DomainDetective.Reports.MessageHeaderReportBrief.Build(result);
        Assert.Contains(brief.Evidence, item => item.Contains("No DKIM or ARC signatures were present", StringComparison.Ordinal));
        Assert.Contains("No signatures present", DomainDetective.Reports.MessageHeaderReport.ToText(result));
    }

    [Fact]
    public async Task HeaderOnlyInputCannotClaimCryptographicValidity() {
        var sample = SignedMessage();
        var text = Encoding.UTF8.GetString(sample.Bytes);
        var boundary = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (boundary < 0) { boundary = text.IndexOf("\n\n", StringComparison.Ordinal); }
        using var health = new DomainHealthCheck();
        var result = await health.AnalyzeMessageAsync(Encoding.UTF8.GetBytes(text.Substring(0, boundary)), sample.Options);
        Assert.False(result.OriginalMessageInspectedForSignatures);
        Assert.Equal(MessageSignatureStatus.NotPerformed, Assert.Single(result.SignatureVerification).Status);
    }

    [Fact]
    public async Task SignatureQuotaProducesExplicitIncompleteOutcomes() {
        var sample = SignedMessage();
        using var input = new MemoryStream(sample.Bytes);
        var message = MimeMessage.Load(input);
        var signature = message.Headers.First(header => header.Id == HeaderId.DkimSignature);
        message.Headers.Insert(0, new Header(HeaderId.DkimSignature, signature.Value));
        using var output = new MemoryStream();
        message.WriteTo(output);
        sample.Options.MaximumDkimSignatures = 1;
        using var health = new DomainHealthCheck();
        var result = await health.AnalyzeMessageAsync(output.ToArray(), sample.Options);
        Assert.Equal(2, result.SignatureVerification.Count);
        Assert.Equal(MessageSignatureStatus.Valid, result.SignatureVerification[0].Status);
        Assert.Equal(MessageSignatureStatus.NotPerformed, result.SignatureVerification[1].Status);
        Assert.Contains("limit reached", result.SignatureVerification[1].Explanation);
    }

    private sealed class TestArcSigner : ArcSigner {
        internal TestArcSigner() : base(Keys.Value.Private, "example.com", "s1", DkimSignatureAlgorithm.RsaSha256) { }

        protected override AuthenticationResults GenerateArcAuthenticationResults(FormatOptions options, MimeMessage message, CancellationToken cancellationToken) {
            var results = new AuthenticationResults("mx.example.com");
            results.Results.Add(new AuthenticationMethodResult("dkim", "pass"));
            return results;
        }

        protected override Task<AuthenticationResults> GenerateArcAuthenticationResultsAsync(FormatOptions options, MimeMessage message, CancellationToken cancellationToken) {
            return Task.FromResult(GenerateArcAuthenticationResults(options, message, cancellationToken));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CryptographicArcVerificationDetectsModifiedMessage(bool tamper) {
        var sample = SignedMessage();
        using var input = new MemoryStream(sample.Bytes);
        var message = MimeMessage.Load(input);
        var signer = new TestArcSigner();
        signer.Sign(message, new[] { HeaderId.From, HeaderId.To, HeaderId.Subject, HeaderId.Date });
        if (tamper) { message.Subject = "Changed after ARC seal"; }
        using var output = new MemoryStream();
        message.WriteTo(output);
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, _) => throw new InvalidOperationException("ARC test must stay offline.");
        var analysis = await health.AnalyzeMessageAsync(output.ToArray(), sample.Options);
        var arc = Assert.Single(analysis.SignatureVerification, value => value.Method == "ARC");
        Assert.True(arc.Status == (tamper ? MessageSignatureStatus.Invalid : MessageSignatureStatus.Valid), arc.Explanation);
        Assert.True(analysis.ArcStructure.ValidChain, string.Join(" ", analysis.ArcStructure.StructureIssues));
        Assert.False(arc.UsedDns);
    }
}
