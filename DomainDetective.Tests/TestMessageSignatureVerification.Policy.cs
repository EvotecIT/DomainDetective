using DnsClientX;
using MimeKit;
using System.IO;

namespace DomainDetective.Tests;

public partial class TestMessageSignatureVerification {
    [Theory]
    [InlineData("v=DKIM1; k=rsa;", MessageSignatureStatus.Valid)]
    [InlineData("k=rsa;", MessageSignatureStatus.Valid)]
    [InlineData("v=DKIM1; h=sha256; s=email; t=y:s; k=rsa;", MessageSignatureStatus.Valid)]
    [InlineData("v=DKIM2; k=rsa;", MessageSignatureStatus.Invalid)]
    [InlineData("v=DKIM10; k=rsa;", MessageSignatureStatus.Invalid)]
    [InlineData("k=rsa; v=DKIM1;", MessageSignatureStatus.Invalid)]
    [InlineData("v=DKIM1; h=sha1; k=rsa;", MessageSignatureStatus.Invalid)]
    [InlineData("v=DKIM1; s=other; k=rsa;", MessageSignatureStatus.Invalid)]
    [InlineData("v=DKIM1; p=QUJD; k=rsa;", MessageSignatureStatus.Invalid)]
    public async Task KeyPolicyConstrainsRealSignaturesAndDnsAssessment(string policy, MessageSignatureStatus expected) {
        var sample = SignedMessage();
        string key = sample.Options.PublicKeyRecords.Single().Value.Split(new[] { "p=" }, StringSplitOptions.None)[1];
        string record = policy + " p=" + key;
        sample.Options.PublicKeyRecords["s1._domainkey.example.com"] = record;
        using var health = new DomainHealthCheck();
        var verified = await health.AnalyzeMessageAsync(sample.Bytes, sample.Options);
        var signature = Assert.Single(verified.SignatureVerification);
        Assert.True(expected == signature.Status, signature.Explanation);
        var dns = new DkimAnalysis();
        await dns.AnalyzeDkimRecords("s1", new[] { new DnsAnswer { Type = DnsRecordType.TXT, DataRaw = record } }, new InternalLogger());
        Assert.Equal(expected == MessageSignatureStatus.Valid, dns.Assessments.Any(a => a.Code == DkimCodes.SelectorsValid));
    }

    [Theory]
    [InlineData("", MessageSignatureStatus.Valid)]
    [InlineData("t=s;", MessageSignatureStatus.Invalid)]
    public async Task IdentityRestrictionIsCheckedAgainstTheSignedAuid(string policy, MessageSignatureStatus expected) {
        var sample = SignedMessage(identity: "user@child.example.com");
        sample.Options.PublicKeyRecords["s1._domainkey.example.com"] = policy + sample.Options.PublicKeyRecords.Single().Value.Replace("v=DKIM1; ", string.Empty);
        using var health = new DomainHealthCheck();
        var signature = Assert.Single((await health.AnalyzeMessageAsync(sample.Bytes, sample.Options)).SignatureVerification);
        Assert.True(expected == signature.Status, signature.Explanation);
    }

    [Fact]
    public async Task RetrievedKeyPolicyAlsoConstrainsVerification() {
        var sample = SignedMessage();
        string key = sample.Options.PublicKeyRecords.Single().Value.Replace("v=DKIM1;", "v=DKIM1; h=sha1;");
        sample.Options.PublicKeyRecords.Clear();
        sample.Options.AllowDnsLookups = true;
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, _) => Task.FromResult(new[] { new DnsAnswer { Type = DnsRecordType.TXT, DataRaw = key } });
        var signature = Assert.Single((await health.AnalyzeMessageAsync(sample.Bytes, sample.Options)).SignatureVerification);
        Assert.Equal(MessageSignatureStatus.Invalid, signature.Status);
        Assert.True(signature.UsedDns);
    }

    [Fact]
    public async Task InternationalizedSelectorUsesALabelDnsNameForSignedMessage() {
        var sample = SignedMessage(selector: "bücher");
        string record = sample.Options.PublicKeyRecords.Single().Value;
        sample.Options.PublicKeyRecords.Clear();
        sample.Options.AllowDnsLookups = true;
        using var health = new DomainHealthCheck();
        var names = new List<string>();
        health.DnsConfiguration.QueryDnsOverride = (name, _) => {
            names.Add(name);
            return Task.FromResult(new[] { new DnsAnswer { Type = DnsRecordType.TXT, DataRaw = record } });
        };
        var result = Assert.Single((await health.AnalyzeMessageAsync(sample.Bytes, sample.Options)).SignatureVerification);
        Assert.True(result.Status == MessageSignatureStatus.Valid, result.Explanation);
        Assert.Equal("bücher", result.Selector);
        Assert.Equal("xn--bcher-kva._domainkey.example.com", Assert.Single(names));
    }

    [Fact]
    public async Task InternationalizedArcSelectorUsesTheSameDnsNameContract() {
        var sample = SignedMessage();
        using var input = new MemoryStream(sample.Bytes);
        var message = MimeMessage.Load(input);
        new TestArcSigner("bücher").Sign(message, new[] { HeaderId.From, HeaderId.To, HeaderId.Subject, HeaderId.Date });
        var options = new MessageVerificationOptions();
        string record = sample.Options.PublicKeyRecords.Single().Value;
        options.PublicKeyRecords["s1._domainkey.example.com"] = record;
        options.PublicKeyRecords["bücher._domainkey.example.com"] = record;
        using var output = new MemoryStream();
        message.WriteTo(output);
        using var health = new DomainHealthCheck();
        var analysis = await health.AnalyzeMessageAsync(output.ToArray(), options);
        var arc = Assert.Single(analysis.SignatureVerification, result => result.Method == "ARC");
        Assert.True(arc.Status == MessageSignatureStatus.Valid, arc.Explanation);
    }

    [Fact]
    public async Task ArcInstanceGroupingDoesNotDependOnPhysicalSealOrder() {
        var sample = SignedMessage();
        using var input = new MemoryStream(sample.Bytes);
        var message = MimeMessage.Load(input);
        var signer = new TestArcSigner();
        for (int i = 0; i < 3; i++) signer.Sign(message, new[] { HeaderId.From, HeaderId.To, HeaderId.Subject, HeaderId.Date });
        var indexes = message.Headers.Select((header, index) => (header, index)).Where(pair => pair.header.Id == HeaderId.ArcSeal).Select(pair => pair.index).ToArray();
        var seals = indexes.Select(index => message.Headers[index]).ToArray();
        var reordered = new[] { seals[0], seals[2], seals[1] };
        for (int i = 0; i < indexes.Length; i++) message.Headers[indexes[i]] = reordered[i];
        using var output = new MemoryStream();
        message.WriteTo(output);
        using var health = new DomainHealthCheck();
        var analysis = await health.AnalyzeMessageAsync(output.ToArray(), sample.Options);
        Assert.True(analysis.ArcStructure.ValidChain, string.Join(" ", analysis.ArcStructure.StructureIssues));
        var arc = Assert.Single(analysis.SignatureVerification, result => result.Method == "ARC");
        Assert.True(arc.Status == MessageSignatureStatus.Valid, arc.Explanation);
    }
}
