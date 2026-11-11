using DnsClientX;
using MimeKit;
using MimeKit.Cryptography;

namespace DomainDetective.Tests;

/// <summary>Independent policy-discovery comparison; no live DNS or message delivery.</summary>
public sealed class TestDmarcMimeKitQualification {
    [Theory]
    [InlineData("example.com", "example.com", "v=DMARC1; p=reject; psd=n", "example.com")]
    [InlineData("child.example.com", "example.com", "v=DMARC1; p=reject; psd=n", "example.com")]
    [InlineData("child.example.com", "com", "v=DMARC1; p=reject; psd=y", "example.com")]
    public async Task DomainAuditAndMimeKitAgreeOnValidPolicyDiscovery(string authorDomain, string policyDomain, string record, string organization) {
        using var dns = new DnsConfiguration();
        dns.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(new DnsResponse {
            Status = DnsResponseCode.NoError,
            Answers = name == "_dmarc." + policyDomain && type == DnsRecordType.TXT
                ? new[] { new DnsAnswer { Type = DnsRecordType.TXT, DataRaw = record } } : Array.Empty<DnsAnswer>()
        });
        var audit = await new DmarcPolicyDiscovery((name, token) => dns.QueryDNS(name, DnsRecordType.TXT, cancellationToken: token))
            .DiscoverAsync(authorDomain, default);
        using var message = new MimeMessage();
        message.From.Add(MailboxAddress.Parse("sender@" + authorDomain));
        message.Body = new TextPart("plain") { Text = "Synthetic policy comparison" };
        var resolver = new MessageDnsResolver(new MessageVerificationOptions { AllowDnsLookups = true }, dns);
        var verification = await new DmarcVerifier(resolver).VerifyAsync(message, Array.Empty<DkimSignatureValidationResult>(), null);

        Assert.Equal(policyDomain, audit.Policy?.Domain);
        Assert.Equal(policyDomain, verification.PolicyDomain);
        Assert.Equal(organization, audit.OrganizationalDomain);
        Assert.Equal(organization, verification.OrganizationalDomain);
        Assert.Equal(DmarcStatus.Fail, verification.Status);
    }
}
