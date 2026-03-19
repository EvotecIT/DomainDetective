using DomainDetective;
using DomainDetective.Reports;
using Xunit;

namespace DomainDetective.Tests;

public class TestSectionOrdering {
    [Theory]
    [InlineData("tlsrpt", "TLS-RPT")]
    [InlineData("mtasts", "MTA-STS")]
    [InlineData("zone-transfer", "ZoneTransfer")]
    [InlineData("ZoneXfr", "ZoneTransfer")]
    [InlineData("wildcarddns", "Wildcard")]
    [InlineData("mailclassification", "Classification")]
    [InlineData("smtpTls", "MAILTLS")]
    [InlineData("imapTls", "MAILTLS")]
    [InlineData("pop3tls", "MAILTLS")]
    [InlineData("m365", "Microsoft 365")]
    [InlineData("microsoft365", "Microsoft 365")]
    public void NormalizeSection_MapsSynonyms(string input, string expected) {
        Assert.Equal(expected, SectionOrdering.NormalizeSection(input));
    }

    [Theory]
    [InlineData(HealthCheckType.MX, "MX")]
    [InlineData(HealthCheckType.SPF, "SPF")]
    [InlineData(HealthCheckType.DKIM, "DKIM")]
    [InlineData(HealthCheckType.DMARC, "DMARC")]
    [InlineData(HealthCheckType.ARC, "ARC")]
    [InlineData(HealthCheckType.BIMI, "BIMI")]
    [InlineData(HealthCheckType.DNSBL, "DNSBL")]
    [InlineData(HealthCheckType.RPKI, "RPKI")]
    [InlineData(HealthCheckType.NS, "NS")]
    [InlineData(HealthCheckType.SOA, "SOA")]
    [InlineData(HealthCheckType.ZONETRANSFER, "ZoneTransfer")]
    [InlineData(HealthCheckType.WILDCARDDNS, "Wildcard")]
    [InlineData(HealthCheckType.CAA, "CAA")]
    [InlineData(HealthCheckType.MAILCLASSIFICATION, "Classification")]
    [InlineData(HealthCheckType.MTASTS, "MTA-STS")]
    [InlineData(HealthCheckType.TLSRPT, "TLS-RPT")]
    [InlineData(HealthCheckType.DNSSEC, "DNSSEC")]
    [InlineData(HealthCheckType.DANE, "DANE")]
    [InlineData(HealthCheckType.SMTPTLS, "MAILTLS")]
    [InlineData(HealthCheckType.IMAPTLS, "MAILTLS")]
    [InlineData(HealthCheckType.POP3TLS, "MAILTLS")]
    [InlineData(HealthCheckType.MICROSOFT365, "Microsoft 365")]
    public void SectionKeyFor_MapsHealthCheckType(HealthCheckType check, string expected) {
        Assert.Equal(expected, SectionOrdering.SectionKeyFor(check));
    }
}
