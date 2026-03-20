using Xunit;

namespace DomainDetective.Tests;

public class TestGetAnalysisMap
{
    [Fact]
    public void ReturnsDictionaryWithAllAnalyses()
    {
        var healthCheck = new DomainHealthCheck();
        var map = healthCheck.GetAnalysisMap();

        Assert.Equal(Enum.GetValues(typeof(HealthCheckType)).Length, map.Count);

        foreach (HealthCheckType type in Enum.GetValues(typeof(HealthCheckType)))
        {
            Assert.True(map.TryGetValue(type, out var actual));
            var expected = GetExpectedAnalysis(healthCheck, type);
            if (type == HealthCheckType.WEBSITE)
            {
                Assert.IsType<DomainDetective.Views.WebsiteInfo>(actual);
                continue;
            }

            Assert.Same(expected, actual);
        }
    }

    private static object? GetExpectedAnalysis(DomainHealthCheck healthCheck, HealthCheckType type)
    {
        switch (type)
        {
            case HealthCheckType.DMARC:
                return healthCheck.DmarcAnalysis;
            case HealthCheckType.SPF:
                return healthCheck.SpfAnalysis;
            case HealthCheckType.DKIM:
                return healthCheck.DKIMAnalysis;
            case HealthCheckType.MX:
                return healthCheck.MXAnalysis;
            case HealthCheckType.REVERSEDNS:
                return healthCheck.ReverseDnsAnalysis;
            case HealthCheckType.FCRDNS:
                return healthCheck.FcrDnsAnalysis;
            case HealthCheckType.CAA:
                return healthCheck.CAAAnalysis;
            case HealthCheckType.NS:
            case HealthCheckType.DELEGATION:
                return healthCheck.NSAnalysis;
            case HealthCheckType.ZONETRANSFER:
                return healthCheck.ZoneTransferAnalysis;
            case HealthCheckType.DANE:
                return healthCheck.DaneAnalysis;
            case HealthCheckType.SMIMEA:
                return healthCheck.SmimeaAnalysis;
            case HealthCheckType.DNSBL:
                return healthCheck.DNSBLAnalysis;
            case HealthCheckType.DNSSEC:
                return healthCheck.DnsSecAnalysis;
            case HealthCheckType.MTASTS:
                return healthCheck.MTASTSAnalysis;
            case HealthCheckType.TLSRPT:
                return healthCheck.TLSRPTAnalysis;
            case HealthCheckType.BIMI:
                return healthCheck.BimiAnalysis;
            case HealthCheckType.IDENTITYPROVIDER:
                return healthCheck.IdpInfoAnalysis;
            case HealthCheckType.AUTODISCOVER:
                return healthCheck.AutodiscoverAnalysis;
            case HealthCheckType.CERT:
                return healthCheck.CertificateAnalysis;
            case HealthCheckType.SECURITYTXT:
                return healthCheck.SecurityTXTAnalysis;
            case HealthCheckType.ROBOTS:
                return healthCheck.RobotsTxtAnalysis;
            case HealthCheckType.SOA:
                return healthCheck.SOAAnalysis;
            case HealthCheckType.OPENRELAY:
                return healthCheck.OpenRelayAnalysis;
            case HealthCheckType.OPENRESOLVER:
                return healthCheck.OpenResolverAnalysis;
            case HealthCheckType.STARTTLS:
                return healthCheck.StartTlsAnalysis;
            case HealthCheckType.SMTPTLS:
                return healthCheck.SmtpTlsAnalysis;
            case HealthCheckType.IMAPTLS:
                return healthCheck.ImapTlsAnalysis;
            case HealthCheckType.POP3TLS:
                return healthCheck.Pop3TlsAnalysis;
            case HealthCheckType.SMTPBANNER:
                return healthCheck.SmtpBannerAnalysis;
            case HealthCheckType.SMTPAUTH:
                return healthCheck.SmtpAuthAnalysis;
            case HealthCheckType.HTTP:
                return healthCheck.HttpAnalysis;
            case HealthCheckType.HPKP:
                return healthCheck.HPKPAnalysis;
            case HealthCheckType.CONTACT:
                return healthCheck.ContactInfoAnalysis;
            case HealthCheckType.MESSAGEHEADER:
                return healthCheck.MessageHeaderAnalysis;
            case HealthCheckType.ARC:
                return healthCheck.ArcAnalysis;
            case HealthCheckType.DANGLINGCNAME:
                return healthCheck.DanglingCnameAnalysis;
            case HealthCheckType.TTL:
                return healthCheck.DnsTtlAnalysis;
            case HealthCheckType.PORTAVAILABILITY:
                return healthCheck.PortAvailabilityAnalysis;
            case HealthCheckType.PORTSCAN:
                return healthCheck.PortScanAnalysis;
            case HealthCheckType.SNMP:
                return healthCheck.SnmpAnalysis;
            case HealthCheckType.IPNEIGHBOR:
                return healthCheck.IPNeighborAnalysis;
            case HealthCheckType.IPENRICHMENT:
                return healthCheck.IpEnrichmentAnalysis;
            case HealthCheckType.RPKI:
                return healthCheck.RpkiAnalysis;
            case HealthCheckType.DNSTUNNELING:
                return healthCheck.DnsTunnelingAnalysis;
            case HealthCheckType.TYPOSQUATTING:
                return healthCheck.TyposquattingAnalysis;
            case HealthCheckType.THREATINTEL:
                return healthCheck.ThreatIntelAnalysis;
            case HealthCheckType.THREATFEED:
                return healthCheck.ThreatFeedAnalysis;
            case HealthCheckType.WILDCARDDNS:
                return healthCheck.WildcardDnsAnalysis;
            case HealthCheckType.EDNSSUPPORT:
                return healthCheck.EdnsSupportAnalysis;
            case HealthCheckType.DNSHEALTH:
                return healthCheck.DnsHealthAnalysis;
            case HealthCheckType.MAILLATENCY:
                return healthCheck.MailLatencyAnalysis;
            case HealthCheckType.FLATTENINGSERVICE:
                return healthCheck.FlatteningServiceAnalysis;
            case HealthCheckType.RDAP:
                return healthCheck.RdapAnalysis;
            case HealthCheckType.DIRECTORYEXPOSURE:
                return healthCheck.DirectoryExposureAnalysis;
            case HealthCheckType.NTP:
                return healthCheck.NtpAnalysis;
            case HealthCheckType.WHOIS:
                return healthCheck.WhoisAnalysis;
            case HealthCheckType.APEXADDRESS:
                return healthCheck.ApexAddressAnalysis;
            case HealthCheckType.SPFFLATTENED:
                return healthCheck.SpfAnalysis.FlattenedIpAnalysis;
            case HealthCheckType.SUBDOMAINS:
                return healthCheck.SubdomainsAnalysis;
            case HealthCheckType.DNSINVENTORY:
                return healthCheck.DnsInventoryAnalysis;
            case HealthCheckType.DNSTRACE:
                return healthCheck.DnsTraceAnalysis;
            case HealthCheckType.CTTIMELINE:
                return healthCheck.CtTimelineAnalysis;
            case HealthCheckType.DNSPROPAGATION:
                return healthCheck.DnsPropagationSet;
            case HealthCheckType.DNSAMPLIFICATION:
                return healthCheck.DnsAmplificationAnalysis;
            case HealthCheckType.DNSOVERTLS:
                return healthCheck.DnsOverTlsAnalysis;
            case HealthCheckType.MICROSOFT365:
                return healthCheck.Microsoft365TenantAnalysis;
            case HealthCheckType.WEBSITE:
            case HealthCheckType.MAILCLASSIFICATION:
            default:
                return null;
        }
    }
}
