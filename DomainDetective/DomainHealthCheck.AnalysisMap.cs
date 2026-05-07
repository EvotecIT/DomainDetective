using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>
/// Provides helper methods mapping health check types to results.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public partial class DomainHealthCheck
{
    private static readonly HealthCheckType[] _healthCheckTypes =
        (HealthCheckType[])Enum.GetValues(typeof(HealthCheckType));

    /// <summary>
    /// Creates a dictionary mapping each <see cref="HealthCheckType"/> to
    /// the corresponding analysis result instance.
    /// </summary>
    /// <returns>Read-only dictionary of health check results.</returns>
    public IReadOnlyDictionary<HealthCheckType, object?> GetAnalysisMap()
    {
        var map = new Dictionary<HealthCheckType, object?>(_healthCheckTypes.Length);
        for (var i = 0; i < _healthCheckTypes.Length; i++)
        {
            var type = _healthCheckTypes[i];
            map[type] = GetAnalysisFor(type);
        }
        return map;
    }

    /// <summary>
    /// Gets the analysis result instance for a single health check type.
    /// </summary>
    internal object? GetAnalysisFor(HealthCheckType type)
    {
        switch (type)
        {
            case HealthCheckType.DMARC:
                return DmarcAnalysis;
            case HealthCheckType.SPF:
                return SpfAnalysis;
            case HealthCheckType.DKIM:
                return DKIMAnalysis;
            case HealthCheckType.MX:
                return MXAnalysis;
            case HealthCheckType.REVERSEDNS:
                return ReverseDnsAnalysis;
            case HealthCheckType.FCRDNS:
                return FcrDnsAnalysis;
            case HealthCheckType.CAA:
                return CAAAnalysis;
            case HealthCheckType.NS:
                return NSAnalysis;
            case HealthCheckType.DELEGATION:
                return NSAnalysis;
            case HealthCheckType.ZONETRANSFER:
                return ZoneTransferAnalysis;
            case HealthCheckType.DANE:
                return DaneAnalysis;
            case HealthCheckType.SMIMEA:
                return SmimeaAnalysis;
            case HealthCheckType.DNSBL:
                return DNSBLAnalysis;
            case HealthCheckType.DNSSEC:
                return DnsSecAnalysis;
            case HealthCheckType.MTASTS:
                return MTASTSAnalysis;
            case HealthCheckType.TLSRPT:
                return TLSRPTAnalysis;
            case HealthCheckType.BIMI:
                return BimiAnalysis;
            case HealthCheckType.IDENTITYPROVIDER:
                return IdpInfoAnalysis;
            case HealthCheckType.AUTODISCOVER:
                return AutodiscoverAnalysis;
            case HealthCheckType.CERT:
                return CertificateAnalysis;
            case HealthCheckType.SECURITYTXT:
                return SecurityTXTAnalysis;
            case HealthCheckType.ROBOTS:
                return RobotsTxtAnalysis;
            case HealthCheckType.SITEMAP:
                return SitemapAnalysis;
            case HealthCheckType.SOA:
                return SOAAnalysis;
            case HealthCheckType.OPENRELAY:
                return OpenRelayAnalysis;
            case HealthCheckType.OPENRESOLVER:
                return OpenResolverAnalysis;
            case HealthCheckType.STARTTLS:
                return StartTlsAnalysis;
            case HealthCheckType.SMTPTLS:
                return SmtpTlsAnalysis;
            case HealthCheckType.IMAPTLS:
                return ImapTlsAnalysis;
            case HealthCheckType.POP3TLS:
                return Pop3TlsAnalysis;
            case HealthCheckType.SMTPBANNER:
                return SmtpBannerAnalysis;
            case HealthCheckType.SMTPAUTH:
                return SmtpAuthAnalysis;
            case HealthCheckType.HTTP:
                return HttpAnalysis;
            case HealthCheckType.HPKP:
                return HPKPAnalysis;
            case HealthCheckType.CONTACT:
                return ContactInfoAnalysis;
            case HealthCheckType.MESSAGEHEADER:
                return MessageHeaderAnalysis;
            case HealthCheckType.ARC:
                return ArcAnalysis;
            case HealthCheckType.DANGLINGCNAME:
                return DanglingCnameAnalysis;
            case HealthCheckType.TTL:
                return DnsTtlAnalysis;
            case HealthCheckType.PORTAVAILABILITY:
                return PortAvailabilityAnalysis;
            case HealthCheckType.PORTSCAN:
                return PortScanAnalysis;
            case HealthCheckType.SNMP:
                return SnmpAnalysis;
            case HealthCheckType.IPNEIGHBOR:
                return IPNeighborAnalysis;
            case HealthCheckType.IPENRICHMENT:
                return IpEnrichmentAnalysis;
            case HealthCheckType.RPKI:
                return RpkiAnalysis;
            case HealthCheckType.DNSTUNNELING:
                return DnsTunnelingAnalysis;
            case HealthCheckType.TYPOSQUATTING:
                return TyposquattingAnalysis;
            case HealthCheckType.THREATINTEL:
                return ThreatIntelAnalysis;
            case HealthCheckType.THREATFEED:
                return ThreatFeedAnalysis;
            case HealthCheckType.WILDCARDDNS:
                return WildcardDnsAnalysis;
            case HealthCheckType.EDNSSUPPORT:
                return EdnsSupportAnalysis;
            case HealthCheckType.DNSHEALTH:
                return DnsHealthAnalysis;
            case HealthCheckType.MAILLATENCY:
                return MailLatencyAnalysis;
            case HealthCheckType.FLATTENINGSERVICE:
                return FlatteningServiceAnalysis;
            case HealthCheckType.RDAP:
                return RdapAnalysis;
            case HealthCheckType.DIRECTORYEXPOSURE:
                return DirectoryExposureAnalysis;
            case HealthCheckType.NTP:
                return NtpAnalysis;
            case HealthCheckType.AGENTREADINESS:
                return AgentReadinessAnalysis;
            case HealthCheckType.WHOIS:
                return WhoisAnalysis;
            case HealthCheckType.APEXADDRESS:
                return ApexAddressAnalysis;
            case HealthCheckType.SPFFLATTENED:
                return SpfAnalysis?.FlattenedIpAnalysis;
            case HealthCheckType.MAILCLASSIFICATION:
                return MailDomainClassification;
            case HealthCheckType.SUBDOMAINS:
                return SubdomainsAnalysis;
            case HealthCheckType.DNSINVENTORY:
                return DnsInventoryAnalysis;
            case HealthCheckType.DNSTRACE:
                return DnsTraceAnalysis;
            case HealthCheckType.CTTIMELINE:
                return CtTimelineAnalysis;
            case HealthCheckType.DNSPROPAGATION:
                return DnsPropagationSet;
            case HealthCheckType.DNSAMPLIFICATION:
                return DnsAmplificationAnalysis;
            case HealthCheckType.DNSOVERTLS:
                return DnsOverTlsAnalysis;
            case HealthCheckType.MICROSOFT365:
                return Microsoft365TenantAnalysis;
            case HealthCheckType.WEBSITE:
                return DomainDetective.Views.Converters.CombineWebsite(
                    DomainDetective.Views.Converters.Convert(CertificateAnalysis),
                    DomainDetective.Views.Converters.Convert(HttpAnalysis));
            default:
                return null;
        }
    }
}
