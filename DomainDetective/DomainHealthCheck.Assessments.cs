using System;
using System.Collections.Generic;

namespace DomainDetective;

public partial class DomainHealthCheck
{
    private static readonly Func<DomainHealthCheck, IHasAssessments?>[] _assessmentProviderGetters =
    {
        static h => h.DmarcAnalysis,
        static h => h.SpfAnalysis,
        static h => h.DKIMAnalysis,
        static h => h.MXAnalysis,
        static h => h.ReverseDnsAnalysis,
        static h => h.CAAAnalysis,
        static h => h.NSAnalysis,
        static h => h.DaneAnalysis,
        static h => h.SmimeaAnalysis,
        static h => h.DNSBLAnalysis,
        static h => h.DnsSecAnalysis,
        static h => h.MTASTSAnalysis,
        static h => h.CertificateAnalysis,
        static h => h.SecurityTXTAnalysis,
        static h => h.RobotsTxtAnalysis,
        static h => h.SitemapAnalysis,
        static h => h.SOAAnalysis,
        static h => h.WhoisAnalysis,
        static h => h.RdapAnalysis,
        static h => h.ZoneTransferAnalysis,
        static h => h.OpenRelayAnalysis,
        static h => h.OpenResolverAnalysis,
        static h => h.StartTlsAnalysis,
        static h => h.SmtpTlsAnalysis,
        static h => h.ImapTlsAnalysis,
        static h => h.Pop3TlsAnalysis,
        static h => h.SmtpBannerAnalysis,
        static h => h.MailLatencyAnalysis,
        static h => h.SmtpAuthAnalysis,
        static h => h.TLSRPTAnalysis,
        static h => h.BimiAnalysis,
        static h => h.IdpInfoAnalysis,
        static h => h.Microsoft365TenantAnalysis,
        static h => h.AutodiscoverAnalysis,
        static h => h.AutodiscoverHttpAnalysis,
        static h => h.HttpAnalysis,
        static h => h.HPKPAnalysis,
        static h => h.ContactInfoAnalysis,
        static h => h.MessageHeaderAnalysis,
        static h => h.ArcAnalysis,
        static h => h.DanglingCnameAnalysis,
        static h => h.DnsTtlAnalysis,
        static h => h.PortAvailabilityAnalysis,
        static h => h.PortScanAnalysis,
        static h => h.SnmpAnalysis,
        static h => h.IPNeighborAnalysis,
        static h => h.RpkiAnalysis,
        static h => h.DnsTunnelingAnalysis,
        static h => h.TyposquattingAnalysis,
        static h => h.ThreatIntelAnalysis,
        static h => h.ThreatFeedAnalysis,
        static h => h.WildcardDnsAnalysis,
        static h => h.EdnsSupportAnalysis,
        static h => h.DnsAmplificationAnalysis,
        static h => h.DnsOverTlsAnalysis,
        static h => h.FlatteningServiceAnalysis,
        static h => h.TakeoverCnameAnalysis,
        static h => h.DirectoryExposureAnalysis,
        static h => h.DnsHealthAnalysis,
        static h => h.NtpAnalysis,
        static h => h.WebStaticScanAnalysis,
        static h => h.AgentReadinessAnalysis,
        static h => h.SubdomainsAnalysis,
        static h => h.DnsInventoryAnalysis,
        static h => h.DnsTraceAnalysis,
        static h => h.CtTimelineAnalysis,
        static h => h.IpEnrichmentAnalysis,
        static h => h.DnsPropagationSet
    };

    /// <summary>
    /// Aggregated assessments collected from all analyses that expose them.
    /// </summary>
    public IEnumerable<Assessment> GetAllAssessments()
    {
        foreach (var has in GetAssessmentProviders())
        {
            var list = has.Assessments;
            if (list == null || list.Count == 0)
            {
                continue;
            }

            foreach (var a in list)
            {
                yield return a;
            }
        }
    }

    /// <summary>Gets assessment providers.</summary>
    public IEnumerable<IHasAssessments> GetAssessmentProviders()
    {
        for (var i = 0; i < _assessmentProviderGetters.Length; i++)
        {
            var has = _assessmentProviderGetters[i](this);
            if (has != null)
            {
                yield return has;
            }
        }
    }
}
