using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;
using DomainDetective;
using DomainDetective.Reports;
using DomainDetective.Views;
using DomainDetective.Narratives;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HtmlCompositionReport partial: ordered per-domain sections.
/// </summary>
public static partial class HtmlCompositionReport
{
    private static readonly string[] ProviderTopicOrder = new[] { "DMARC", "SPF", "DKIM", "ARC", "BIMI", "MTA-STS", "TLS-RPT", "DELIVERABILITY" };

    private static IReadOnlyList<string> GetPresentSections(DomainBucket b)
    {
        var list = new List<string>();
        if (b.Mx != null) list.Add("MX");
        if (b.Mx != null || b.SmtpTls != null || b.ImapTls != null || b.PopTls != null || b.Mtasts != null || b.TlsRpt != null || b.TlsRptReports != null || b.Dane != null)
            list.Add("Mail Transport Posture");
        if (b.DesiredState != null) list.Add("Desired State");
        if (b.Spf != null) list.Add("SPF");
        if (b.Dkim.Count > 0) list.Add("DKIM");
	        if (b.Dmarc != null) list.Add("DMARC");
	        if (b.DmarcAggregate != null) list.Add("DMARC Aggregate");
	        if (b.Registration != null) list.Add("Registration");
	        if (b.Microsoft365 != null) list.Add("Microsoft 365");
	        if (b.Http != null) list.Add("HTTP");
        if (b.Sitemap != null) list.Add("Sitemap");
        if (b.AgentReadiness != null) list.Add("Agent Readiness");
        if (b.Typosquatting != null) list.Add("Typosquatting");
	        if (b.CtTimeline != null) list.Add("CT Timeline");
        if (b.Subdomains != null) list.Add("Subdomains");
        if (b.DnsInventory != null) list.Add("DNS Inventory");
        if (b.DnsTrace != null) list.Add("DNS Trace");
        if (b.DnsPropagation != null && b.DnsPropagation.Count > 0) list.Add("DNS Propagation");
        if (b.DnsAmplification != null) list.Add("DNS Amplification");
        if (b.DnsOverTls != null) list.Add("DNS over TLS");
        if (b.IpEnrichment != null) list.Add("IP Enrichment");
        if (b.Arc != null) list.Add("ARC");
        if (b.Bimi != null) list.Add("BIMI");
        if (b.Dnsbl != null) list.Add("DNSBL");
        if (b.Rpki != null) list.Add("RPKI");
        if (b.Ns != null) list.Add("NS");
        if (b.Soa != null) list.Add("SOA");
        if (b.Ttl != null) list.Add("TTL");
        if (b.ZoneTransfer != null) list.Add("ZoneTransfer");
        if (b.Wildcard != null) list.Add("Wildcard");
        if (b.Caa != null) list.Add("CAA");
        if (b.Classification != null) list.Add("Classification");
        if (b.Mtasts != null) list.Add("MTA-STS");
        if (b.TlsRpt != null) list.Add("TLS-RPT");
        if (b.TlsRptReports != null) list.Add("TLS-RPT Reports");
        if (b.SmtpTls != null || b.ImapTls != null || b.PopTls != null) list.Add("MAILTLS");
        if (b.Dnssec != null) list.Add("DNSSEC");
        if (b.Dane != null) list.Add("DANE");
        return list;
    }

    private static void RenderDomainSections(TablerAccordion acc, string domain, DomainBucket b, SectionOrderMode sectionOrderMode, string[] customOrder, Dictionary<string, List<string>> inputSectionOrder)
    {
        var present = GetPresentSections(b);
        List<string>? input = null;
        if (inputSectionOrder != null && inputSectionOrder.TryGetValue(domain, out var list))
        {
            input = list;
        }
        var order = SectionOrdering.ResolveOrder(sectionOrderMode, present, input, customOrder);
        foreach (var section in order)
        {
            switch (section)
            {
                case "MX":
                    RenderMxSection(acc, b);
                    break;
                case "Mail Transport Posture":
                    RenderMailTransportPostureSection(acc, b);
                    break;
                case "Desired State":
                    RenderDesiredStateSection(acc, b);
                    break;
                case "SPF":
                    RenderSpfSection(acc, b);
                    break;
                case "DKIM":
                    RenderDkimSection(acc, b);
                    break;
                case "DMARC":
                    RenderDmarcSection(acc, b);
                    break;
                case "DMARC Aggregate":
                    RenderDmarcAggregateSection(acc, b);
                    break;
                case "ARC":
                    RenderArcSection(acc, b);
                    break;
                case "BIMI":
                    RenderBimiSection(acc, b);
                    break;
                case "DNSBL":
                    RenderDnsblSection(acc, b);
                    break;
                case "Classification":
                    RenderClassificationSection(acc, b);
                    break;
                case "MTA-STS":
                    RenderMtastsSection(acc, b);
                    break;
                case "TLS-RPT":
                    RenderTlsRptSection(acc, b);
                    break;
                case "TLS-RPT Reports":
                    RenderTlsRptReportsSection(acc, b);
                    break;
	                case "Registration":
	                    RenderRegistrationSection(acc, b);
	                    break;
                case "Microsoft 365":
                    RenderMicrosoft365Section(acc, b);
                    break;
                case "HTTP":
	                    RenderHttpSection(acc, b);
	                    break;
                case "Sitemap":
                    RenderSitemapSection(acc, b);
                    break;
                case "Agent Readiness":
                    RenderAgentReadinessSection(acc, b);
                    break;
                case "Typosquatting":
                    RenderTyposquattingSection(acc, b);
                    break;
	                case "CT Timeline":
	                    RenderCtTimelineSection(acc, b);
	                    break;
                case "Subdomains":
                    RenderSubdomainsSection(acc, b);
                    break;
                case "DNS Inventory":
                    RenderDnsInventorySection(acc, b);
                    break;
                case "DNS Trace":
                    RenderDnsTraceSection(acc, b);
                    break;
                case "DNS Propagation":
                    RenderDnsPropagationSection(acc, b);
                    break;
                case "DNS Amplification":
                    RenderDnsAmplificationSection(acc, b);
                    break;
                case "DNS over TLS":
                    RenderDnsOverTlsSection(acc, b);
                    break;
                case "IP Enrichment":
                    RenderIpEnrichmentSection(acc, b);
                    break;
                case "NS":
                    RenderNsSection(acc, b);
                    break;
                case "SOA":
                    RenderSoaSection(acc, b);
                    break;
                case "TTL":
                    RenderTtlSection(acc, b);
                    break;
                case "CAA":
                    RenderCaaSection(acc, b);
                    break;
                case "DNSSEC":
                    RenderDnssecSection(acc, b);
                    break;
                case "DANE":
                    RenderDaneSection(acc, b);
                    break;
                case "RPKI":
                    RenderRpkiSection(acc, b);
                    break;
                case "ZoneTransfer":
                    RenderZoneTransferSection(acc, b);
                    break;
                case "Wildcard":
                    RenderWildcardSection(acc, b);
                    break;
                case "MAILTLS":
                    RenderMailTlsSection(acc, b);
                    break;
            }
        }
    }

}
