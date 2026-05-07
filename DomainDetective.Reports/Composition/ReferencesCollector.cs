using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Reports;

/// <summary>
/// Collects reference URLs across composed buckets so all renderers can surface
/// a shared "All References" section.
/// </summary>
public static class ReferencesCollector
{
    public static List<string> CollectAll(IEnumerable<CompositionBuilder.DomainBucket> buckets)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Pull(IEnumerable<string>? urls)
        {
            if (urls == null) return;
            foreach (var u in urls)
            {
                var s = (u ?? string.Empty).Trim();
                if (s.Length == 0) continue;
                set.Add(s);
            }
        }

        foreach (var b in buckets ?? Enumerable.Empty<CompositionBuilder.DomainBucket>())
        {
            Pull(b.Spf?.References);
            if (b.Dkim != null) foreach (var d in b.Dkim) Pull(d.References);   
            Pull(b.Dmarc?.References);
            Pull(b.DmarcAggregate?.References);
            Pull(b.Registration?.References);
            Pull(b.Mx?.References);
            Pull(b.Mtasts?.References);
            Pull(b.TlsRpt?.References);
            Pull(b.TlsRptReports?.References);
            Pull(b.Dnsbl?.References);
            Pull(b.Rpki?.References);
            Pull(b.Ns?.References);
            Pull(b.Soa?.References);
            Pull(b.ZoneTransfer?.References);
            Pull(b.Wildcard?.References);
            Pull(b.Dnssec?.References);
            Pull(b.Dane?.References);
            Pull(b.Caa?.References);
            Pull(b.SmtpTls?.References);
            Pull(b.ImapTls?.References);
            Pull(b.PopTls?.References);
            Pull(b.Classification?.References);
            Pull(b.DesiredState?.References);
            Pull(b.Subdomains?.References);
            Pull(b.DnsInventory?.References);
            Pull(b.DnsTrace?.References);
            Pull(b.CtTimeline?.References);
            Pull(b.Http?.References);
            Pull(b.AgentReadiness?.References);
            Pull(b.Sitemap?.References);
            Pull(b.IpEnrichment?.References);
            Pull(b.Microsoft365?.References);
            Pull(b.Typosquatting?.References);
            if (b.DnsPropagation != null) foreach (var d in b.DnsPropagation) Pull(d.References);
        }

        return set.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
    }
}

