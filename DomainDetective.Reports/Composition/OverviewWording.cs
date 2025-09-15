using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Reports;

/// <summary>
/// Builds the canonical Executive Summary overview sentence so all renderers
/// (Word, Markdown, HTML, Excel) display identical wording and control lists.
/// </summary>
public static class OverviewWording
{
    private static readonly string[] ControlOrder = new[] {
        // Email auth + transport first
        "MX", "SPF", "DKIM", "DMARC", "ARC", "BIMI", "MTA-STS", "TLS-RPT", "DNSBL", "RPKI", "MAILTLS",
        // Other checks next
        "Classification", "DNSSEC", "DANE", "NS", "SOA", "ZoneXFR", "Wildcard", "CAA"
    };

    /// <summary>
    /// Compose the uniform overview sentence from raw items. Safe to call from any renderer.
    /// </summary>
    public static string ComposeFromItems(IReadOnlyList<object> items)
    {
        if (items == null || items.Count == 0) return "This report summarizes the email security posture for 0 domain(s).";

        var grouped = CompositionBuilder.GroupBySubject(items);
        int domainsCount = grouped.Count;

        // Determine present controls based on buckets
        var present = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        bool anyArc = false, anyBimi = false;
        foreach (var b in grouped.Values)
        {
            if (b.Mx != null) present.Add("MX");
            if (b.Spf != null) present.Add("SPF");
            if (b.Dkim != null && b.Dkim.Count > 0) present.Add("DKIM");
            if (b.Dmarc != null) present.Add("DMARC");
            if (b.Dnsbl != null) present.Add("DNSBL");
            if (b.Classification != null) present.Add("Classification");
            if (b.Mtasts != null) present.Add("MTA-STS");
            if (b.TlsRpt != null) present.Add("TLS-RPT");
            if (b.Ns != null) present.Add("NS");
            if (b.Soa != null) present.Add("SOA");
            if (b.Caa != null) present.Add("CAA");
            if (b.Dnssec != null) present.Add("DNSSEC");
            if (b.Dane != null) present.Add("DANE");
            if (b.Rpki != null) present.Add("RPKI");
            if (b.ZoneTransfer != null) present.Add("ZoneXFR");
            if (b.Wildcard != null) present.Add("Wildcard");
            // MailTLS presence if any protocol exists
            if (b.SmtpTls != null || b.ImapTls != null || b.PopTls != null) present.Add("MAILTLS");
        }

        // ARC/BIMI presence via direct scan of inputs (not yet in CompositionBuilder.DomainBucket)
        foreach (var it in items)
        {
            switch (it)
            {
                case DomainDetective.Views.ArcInfo:
                    anyArc = true; break;
                case DomainDetective.Views.BimiRecordInfo:
                    anyBimi = true; break;
                default:
                    break;
            }
        }
        if (anyArc) present.Add("ARC");
        if (anyBimi) present.Add("BIMI");

        var orderedControls = ControlOrder.Where(c => present.Contains(c)).ToList();
        string controlsText = orderedControls.Count > 0 ? string.Join(", ", orderedControls) : "requested checks";

        var rows = ExecutiveSummaryBuilder.Build(items, DomainOrder.Alphabetical);
        int totalWarn = rows.Sum(r => r.Warnings);
        int totalErr = rows.Sum(r => r.Errors);

        return $"This report summarizes the email security posture for {domainsCount} domain(s). The table highlights the presence and status of key controls ({controlsText}) and the count of warnings/errors detected. Total across all domains: {totalWarn} warning(s), {totalErr} error(s).";
    }
}
