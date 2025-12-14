using System;
using System.Linq;

namespace DomainDetective.Reports.Html;

public static class MxHtmlSectionWriter
{
    public static void Write(IHtmlComposer html, DomainDetective.Views.MxInfo mx, string domain, Reports.ReportScope scope)
    {
        if (html == null) throw new ArgumentNullException(nameof(html));
        if (mx == null) throw new ArgumentNullException(nameof(mx));

        html.AddHeading($"MX — {domain}", 2);
        html.AddTable(new[] {
            new { Name = "MX Records", Value = (mx.MxRecords?.Count ?? 0).ToString() },
            new { Name = "Priorities In Order", Value = mx.PrioritiesInOrder ? "Yes" : "No" },
            new { Name = "Backup Servers", Value = mx.HasBackupServers ? "Yes" : "No" },
            new { Name = "IPv6 Supported", Value = mx.Ipv6Supported ? "Yes" : "No" },
            new { Name = "TTL Uniform", Value = mx.MxTtlUniform ? "Yes" : "No" },
            new { Name = "MX TTL Min (s)", Value = mx.MinMxTtl?.ToString() ?? "-" },
            new { Name = "MX TTL Avg (s)", Value = mx.AvgMxTtl.HasValue ? ((int)Math.Round(mx.AvgMxTtl.Value)).ToString() : "-" },
            new { Name = "MX TTL Max (s)", Value = mx.MaxMxTtl?.ToString() ?? "-" },
            new { Name = "NS RRset Consistent", Value = mx.MxRrsetConsistentAcrossNs ? "Yes" : "No" },
            new { Name = "Status", Value = mx.Status ?? string.Empty },
            new { Name = "Primary Provider", Value = mx.ProviderPrimary ?? string.Empty },
            new { Name = "Gateways", Value = (mx.ProviderGateways != null && mx.ProviderGateways.Count > 0) ? string.Join(", ", mx.ProviderGateways) : string.Empty },
        });

        if (scope == Reports.ReportScope.Detailed && mx.MxRecords != null && mx.MxRecords.Count > 0)
        {
            html.AddHeading("Evidence", 3);
            html.AddList(mx.MxRecords);
        }

        // Provider Help (render simple text links)
        try
        {
            var help = mx.ProviderHelp ?? Array.Empty<DomainDetective.Views.ProviderHelpLinks>();
            bool any = help.Any(h => h != null && h.HasAny);
            if (any)
            {
                html.AddHeading("Provider Help", 3);
                html.AddParagraph("Official provider documentation for core email controls:");
                foreach (var ph in help)
                {
                    if (ph == null || !ph.HasAny) continue;
                    html.AddParagraph(ph.ProviderName);
                    var items = new System.Collections.Generic.List<string>();
                    if (!string.IsNullOrWhiteSpace(ph.Dmarc)) items.Add($"DMARC: {ph.Dmarc}");
                    if (!string.IsNullOrWhiteSpace(ph.Spf)) items.Add($"SPF: {ph.Spf}");
                    if (!string.IsNullOrWhiteSpace(ph.Dkim)) items.Add($"DKIM: {ph.Dkim}");
                    if (!string.IsNullOrWhiteSpace(ph.MtaSts)) items.Add($"MTA-STS: {ph.MtaSts}");
                    if (!string.IsNullOrWhiteSpace(ph.TlsRpt)) items.Add($"TLS-RPT: {ph.TlsRpt}");
                    if (!string.IsNullOrWhiteSpace(ph.Deliverability)) items.Add($"Deliverability: {ph.Deliverability}");
                    html.AddList(items);
                }
            }
        }
        catch { }
    }
}
