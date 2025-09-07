using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Reports.Html;

/// <summary>
/// Aggregates mixed view objects (SPF/DKIM/DMARC) for one or more domains into a single HTML document using the IHtmlComposer adapter.
/// </summary>
/// <summary>
/// Builds a single HTML report from mixed view objects using the engine-agnostic composer.
/// </summary>
public static class HtmlCompositionReport
{
    /// <summary>
    /// Generates the HTML report.
    /// </summary>
    /// <param name="path">Output file path.</param>
    /// <param name="items">View objects grouped by Subject.</param>
    /// <param name="scope">Detail level.</param>
    /// <param name="openInBrowser">Open the file after saving.</param>
    public static void Generate(string path, IReadOnlyList<object> items, Reports.ReportScope scope, bool openInBrowser = false)
    {
        if (items == null || items.Count == 0) throw new ArgumentException("No items to compose.", nameof(items));

        var grouped = GroupBySubject(items);
        var title = BuildSubjectTitle(grouped.Keys.ToList());

        using IHtmlComposer html = new HtmlForgeXComposer();
        html.SetMetadata($"Security Report — {title}", "DomainDetective", "Custom composition report");

        html.AddHeading($"Security Report — {title}", 1);
        html.AddParagraph($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");

        // Executive Summary
        var rows = grouped.Select(kv => new
        {
            Domain = kv.Key,
            SPF = kv.Value.Spf?.Status ?? "-",
            DKIM = kv.Value.Dkim.Count > 0 ? (kv.Value.Dkim.Max(x => x.Status) ?? "-") : "-",
            DMARC = kv.Value.Dmarc?.Status ?? "-",
            MTASTS = kv.Value.Mtasts?.Status ?? "-",
            TLSRPT = kv.Value.TlsRpt?.Status ?? "-",
            Findings = $"{(kv.Value.Spf?.WarningCount ?? 0) + (kv.Value.Dmarc?.WarningCount ?? 0) + kv.Value.Dkim.Sum(x => x.WarningCount)} / {(kv.Value.Spf?.ErrorCount ?? 0) + (kv.Value.Dmarc?.ErrorCount ?? 0) + kv.Value.Dkim.Sum(x => x.ErrorCount)}"
        });
        html.AddHeading("Executive Summary", 2);
        html.AddTable(rows);

        foreach (var kv in grouped)
        {
            var domain = kv.Key; var b = kv.Value;
            html.AddHeading(domain, 2);
            if (b.Spf != null) SpfHtmlSectionWriter.Write(html, b.Spf, domain, scope);
            if (b.Dkim.Count > 0) DkimHtmlSectionWriter.Write(html, b.Dkim, domain, scope);
            if (b.Dmarc != null) DmarcHtmlSectionWriter.Write(html, b.Dmarc, domain, scope);
            if (b.Dnsbl != null) DnsblHtmlSectionWriter.Write(html, b.Dnsbl, domain, scope);
            if (b.Classification != null) MailClassificationHtmlSectionWriter.Write(html, b.Classification, domain, scope);
            if (b.Mtasts != null) MtastsHtmlSectionWriter.Write(html, b.Mtasts, domain, scope);
            if (b.TlsRpt != null) TlsRptHtmlSectionWriter.Write(html, b.TlsRpt, domain, scope);
        }

        html.Save(path, openInBrowser);
    }

    private static string BuildSubjectTitle(List<string> domains)
    {
        if (domains.Count == 1) return domains[0];
        if (domains.Count == 2) return $"{domains[0]}+{domains[1]}";
        return $"{domains[0]}+{domains[1]}(+{domains.Count - 2})";
    }

    private sealed class DomainBucket
    {
        public string Subject { get; set; } = string.Empty;
        public DomainDetective.Views.SpfRecordInfo? Spf { get; set; }
        public DomainDetective.Views.DmarcRecordInfo? Dmarc { get; set; }
        public List<DomainDetective.Views.DkimRecordInfo> Dkim { get; } = new();
        public DomainDetective.Views.DnsblInfo? Dnsbl { get; set; }
        public DomainDetective.Views.MailClassificationInfo? Classification { get; set; }
        public DomainDetective.Views.MtastsInfo? Mtasts { get; set; }
        public DomainDetective.Views.TlsRptInfo? TlsRpt { get; set; }
    }

    private static Dictionary<string, DomainBucket> GroupBySubject(IReadOnlyList<object> items)
    {
        var map = new Dictionary<string, DomainBucket>(StringComparer.OrdinalIgnoreCase);
        void Ensure(string subject)
        {
            if (!map.ContainsKey(subject)) map[subject] = new DomainBucket { Subject = subject };
        }

        foreach (var it in items)
        {
            switch (it)
            {
                case DomainDetective.Views.SpfRecordInfo spf when !string.IsNullOrWhiteSpace(spf.Subject):
                    Ensure(spf.Subject); map[spf.Subject].Spf = spf; break;
                case DomainDetective.Views.DmarcRecordInfo dmarc when !string.IsNullOrWhiteSpace(dmarc.Subject):
                    Ensure(dmarc.Subject); map[dmarc.Subject].Dmarc = dmarc; break;
                case DomainDetective.Views.DkimRecordInfo dkim when !string.IsNullOrWhiteSpace(dkim.Subject):
                    Ensure(dkim.Subject); map[dkim.Subject].Dkim.Add(dkim); break;
                case DomainDetective.Views.DnsblInfo dnsbl when !string.IsNullOrWhiteSpace(dnsbl.Subject):
                    Ensure(dnsbl.Subject); map[dnsbl.Subject].Dnsbl = dnsbl; break;
                case DomainDetective.Views.MailClassificationInfo mc when !string.IsNullOrWhiteSpace(mc.Subject):
                    Ensure(mc.Subject); map[mc.Subject].Classification = mc; break;
                case DomainDetective.Views.MtastsInfo ms when !string.IsNullOrWhiteSpace(ms.Subject):
                    Ensure(ms.Subject); map[ms.Subject].Mtasts = ms; break;
                case DomainDetective.Views.TlsRptInfo tr when !string.IsNullOrWhiteSpace(tr.Subject):
                    Ensure(tr.Subject); map[tr.Subject].TlsRpt = tr; break;
                default:
                    break;
            }
        }
        return map;
    }
}
