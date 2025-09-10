using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using OfficeIMO.Markdown;

namespace DomainDetective.Reports.Markdown;

/// <summary>
/// Markdown composition across mixed view items (SPF/DKIM/DMARC/MX/Classification...).
/// Mirrors Word layout at a high level and supports HtmlAsMarkdown export.
/// </summary>
public static class MarkdownCompositionReport
{
    public static void Generate(
        string path,
        IReadOnlyList<object> items,
        ReportScope scope,
        OrderingOptions? ordering = null)
    {
        if (items == null || items.Count == 0) throw new ArgumentException("No items to compose.", nameof(items));

        var groups = GroupBySubject(items);
        var domains = OrderDomains(items, groups, ordering?.DomainOrder ?? DomainOrder.Alphabetical);
        var title = BuildTitle(domains.Select(x => x.Key).ToList());

        int totalWarn = 0, totalErr = 0;
        var summary = new List<(string Domain, string MX, string SPF, string DKIM, string DMARC, string MTASTS, string TLSRPT, string Classification, string Findings)>();
        foreach (var kv in domains)
        {
            var b = kv.Value;
            int warn = (b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + b.Dkim.Sum(x => x.WarningCount);
            int err  = (b.Mx?.ErrorCount ?? 0) + (b.Spf?.ErrorCount ?? 0) + (b.Dmarc?.ErrorCount ?? 0) + (b.Mtasts?.ErrorCount ?? 0) + (b.TlsRpt?.ErrorCount ?? 0) + b.Dkim.Sum(x => x.ErrorCount);
            totalWarn += warn; totalErr += err;
            string status(string? s) => string.IsNullOrWhiteSpace(s) ? "-" : s!;
            string dkimStatus = b.Dkim.Count > 0 ? (b.Dkim.Max(x => x.Status) ?? "-") : "-";
            summary.Add((kv.Key, status(b.Mx?.Status), status(b.Spf?.Status), dkimStatus, status(b.Dmarc?.Status), status(b.Mtasts?.Status), status(b.TlsRpt?.Status), status(b.Classification?.Classification), $"{warn} / {err}"));
        }

        var md = BuildDoc(domains, title);
        var text = md.ToMarkdown();
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)) ?? ".");
        File.WriteAllText(path, text, Encoding.UTF8);
    }

    public static void GenerateHtmlAsMarkdown(
        string htmlPath,
        IReadOnlyList<object> items,
        ReportScope scope,
        OrderingOptions? ordering = null)
    {
        if (items == null || items.Count == 0) throw new ArgumentException("No items to compose.", nameof(items));
        var groups = GroupBySubject(items);
        var domains = OrderDomains(items, groups, ordering?.DomainOrder ?? DomainOrder.Alphabetical);
        var title = BuildTitle(domains.Select(x => x.Key).ToList());

        var md = BuildDoc(domains, title);
        var mdPath = Path.ChangeExtension(htmlPath, ".md");
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(mdPath)) ?? ".");
        File.WriteAllText(mdPath, md.ToMarkdown(), Encoding.UTF8);

        var htmlOptions = new HtmlOptions {
            Kind = HtmlKind.Document,
            Style = HtmlStyle.GithubAuto,
            CssDelivery = CssDelivery.Inline,
            IncludeAnchorLinks = false,
            ShowAnchorIcons = true,
            AnchorIcon = "🔗",
            CopyHeadingLinkOnClick = true,
            BackToTopLinks = true,
            BackToTopMinLevel = 1,
            BackToTopText = "Back to top",
            ThemeToggle = true
        };
        md.SaveHtml(htmlPath, htmlOptions);
    }

    private static MarkdownDoc BuildDoc(List<KeyValuePair<string, DomainBucket>> domains, string title)
    {
        int totalWarn = 0, totalErr = 0;
        var summary = new List<(string Domain, string MX, string SPF, string DKIM, string DMARC, string MTASTS, string TLSRPT, string Classification, string Findings)>();
        foreach (var kv in domains)
        {
            var b = kv.Value;
            int warn = (b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + b.Dkim.Sum(x => x.WarningCount);
            int err  = (b.Mx?.ErrorCount ?? 0) + (b.Spf?.ErrorCount ?? 0) + (b.Dmarc?.ErrorCount ?? 0) + (b.Mtasts?.ErrorCount ?? 0) + (b.TlsRpt?.ErrorCount ?? 0) + b.Dkim.Sum(x => x.ErrorCount);
            totalWarn += warn; totalErr += err;
            string status(string? s) => string.IsNullOrWhiteSpace(s) ? "-" : s!;
            string dkimStatus = b.Dkim.Count > 0 ? (b.Dkim.Max(x => x.Status) ?? "-") : "-";
            summary.Add((kv.Key, status(b.Mx?.Status), status(b.Spf?.Status), dkimStatus, status(b.Dmarc?.Status), status(b.Mtasts?.Status), status(b.TlsRpt?.Status), status(b.Classification?.Classification), $"{warn} / {err}"));
        }

        var md = MarkdownDoc.Create()
            .FrontMatter(new { title = $"Security Report — {title}", date = DateTimeOffset.Now.ToString("u") })
            .H1("Executive Summary")
            .Toc(opts => { opts.MinLevel = 1; opts.MaxLevel = 3; opts.IncludeTitle = false; opts.Collapsible = true; }, placeAtTop: true)
            .H2("Overview")
            .P(p => p.Text("This report summarizes email and DNS security signals for ")
                    .Bold(domains.Count.ToString()).Text(" domain(s). Totals: ").Underline($"{totalWarn} warning(s), {totalErr} error(s)").Text("."))
            .H2("Legend")
            .Table(t => t.Headers("Status","Meaning")
                           .Row("🟢 OK","All checks passed or acceptable")
                           .Row("🟠 Warning","Requires attention; not blocking")
                           .Row("🔴 Error","Blocking or invalid configuration")
                           .AlignLeft(0,1))
            .H2("Domains");

        md.Table(t => t
            .Headers("Domain","MX","SPF","DKIM","DMARC","MTA-STS","TLS-RPT","Classification","Findings (W/E)")
            .Rows(summary.Select(r => (IReadOnlyList<string>)new []{ r.Domain, r.MX, r.SPF, r.DKIM, r.DMARC, r.MTASTS, r.TLSRPT, r.Classification, r.Findings }))
            .AlignLeft(0).AlignCenter(1,2,3,4,5,6,7).AlignRight(8));

        // Per-domain sections (compact, Word-like)
        foreach (var kv in domains)
        {
            var d = kv.Key; var b = kv.Value;
            md.H1(d).H2("Overview").Table(t => t.Headers("Key","Value")
                .Row("Domain", d)
                .Row("Classification", b.Classification?.Classification ?? "-")
                .Row("Confidence", b.Classification?.Confidence ?? "-")
                .Row("Status", ComputeStatus(b))
                .Row("Warnings", ((b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + b.Dkim.Sum(x => x.WarningCount)).ToString())
                .Row("Errors", ((b.Mx?.ErrorCount ?? 0) + (b.Spf?.ErrorCount ?? 0) + (b.Dmarc?.ErrorCount ?? 0) + (b.Mtasts?.ErrorCount ?? 0) + (b.TlsRpt?.ErrorCount ?? 0) + b.Dkim.Sum(x => x.ErrorCount)).ToString())
                .AlignLeft(0,1));

            if (b.Classification != null && b.Classification.ScoreBreakdown != null && b.Classification.ScoreBreakdown.Count > 0)
            {
                md.H2("Score Breakdown").Table(t => t.Headers("Metric","Value")
                    .Rows(b.Classification.ScoreBreakdown.Select(kv2 => (IReadOnlyList<string>)new[]{ kv2.Key, kv2.Value.ToString("0.##") }))
                    .AlignLeft(0).AlignRight(1));
            }

            if (b.Classification?.Recommendations?.Count > 0)
                md.H2("Recommendations").Ul(b.Classification.Recommendations.Select(r => r.Title ?? r.Code).ToArray());
            if (b.Classification?.Positives?.Count > 0)
                md.H2("Positives").Ul(b.Classification.Positives.Select(r => r.Title ?? r.Code).ToArray());
            if (b.Classification?.References?.Count > 0)
            {
                md.H2("References");
                md.Ul(ul => { foreach (var u in b.Classification.References) ul.ItemLink(u, u); });
            }
        }

        return md;
    }

    private static string ComputeStatus(DomainBucket b)
    {
        var err = (b.Mx?.ErrorCount ?? 0) + (b.Spf?.ErrorCount ?? 0) + (b.Dmarc?.ErrorCount ?? 0) + (b.Mtasts?.ErrorCount ?? 0) + (b.TlsRpt?.ErrorCount ?? 0) + b.Dkim.Sum(x => x.ErrorCount);
        var warn = (b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + b.Dkim.Sum(x => x.WarningCount);
        return err > 0 ? "🔴 Error" : (warn > 0 ? "🟠 Warning" : "🟢 OK");
    }

    private static string BuildTitle(List<string> domains)
        => domains.Count switch { 0 => "Custom Composition", 1 => domains[0], 2 => $"{domains[0]}+{domains[1]}", _ => $"{domains[0]}+{domains[1]}(+{domains.Count - 2})" };

    private static List<KeyValuePair<string, DomainBucket>> OrderDomains(IReadOnlyList<object> items, Dictionary<string, DomainBucket> grouped, DomainOrder order)
    {
        if (order == DomainOrder.Alphabetical)
            return grouped.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase).ToList();
        var list = new List<KeyValuePair<string, DomainBucket>>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var it in items)
        {
            var s = TryGetSubject(it); if (string.IsNullOrWhiteSpace(s) || seen.Contains(s!)) continue;
            if (grouped.TryGetValue(s!, out var b)) { list.Add(new KeyValuePair<string, DomainBucket>(s!, b)); seen.Add(s!); }
        }
        foreach (var kv in grouped.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase)) if (!seen.Contains(kv.Key)) list.Add(new KeyValuePair<string, DomainBucket>(kv.Key, kv.Value));
        return list;
    }

    private static Dictionary<string, DomainBucket> GroupBySubject(IReadOnlyList<object> items)
    {
        var map = new Dictionary<string, DomainBucket>(StringComparer.OrdinalIgnoreCase);
        void Ensure(string s) { if (!map.ContainsKey(s)) map[s] = new DomainBucket { Subject = s }; }
        foreach (var it in items)
        {
            switch (it)
            {
                case DomainDetective.Views.MxInfo mx when !string.IsNullOrWhiteSpace(mx.Subject): Ensure(mx.Subject); map[mx.Subject].Mx = mx; break;
                case DomainDetective.Views.SpfRecordInfo spf when !string.IsNullOrWhiteSpace(spf.Subject): Ensure(spf.Subject); map[spf.Subject].Spf = spf; break;
                case DomainDetective.Views.DmarcRecordInfo dmarc when !string.IsNullOrWhiteSpace(dmarc.Subject): Ensure(dmarc.Subject); map[dmarc.Subject].Dmarc = dmarc; break;
                case DomainDetective.Views.DkimRecordInfo dkim when !string.IsNullOrWhiteSpace(dkim.Subject): Ensure(dkim.Subject); map[dkim.Subject].Dkim.Add(dkim); break;
                case DomainDetective.Views.MtastsInfo ms when !string.IsNullOrWhiteSpace(ms.Subject): Ensure(ms.Subject); map[ms.Subject].Mtasts = ms; break;
                case DomainDetective.Views.TlsRptInfo tr when !string.IsNullOrWhiteSpace(tr.Subject): Ensure(tr.Subject); map[tr.Subject].TlsRpt = tr; break;
                case DomainDetective.Views.MailClassificationInfo mc when !string.IsNullOrWhiteSpace(mc.Subject): Ensure(mc.Subject); map[mc.Subject].Classification = mc; break;
                default: break;
            }
        }
        return map;
    }

    private static string? TryGetSubject(object item)
    {
        try { var p = item.GetType().GetProperty("Subject"); return p?.GetValue(item) as string; } catch { return null; }
    }

    private sealed class DomainBucket
    {
        public string Subject { get; set; } = string.Empty;
        public DomainDetective.Views.MxInfo? Mx { get; set; }
        public DomainDetective.Views.SpfRecordInfo? Spf { get; set; }
        public DomainDetective.Views.DmarcRecordInfo? Dmarc { get; set; }
        public List<DomainDetective.Views.DkimRecordInfo> Dkim { get; } = new();
        public DomainDetective.Views.MtastsInfo? Mtasts { get; set; }
        public DomainDetective.Views.TlsRptInfo? TlsRpt { get; set; }
        public DomainDetective.Views.MailClassificationInfo? Classification { get; set; }
    }
}
