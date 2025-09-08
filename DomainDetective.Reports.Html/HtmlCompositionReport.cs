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
    public static void Generate(string path, IReadOnlyList<object> items, Reports.ReportScope scope, bool openInBrowser = false, Reports.NarrativePlacement narrativePlacement = Reports.NarrativePlacement.Auto, string? titleOverride = null, string? authorOverride = null, string? descriptionOverride = null)
    {
        if (items == null || items.Count == 0) throw new ArgumentException("No items to compose.", nameof(items));

        var grouped = GroupBySubject(items);
        var title = BuildSubjectTitle(grouped.Keys.ToList());

        using IHtmlComposer html = new HtmlForgeXComposer();
        var theTitle = string.IsNullOrWhiteSpace(titleOverride) ? $"Security Report — {title}" : titleOverride;
        var theAuthor = string.IsNullOrWhiteSpace(authorOverride) ? "DomainDetective" : authorOverride;
        var theDesc = string.IsNullOrWhiteSpace(descriptionOverride) ? "Custom composition report" : descriptionOverride;
        html.SetMetadata(theTitle, theAuthor, theDesc);

        html.AddHeading($"Security Report — {title}", 1);
        html.AddParagraph($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");

        // Executive Summary
        var rows = grouped.Select(kv => new
        {
            Domain = kv.Key,
            MX = kv.Value.Mx?.Status ?? "-",
            SPF = kv.Value.Spf?.Status ?? "-",
            DKIM = kv.Value.Dkim.Count > 0 ? (kv.Value.Dkim.Max(x => x.Status) ?? "-") : "-",
            DMARC = kv.Value.Dmarc?.Status ?? "-",
            MTASTS = kv.Value.Mtasts?.Status ?? "-",
            TLSRPT = kv.Value.TlsRpt?.Status ?? "-",
            Findings = $"{(kv.Value.Spf?.WarningCount ?? 0) + (kv.Value.Dmarc?.WarningCount ?? 0) + kv.Value.Dkim.Sum(x => x.WarningCount) + (kv.Value.Mtasts?.WarningCount ?? 0) + (kv.Value.TlsRpt?.WarningCount ?? 0) + (kv.Value.Mx?.WarningCount ?? 0)} / {(kv.Value.Spf?.ErrorCount ?? 0) + (kv.Value.Dmarc?.ErrorCount ?? 0) + kv.Value.Dkim.Sum(x => x.ErrorCount) + (kv.Value.Mtasts?.ErrorCount ?? 0) + (kv.Value.TlsRpt?.ErrorCount ?? 0) + (kv.Value.Mx?.ErrorCount ?? 0)}"
        });
        html.AddHeading("Executive Summary", 2);
        html.AddTable(rows);

        bool multiDomain = grouped.Count > 1;
        bool placeGlobal = narrativePlacement == Reports.NarrativePlacement.Global || (narrativePlacement == Reports.NarrativePlacement.Auto && multiDomain);
        bool includeNarrativePerDomain = narrativePlacement == Reports.NarrativePlacement.PerDomain || (narrativePlacement == Reports.NarrativePlacement.Auto && !multiDomain);
        if (placeGlobal)
        {
            BackgroundHtmlSectionWriter.Write(html, items);
        }

        foreach (var kv in grouped)
        {
            var domain = kv.Key; var b = kv.Value;
            html.AddHeading(domain, 2);
            if (b.Mx != null) MxHtmlSectionWriter.Write(html, b.Mx, domain, scope);
            if (b.Spf != null) SpfHtmlSectionWriter.Write(html, b.Spf, domain, scope);
            if (b.Dkim.Count > 0) DkimHtmlSectionWriter.Write(html, b.Dkim, domain, scope);
            if (b.Dmarc != null) DmarcHtmlSectionWriter.Write(html, b.Dmarc, domain, scope);
            if (b.Dnsbl != null) DnsblHtmlSectionWriter.Write(html, b.Dnsbl, domain, scope);
            if (b.Classification != null) MailClassificationHtmlSectionWriter.Write(html, b.Classification, domain, scope);
            if (b.Mtasts != null) MtastsHtmlSectionWriter.Write(html, b.Mtasts, domain, scope);
            if (b.TlsRpt != null) TlsRptHtmlSectionWriter.Write(html, b.TlsRpt, domain, scope);
        }

        // Consolidated Recommendations
        var allAssessments = new List<DomainDetective.Assessment>();
        foreach (var kv in grouped)
        {
            var b = kv.Value;
            void Pull(IReadOnlyList<DomainDetective.Assessment>? a) { if (a != null && a.Count > 0) allAssessments.AddRange(a); }
            Pull(b.Spf?.Assessments);
            foreach (var d in b.Dkim) Pull(d.Assessments);
            Pull(b.Dmarc?.Assessments);
            Pull(b.Mx?.Assessments);
            Pull(b.Mtasts?.Assessments);
            Pull(b.TlsRpt?.Assessments);
            Pull(b.Dnsbl?.Assessments);
        }
        var groupedRecs = DomainDetective.RecommendationEngine.GroupByCode(allAssessments);
        var negative = groupedRecs.Where(g => g.MaxSeverity != DomainDetective.AssessmentSeverity.Info).ToList();
        if (negative.Count > 0)
        {
            html.AddHeading("Consolidated Recommendations", 2);
            var recRows = negative.Select(g => new { Severity = g.MaxSeverity.ToString(), g.Code, Title = g.Advice?.Title ?? string.Empty, How = g.Advice?.How ?? string.Empty });
            html.AddTable(recRows);
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
        public DomainDetective.Views.MxInfo? Mx { get; set; }
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
                case DomainDetective.Views.MxInfo mx when !string.IsNullOrWhiteSpace(mx.Subject):
                    Ensure(mx.Subject); map[mx.Subject].Mx = mx; break;
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
