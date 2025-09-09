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
    /// <param name="narrativePlacement">Where to render background narrative (global or per-domain).</param>
    /// <param name="titleOverride">Optional document title override.</param>
    /// <param name="authorOverride">Optional author override.</param>
    /// <param name="descriptionOverride">Optional description/summary override.</param>
    public static void Generate(string path, IReadOnlyList<object> items, Reports.ReportScope scope, bool openInBrowser = false, Reports.NarrativePlacement narrativePlacement = Reports.NarrativePlacement.Auto, string? titleOverride = null, string? authorOverride = null, string? descriptionOverride = null, DomainOrder domainOrder = DomainOrder.Alphabetical, SectionOrderMode sectionOrderMode = SectionOrderMode.Canonical, string[]? sectionOrder = null)
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
        // Domain ordering
        var ordered = (domainOrder == DomainOrder.Input)
            ? OrderDomainsByInput(items, grouped)
            : grouped.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase).ToList();

        var rows = ordered.Select(kv => new
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

        // Section ordering helpers
        var inputSectionOrder = (sectionOrderMode == SectionOrderMode.Input) ? DetermineSectionOrderByDomain(items) : new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var normalizedCustom = (sectionOrderMode == SectionOrderMode.Custom && sectionOrder != null) ? NormalizeSectionList(sectionOrder) : Array.Empty<string>();

        foreach (var kv in ordered)
        {
            var domain = kv.Key; var b = kv.Value;
            html.AddHeading(domain, 2);
            var writers = new Dictionary<string, Action>(StringComparer.OrdinalIgnoreCase);
            var present = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            void add(string key, Action a, bool isPresent) { if (isPresent) present.Add(key); writers[key] = a; }
            add("MX", () => MxHtmlSectionWriter.Write(html, b.Mx!, domain, scope), b.Mx != null);
            add("SPF", () => SpfHtmlSectionWriter.Write(html, b.Spf!, domain, scope), b.Spf != null);
            add("DKIM", () => DkimHtmlSectionWriter.Write(html, b.Dkim, domain, scope), b.Dkim.Count > 0);
            add("DMARC", () => DmarcHtmlSectionWriter.Write(html, b.Dmarc!, domain, scope), b.Dmarc != null);
            add("DNSBL", () => DnsblHtmlSectionWriter.Write(html, b.Dnsbl!, domain, scope), b.Dnsbl != null);
            add("Classification", () => MailClassificationHtmlSectionWriter.Write(html, b.Classification!, domain, scope), b.Classification != null);
            add("MTA-STS", () => MtastsHtmlSectionWriter.Write(html, b.Mtasts!, domain, scope), b.Mtasts != null);
            add("TLS-RPT", () => TlsRptHtmlSectionWriter.Write(html, b.TlsRpt!, domain, scope), b.TlsRpt != null);

            var canonical = CanonicalSections;
            var finalOrder = new List<string>();
            if (sectionOrderMode == SectionOrderMode.Custom && normalizedCustom.Length > 0) {
                foreach (var s in normalizedCustom) if (present.Contains(s)) finalOrder.Add(s);
                foreach (var s in canonical) if (present.Contains(s) && !finalOrder.Contains(s, StringComparer.OrdinalIgnoreCase)) finalOrder.Add(s);
            } else if (sectionOrderMode == SectionOrderMode.Input && inputSectionOrder.TryGetValue(domain, out var seenOrder) && seenOrder.Count > 0) {
                foreach (var s in seenOrder) if (present.Contains(s)) finalOrder.Add(s);
                foreach (var s in canonical) if (present.Contains(s) && !finalOrder.Contains(s, StringComparer.OrdinalIgnoreCase)) finalOrder.Add(s);
            } else {
                foreach (var s in canonical) if (present.Contains(s)) finalOrder.Add(s);
            }

            foreach (var key in finalOrder) { try { writers[key](); } catch { } }
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
        if (domains.Count == 0) return "Custom Composition";
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

    private static List<KeyValuePair<string, DomainBucket>> OrderDomainsByInput(IReadOnlyList<object> items, Dictionary<string, DomainBucket> grouped)
    {
        var ordered = new List<KeyValuePair<string, DomainBucket>>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var it in items ?? Array.Empty<object>())
        {
            var subject = TryGetSubject(it);
            if (string.IsNullOrWhiteSpace(subject)) continue;
            if (seen.Contains(subject!)) continue;
            if (grouped.TryGetValue(subject!, out var bucket))
            {
                ordered.Add(new KeyValuePair<string, DomainBucket>(subject!, bucket));
                seen.Add(subject!);
            }
        }
        foreach (var kv in grouped.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase)) if (!seen.Contains(kv.Key)) ordered.Add(new KeyValuePair<string, DomainBucket>(kv.Key, kv.Value));
        return ordered;
    }

    private static string? TryGetSubject(object item)
    {
        try { var p = item.GetType().GetProperty("Subject"); return p?.GetValue(item) as string; } catch { return null; }
    }

    private static Dictionary<string, List<string>> DetermineSectionOrderByDomain(IReadOnlyList<object> items)
    {
        var map = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var it in items ?? Array.Empty<object>())
        {
            var subject = TryGetSubject(it);
            if (string.IsNullOrWhiteSpace(subject)) continue;
            var key = TryGetSectionKey(it);
            if (string.IsNullOrWhiteSpace(key)) continue;
            if (!map.TryGetValue(subject!, out var list)) { list = new List<string>(); map[subject!] = list; }
            if (!list.Contains(key!, StringComparer.OrdinalIgnoreCase)) list.Add(key!);
        }
        return map;
    }

    private static string? TryGetSectionKey(object it)
    {
        try {
            var p = it.GetType().GetProperty("Check");
            if (p == null) return null;
            if (p.GetValue(it) is not DomainDetective.HealthCheckType h) return null;
            return SectionKeyFor(h);
        } catch { return null; }
    }

    private static string SectionKeyFor(DomainDetective.HealthCheckType h) => h switch {
        DomainDetective.HealthCheckType.MX => "MX",
        DomainDetective.HealthCheckType.SPF => "SPF",
        DomainDetective.HealthCheckType.DKIM => "DKIM",
        DomainDetective.HealthCheckType.DMARC => "DMARC",
        DomainDetective.HealthCheckType.DNSBL => "DNSBL",
        DomainDetective.HealthCheckType.MAILCLASSIFICATION => "Classification",
        DomainDetective.HealthCheckType.MTASTS => "MTA-STS",
        DomainDetective.HealthCheckType.TLSRPT => "TLS-RPT",
        _ => null
    };

    private static string[] CanonicalSections => new[] { "MX","SPF","DKIM","DMARC","DNSBL","Classification","MTA-STS","TLS-RPT" };

    private static string[] NormalizeSectionList(IEnumerable<string> list)
    {
        return list?.Select(s => NormalizeSection(s)).Where(x => !string.IsNullOrWhiteSpace(x)).ToArray() ?? Array.Empty<string>();
    }
    private static string NormalizeSection(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return s;
        var t = s.Trim();
        var u = t.ToUpperInvariant().Replace(" ", "");
        return u switch {
            "TLSRPT" => "TLS-RPT",
            "MTASTS" => "MTA-STS",
            _ => (u == "MX" || u == "SPF" || u == "DKIM" || u == "DMARC" || u == "DNSBL" || u == "CLASSIFICATION" || u == "MTA-STS" || u == "TLS-RPT") ? (u == "CLASSIFICATION" ? "Classification" : (u == "MTA-STS" ? "MTA-STS" : u)) : t
        };
    }
}

public enum DomainOrder { Alphabetical, Input }
public enum SectionOrderMode { Canonical, Input, Custom }
