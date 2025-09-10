using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Reports;
#if NET8_0
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;
#endif

namespace DomainDetective.Reports.Office;

/// <summary>
/// Excel composition across mixed view items (Index, Overview, per-domain sheets).
/// Implemented for net8.0 using OfficeIMO.Excel.
/// </summary>
public static class ExcelCompositionReport
{
    public static void Generate(
        string path,
        IReadOnlyList<object> items,
        ReportScope scope,
        OrderingOptions? ordering = null)
    {
#if !NET8_0
        throw new NotSupportedException("Excel composition requires .NET 8.0");
#else
        if (items == null || items.Count == 0) throw new ArgumentException("No items to compose.", nameof(items));
        var groups = GroupBySubject(items);
        var order = (ordering != null) ? ordering.DomainOrder : DomainDetective.Reports.DomainOrder.Alphabetical;
        var domains = OrderDomains(items, groups, order);

        using var doc = ExcelDocument.Create(path);
        doc.AsFluent().Info(i => i
            .Title("Domain Detective — Excel Composition")
            .Author("DomainDetective")
            .Company("Evotec")
            .Application("OfficeIMO.Excel")
            .Keywords("excel,report,domains")).End();

        // Overview sheet
        var overview = new SheetComposer(doc, "Overview");
        overview.Title("Security Overview", $"Generated {DateTime.Now:yyyy-MM-dd HH:mm}");

        // Build summary rows
        var sumRows = new List<(string Domain, string MX, string SPF, string DKIM, string DMARC, string MTASTS, string TLSRPT, string Findings)>();
        int totalWarn = 0, totalErr = 0;
        foreach (var kv in domains)
        {
            var b = kv.Value;
            int warn = (b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + b.Dkim.Sum(x => x.WarningCount);
            int err  = (b.Mx?.ErrorCount ?? 0) + (b.Spf?.ErrorCount ?? 0) + (b.Dmarc?.ErrorCount ?? 0) + (b.Mtasts?.ErrorCount ?? 0) + (b.TlsRpt?.ErrorCount ?? 0) + b.Dkim.Sum(x => x.ErrorCount);
            totalWarn += warn; totalErr += err;
            string status(string? s) => string.IsNullOrWhiteSpace(s) ? "-" : s!;
            string dkimStatus = b.Dkim.Count > 0 ? (b.Dkim.Max(x => x.Status) ?? "-") : "-";
            sumRows.Add((kv.Key, status(b.Mx?.Status), status(b.Spf?.Status), dkimStatus, status(b.Dmarc?.Status), status(b.Mtasts?.Status), status(b.TlsRpt?.Status), $"{warn} / {err}"));
        }

        // KPI row
        overview.KpiRow(new (string, object?)[] {
            ("Domains", domains.Count),
            ("Warnings", totalWarn),
            ("Errors", totalErr)
        }, perRow: 3);

        // Summary table
        overview.TableFrom(sumRows, title: "Domains", configure: o => {
            o.HeaderCase = HeaderCase.Title;
        }, visuals: v => { });
        overview.Finish(autoFitColumns: true);

        // Per-domain sheets
        var usedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in domains)
        {
            var name = MakeUniqueSheetName(kv.Key, usedNames); var b = kv.Value;
            var s = new SheetComposer(doc, name);
            s.Title($"Mail & DNS — {name}");
            s.SectionWithAnchor("Overview");
            s.DefinitionList(new (string, object?)[] {
                ("MX", b.Mx?.Status ?? "-"),
                ("SPF", b.Spf?.Status ?? "-"),
                ("DKIM", b.Dkim.Count > 0 ? (b.Dkim.Max(x => x.Status) ?? "-") : "-"),
                ("DMARC", b.Dmarc?.Status ?? "-"),
                ("MTA-STS", b.Mtasts?.Status ?? "-"),
                ("TLS-RPT", b.TlsRpt?.Status ?? "-")
            }, columns: 3);

            if (b.Classification != null)
            {
                s.SectionWithAnchor("Classification");
                s.PropertiesGrid(new (string, object?)[] {
                    ("Category", b.Classification.Classification),
                    ("Confidence", b.Classification.Confidence),
                    ("Status", b.Classification.Status)
                }, columns: 3);
                if (b.Classification.ScoreBreakdown != null && b.Classification.ScoreBreakdown.Count > 0)
                {
                    var rows = b.Classification.ScoreBreakdown.Select(kv2 => new { Name = kv2.Key, Value = kv2.Value }).ToList();
                    s.TableFrom(rows, title: "Score Breakdown", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => { v.NumericColumnDecimals["Value"] = 2; });
                }
                if (b.Classification.Recommendations?.Count > 0)
                {
                    s.SectionWithAnchor("Recommendations");
                    s.BulletedListWithFill(b.Classification.Recommendations.Select(r => r.Title ?? r.Code).ToArray(), fillHex: "#FFF4CE");
                }
            }
            s.Finish(autoFitColumns: true);
        }

        // Index
        SheetIndex.Add(doc, sheetName: "Index", placeFirst: true, includeNamedRanges: false);
        SheetIndex.AddBackLinks(doc, tocSheetName: "Index", row: 2, col: 1, text: "← Index");

        doc.Save();
#endif
    }

    private static List<KeyValuePair<string, DomainBucket>> OrderDomains(IReadOnlyList<object> items, Dictionary<string, DomainBucket> grouped, DomainDetective.Reports.DomainOrder order)
    {
        if (order == DomainDetective.Reports.DomainOrder.Alphabetical)
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

    private static string MakeUniqueSheetName(string domain, HashSet<string> used)
    {
        string Sanitize(string input)
        {
            if (string.IsNullOrWhiteSpace(input)) return "Sheet";
            var invalid = new char[] { ':', '\\', '/', '?', '*', '[', ']' };
            var cleaned = new string(input.Where(ch => !invalid.Contains(ch)).ToArray());
            if (cleaned.Length > 31) cleaned = cleaned.Substring(0, 31);
            if (string.IsNullOrWhiteSpace(cleaned)) cleaned = "Sheet";
            return cleaned;
        }
        var baseName = Sanitize(domain);
        var name = baseName;
        int counter = 2;
        while (used.Contains(name))
        {
            var suffix = $" ({counter})";
            var trimmed = baseName;
            if (baseName.Length + suffix.Length > 31)
                trimmed = baseName.Substring(0, Math.Max(1, 31 - suffix.Length));
            name = trimmed + suffix;
            counter++;
        }
        used.Add(name);
        return name;
    }
}
