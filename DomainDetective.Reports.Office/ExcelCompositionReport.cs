using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Reports;
using System.IO;
#if NET8_0
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;
using DocumentFormat.OpenXml.Spreadsheet;
using SixLabors.ImageSharp;
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
        var sumRows = new List<object>();
        int totalWarn = 0, totalErr = 0;
        foreach (var kv in domains)
        {
            var b = kv.Value;
            int warn = (b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + b.Dkim.Sum(x => x.WarningCount);
            int err  = (b.Mx?.ErrorCount ?? 0) + (b.Spf?.ErrorCount ?? 0) + (b.Dmarc?.ErrorCount ?? 0) + (b.Mtasts?.ErrorCount ?? 0) + (b.TlsRpt?.ErrorCount ?? 0) + b.Dkim.Sum(x => x.ErrorCount);
            totalWarn += warn; totalErr += err;
            string status(string? s) => string.IsNullOrWhiteSpace(s) ? "-" : s!;
            string dkimStatus = b.Dkim.Count > 0 ? (b.Dkim.Max(x => x.Status) ?? "-") : "-";
            sumRows.Add(new {
                Domain = kv.Key,
                MX = status(b.Mx?.Status),
                SPF = status(b.Spf?.Status),
                DKIM = dkimStatus,
                DMARC = status(b.Dmarc?.Status),
                MTASTS = status(b.Mtasts?.Status),
                TLSRPT = status(b.TlsRpt?.Status),
                Warnings = warn,
                Errors = err
            });
        }
        // Totals row at the end of the overview table
        sumRows.Add(new {
            Domain = "TOTAL",
            MX = string.Empty,
            SPF = string.Empty,
            DKIM = string.Empty,
            DMARC = string.Empty,
            MTASTS = string.Empty,
            TLSRPT = string.Empty,
            Warnings = totalWarn,
            Errors = totalErr
        });

        // KPI row
        overview.KpiRow(new (string, object?)[] {
            ("Domains", domains.Count),
            ("Warnings", totalWarn),
            ("Errors", totalErr)
        }, perRow: 3);

        // Summary table with conditional visuals
        var range = overview.TableFrom(sumRows, title: "Domains", configure: o => {
            o.HeaderCase = HeaderCase.Title;
        }, visuals: v => {
            // Numeric formatting
            v.NumericColumnFormats["Warnings"] = "0";
            v.NumericColumnFormats["Errors"] = "0";
            // Data bars for findings
            v.DataBars["Warnings"] = SixLabors.ImageSharp.Color.ParseHex("#FFA500"); // orange
            v.DataBars["Errors"] = SixLabors.ImageSharp.Color.ParseHex("#DC3545");   // red
            // Backgrounds for text statuses
            var ok = "#D1E7DD";      // light green
            var warn = "#FFF4CE";    // light yellow
            var err = "#F8D7DA";     // light red
            var none = "#E9ECEF";    // light gray
            foreach (var col in new[] { "MX", "SPF", "DKIM", "DMARC", "MTASTS", "TLSRPT" })
            {
                v.TextBackgrounds[col] = new System.Collections.Generic.Dictionary<string, string>(System.StringComparer.OrdinalIgnoreCase) {
                    { "OK", ok }, { "Pass", ok }, { "Valid", ok },
                    { "Warning", warn }, { "Warn", warn },
                    { "Error", err }, { "Fail", err },
                    { "-", none }, { "None", none }, { "Missing", none }
                };
                v.BoldByText[col] = new System.Collections.Generic.HashSet<string>(System.StringComparer.OrdinalIgnoreCase) { "Error", "Fail" };
            }
            v.FreezeHeaderRow = true;
        });

        // Add traffic light icon set to Errors column
        try
        {
            var coords = ParseRange(range ?? string.Empty);
            if (coords.startCol != 0)
            {
                // Errors is the 9th column of our table definition
                int errorsCol = coords.startCol + 9 - 1;
                string colLetter = IndexToCol(errorsCol);
                // Exclude header row
                string errRange = $"{colLetter}{coords.startRow + 1}:{colLetter}{coords.endRow}";
                overview.ConditionalIconSet(errRange, IconSetValues.ThreeTrafficLights1);
            }
        }
        catch { }
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

            // Providers (Primary · Gateways · Outbound) + quick top links
            try
            {
                var primary = b.Mx?.ProviderPrimary ?? string.Empty;
                var gateways = b.Mx?.ProviderGateways ?? new List<string>();
                var outbound = new List<string>();
                try
                {
                    var names = (b.Spf?.ProviderHelp ?? new List<DomainDetective.Views.ProviderHelpLinks>())
                        .Select(p => p?.ProviderName)
                        .Where(n => !string.IsNullOrWhiteSpace(n))
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToList();
                    foreach (var n in names)
                    {
                        if (string.IsNullOrWhiteSpace(n)) continue;
                        if (string.Equals(n, primary, StringComparison.OrdinalIgnoreCase)) continue;
                        if (gateways.Contains(n, StringComparer.OrdinalIgnoreCase)) continue;
                        outbound.Add(n);
                    }
                }
                catch { }

                var providerKvp = new List<(string, object?)>();
                if (!string.IsNullOrWhiteSpace(primary)) providerKvp.Add(("Primary", primary));
                if ((gateways?.Count ?? 0) > 0) providerKvp.Add(("Gateways", string.Join(", ", gateways!)));
                if (outbound.Count > 0) providerKvp.Add(("Outbound", string.Join(", ", outbound)));
                if (providerKvp.Count > 0)
                {
                    s.SectionWithAnchor("Providers");
                    s.PropertiesGrid(providerKvp.ToArray(), columns: 3);

                    // Top links (take 3 from primary provider help if available)
                    try
                    {
                        var links = b.Mx?.ProviderHelp ?? b.Spf?.ProviderHelp;
                        var primaryHelp = links?.FirstOrDefault(p => string.Equals(p?.ProviderName, primary, StringComparison.OrdinalIgnoreCase))
                                          ?? links?.FirstOrDefault();
                        if (primaryHelp != null && (primaryHelp.Topics?.Count ?? 0) > 0)
                        {
                            var top = primaryHelp.Topics.Where(t => !string.IsNullOrWhiteSpace(t?.Url)).Take(3).ToList();
                            if (top.Count > 0)
                            {
                                s.Section("Top Links");
                                s.BulletedList(top.Select(t => $"{(string.IsNullOrWhiteSpace(t?.Title) ? t!.Topic : t!.Title)}: {t!.Url}").ToArray());
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }

            // Transport section (compact)
            if (b.Mtasts != null || b.TlsRpt != null)
            {
                s.SectionWithAnchor("Transport");
                var tp = new System.Collections.Generic.List<(string, object?)>();
                if (b.Mtasts != null)
                {
                    tp.Add(("MTA-STS", b.Mtasts.Status ?? "-"));
                    tp.Add(("Mode", b.Mtasts.Mode ?? "-"));
                    tp.Add(("Max-Age", b.Mtasts.MaxAge));
                    tp.Add(("DNS Present", b.Mtasts.DnsRecordPresent ? "Yes" : "No"));
                    tp.Add(("Policy Valid", b.Mtasts.PolicyValid ? "Yes" : "No"));
                    tp.Add(("MX Aligned", b.Mtasts.MxAligned ? "Yes" : "No"));
                }
                if (b.TlsRpt != null)
                {
                    tp.Add(("TLS-RPT", b.TlsRpt.Status ?? "-"));
                    tp.Add(("Record Exists", b.TlsRpt.TlsRptRecordExists ? "Yes" : "No"));
                    tp.Add(("Policy Valid", b.TlsRpt.PolicyValid ? "Yes" : "No"));
                    tp.Add(("mailto RUA", (b.TlsRpt.MailtoRua?.Count ?? 0)));
                    tp.Add(("http RUA", (b.TlsRpt.HttpRua?.Count ?? 0)));
                }
                if (tp.Count > 0) s.PropertiesGrid(tp.ToArray(), columns: 3);
            }

            // SPF details
            if (b.Spf != null)
            {
                var spf = b.Spf;
                s.SectionWithAnchor("SPF");
                s.PropertiesGrid(new (string, object?)[] {
                    ("Record Present", spf.SpfRecordExists ? "Yes" : "No"),
                    ("Starts Correctly", spf.StartsCorrectly ? "Yes" : "No"),
                    ("DNS Lookups", spf.DnsLookupsCount),
                    ("Exceeds Lookup Limit", spf.ExceedsDnsLookups ? "Yes" : "No"),
                    ("Multiple 'all'", spf.MultipleAllMechanisms ? "Yes" : "No"),
                    ("Multiple SPF Records", spf.MultipleSpfRecords ? "Yes" : "No"),
                    ("Record Length", spf.RecordLength),
                    ("Size Limit", (spf.ExceedsTotalCharacterLimit || spf.ExceedsCharacterLimit) ? "Exceeded" : "OK"),
                    ("Unknown Mechanisms", spf.UnknownMechanisms?.Count ?? 0)
                }, columns: 3);

                // Mechanisms table (Prefix, Type, Value, Provider, Source, Depth)
                if (spf.Mechanisms != null && spf.Mechanisms.Count > 0)
                {
                    var mechRows = spf.Mechanisms.Select(m => new {
                        Prefix = m.Prefix,
                        Type = m.Type,
                        Value = m.Value,
                        Provider = string.IsNullOrWhiteSpace(m.Provider) ? "" : m.Provider,
                        Source = string.IsNullOrWhiteSpace(m.SourceDomain) ? spf.Subject : m.SourceDomain,
                        Depth = m.Depth
                    }).ToList();
                    s.TableFrom(mechRows, title: "Mechanisms", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => { v.NumericColumnFormats["Depth"] = "0"; v.FreezeHeaderRow = true; });
                }

                // Highlights / Recommendations
                if ((spf.Highlights?.Count ?? 0) > 0)
                { s.Section("Highlights"); s.BulletedList(spf.Highlights); }
                if ((spf.Recommendations?.Count ?? 0) > 0)
                { s.Section("Recommendations"); s.BulletedListWithFill(spf.Recommendations.Select(r => r.Title ?? r.Code).ToArray(), fillHex: "#FFF4CE"); }
                if ((spf.Positives?.Count ?? 0) > 0)
                { s.Section("Positives"); s.BulletedList(spf.Positives.Select(p => p.Title ?? p.Code).ToArray()); }
            }

            // DMARC details
            if (b.Dmarc != null)
            {
                var d = b.Dmarc;
                s.SectionWithAnchor("DMARC");
                s.PropertiesGrid(new (string, object?)[] {
                    ("Record Present", d.DmarcRecordExists ? "Yes" : "No"),
                    ("Starts Correctly", d.StartsCorrectly ? "Yes" : "No"),
                    ("Policy (p)", d.Policy ?? "-"),
                    ("Subdomain Policy (sp)", d.SubPolicy ?? "-"),
                    ("Percent (pct)", d.Percent ?? "-"),
                    ("Alignment", $"dkim={d.DkimAlignment ?? "?"} / spf={d.SpfAlignment ?? "?"}"),
                    ("Public Suffix Policy", string.IsNullOrWhiteSpace(d.PublicSuffixPolicy) ? "-" : d.PublicSuffixPolicy),
                    ("Nonexistent Policy", string.IsNullOrWhiteSpace(d.NonexistentPolicy) ? "-" : d.NonexistentPolicy),
                    ("Is Policy Valid", d.IsPolicyValid ? "Yes" : "No")
                }, columns: 3);

                // RUA/RUF lists
                if ((d.MailtoRua?.Count ?? 0) > 0 || (d.HttpRua?.Count ?? 0) > 0)
                {
                    s.Section("RUA Destinations");
                    var list = new List<string>();
                    if (d.MailtoRua != null) list.AddRange(d.MailtoRua);
                    if (d.HttpRua != null) list.AddRange(d.HttpRua);
                    s.BulletedList(list);
                }
                if ((d.MailtoRuf?.Count ?? 0) > 0 || (d.HttpRuf?.Count ?? 0) > 0)
                {
                    s.Section("RUF Destinations");
                    var list = new List<string>();
                    if (d.MailtoRuf != null) list.AddRange(d.MailtoRuf);
                    if (d.HttpRuf != null) list.AddRange(d.HttpRuf);
                    s.BulletedList(list);
                }
                if ((d.DeprecatedTags?.Count ?? 0) > 0)
                { s.Section("Deprecated Tags"); s.BulletedList(d.DeprecatedTags); }
                if ((d.Recommendations?.Count ?? 0) > 0)
                { s.Section("Recommendations"); s.BulletedListWithFill(d.Recommendations.Select(r => r.Title ?? r.Code).ToArray(), fillHex: "#FFF4CE"); }
                if ((d.Positives?.Count ?? 0) > 0)
                { s.Section("Positives"); s.BulletedList(d.Positives.Select(p => p.Title ?? p.Code).ToArray()); }
                if ((d.Highlights?.Count ?? 0) > 0)
                { s.Section("Highlights"); s.BulletedList(d.Highlights); }
            }

            // DKIM details
            if (b.Dkim.Count > 0)
            {
                s.SectionWithAnchor("DKIM");
                var rows = b.Dkim.Select(k => new {
                    Selector = k.Selector,
                    Status = k.Status ?? "-",
                    KeyBits = k.PublicKeyExists ? k.KeyLength : 0,
                    WeakKey = k.WeakKey ? "Yes" : "No",
                    Hash = k.HashAlgorithm ?? "-",
                    PublicKey = k.PublicKeyExists ? "Yes" : "No",
                    Flags = string.IsNullOrWhiteSpace(k.Flags) ? "-" : k.Flags,
                    Canon = string.IsNullOrWhiteSpace(k.Canonicalization) ? "-" : k.Canonicalization,
                    Created = k.CreationDate?.ToString("yyyy-MM-dd") ?? "",
                    AgeDays = k.KeyAgeDays
                }).ToList();
                s.TableFrom(rows, title: "Selectors", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => {
                    v.NumericColumnFormats["KeyBits"] = "0";
                    v.NumericColumnFormats["AgeDays"] = "0";
                    v.TextBackgrounds["Status"] = new System.Collections.Generic.Dictionary<string, string>(System.StringComparer.OrdinalIgnoreCase) {
                        { "Valid", "#D1E7DD" }, { "OK", "#D1E7DD" }, { "Warning", "#FFF4CE" }, { "Error", "#F8D7DA" }, { "Fail", "#F8D7DA" }
                    };
                    v.BoldByText["Status"] = new System.Collections.Generic.HashSet<string>(System.StringComparer.OrdinalIgnoreCase) { "Error", "Fail" };
                    v.FreezeHeaderRow = true;
                });
                // Highlights/Recommendations (aggregated)
                var dkimHighlights = b.Dkim.SelectMany(x => x.Highlights ?? new List<string>()).Distinct().ToList();
                if (dkimHighlights.Count > 0) { s.Section("Highlights"); s.BulletedList(dkimHighlights); }
                var dkimRecs = b.Dkim.SelectMany(x => x.Recommendations ?? new List<DomainDetective.RecommendationAdvice>()).Select(r => r.Title ?? r.Code).Distinct().ToArray();
                if (dkimRecs.Length > 0) { s.Section("Recommendations"); s.BulletedListWithFill(dkimRecs, fillHex: "#FFF4CE"); }
            }

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
#if NET8_0
        try
        {
            var errs = doc.ValidateDocument();
            if (errs.Count > 0)
            {
                var report = string.Join(Environment.NewLine, errs.Select(e => $"{e.ErrorType}: {e.Description} at {e.Path?.XPath}"));
                File.WriteAllText(Path.ChangeExtension(path, ".xlsx.validation.txt"), report);
            }
        }
        catch { }
#endif
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
                case DomainDetective.Views.DnsblInfo db when !string.IsNullOrWhiteSpace(db.Subject): Ensure(db.Subject); map[db.Subject].Dnsbl = db; break;
                case DomainDetective.Views.ArcInfo arc when arc != null: Ensure(map.Keys.FirstOrDefault() ?? (TryGetSubject(it) ?? Global)); var keyArc = map.Keys.First(); map[keyArc].Arc = arc; break;
                case DomainDetective.Views.BimiRecordInfo bimi when !string.IsNullOrWhiteSpace(bimi.Subject): Ensure(bimi.Subject); map[bimi.Subject].Bimi = bimi; break;
                case DomainDetective.Views.DnssecStatusInfo ds when !string.IsNullOrWhiteSpace(ds.Subject): Ensure(ds.Subject); map[ds.Subject].Dnssec = ds; break;
                case DomainDetective.Views.DaneRecordInfo dn when !string.IsNullOrWhiteSpace(dn.Subject): Ensure(dn.Subject); map[dn.Subject].Dane = dn; break;
                case DomainDetective.Views.MailTlsInfo mt when !string.IsNullOrWhiteSpace(mt.Subject):
                    Ensure(mt.Subject);
                    switch (mt.Check) {
                        case DomainDetective.HealthCheckType.SMTPTLS: map[mt.Subject].SmtpTls = mt; break;
                        case DomainDetective.HealthCheckType.IMAPTLS: map[mt.Subject].ImapTls = mt; break;
                        case DomainDetective.HealthCheckType.POP3TLS: map[mt.Subject].PopTls = mt; break;
                        default: break;
                    }
                    break;
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

    // Helpers for A1 range parsing (e.g., "B4:J27")
    private struct RangeCoords
    {
        public int startCol, startRow, endCol, endRow;
        public RangeCoords(int sc, int sr, int ec, int er) { startCol = sc; startRow = sr; endCol = ec; endRow = er; }
    }
    private static RangeCoords ParseRange(string a1)
    {
        if (string.IsNullOrWhiteSpace(a1)) return default;
        var parts = a1.Split(':');
        if (parts.Length != 2) return default;
        var (sc, sr) = A1ToCoord(parts[0]);
        var (ec, er) = A1ToCoord(parts[1]);
        if (sc <= 0 || sr <= 0 || ec <= 0 || er <= 0) return default;
        return new RangeCoords(Math.Min(sc, ec), Math.Min(sr, er), Math.Max(sc, ec), Math.Max(sr, er));
    }
    private static (int col, int row) A1ToCoord(string cell)
    {
        if (string.IsNullOrWhiteSpace(cell)) return (0, 0);
        int i = 0; int col = 0;
        while (i < cell.Length && char.IsLetter(cell[i])) { col = col * 26 + (char.ToUpperInvariant(cell[i]) - 'A' + 1); i++; }
        int row = 0; while (i < cell.Length && char.IsDigit(cell[i])) { row = row * 10 + (cell[i] - '0'); i++; }
        return (col, row);
    }
    private static string IndexToCol(int index)
    {
        if (index <= 0) return "A";
        string s = string.Empty;
        while (index > 0)
        {
            index--; s = (char)('A' + (index % 26)) + s; index /= 26;
        }
        return s;
    }
}
