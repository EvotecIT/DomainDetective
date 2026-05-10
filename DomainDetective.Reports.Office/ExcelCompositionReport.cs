using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using DomainDetective.Reports;
using System.IO;
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;
using DocumentFormat.OpenXml.Spreadsheet;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Excel composition across mixed view items (Index, Overview, per-domain sheets).
/// Implemented using OfficeIMO.Excel.
/// </summary>
public static partial class ExcelCompositionReport {
    public static void Generate(
        string path,
        IReadOnlyList<object> items,
        ReportScope scope,
        OrderingOptions? ordering = null,
        ExcelProfile profile = ExcelProfile.Workbook) {
        if (items == null || items.Count == 0) throw new ArgumentException("No items to compose.", nameof(items));
        var compGroups = CompositionBuilder.GroupBySubject(items);
        var order = (ordering != null) ? ordering.DomainOrder : DomainOrder.Alphabetical;
        var orderedComp = CompositionBuilder.OrderDomains(items, compGroups, order);
        var domains = orderedComp.Select(kv => new KeyValuePair<string, DomainBucket>(kv.Key, Map(kv.Value))).ToList();

        using var doc = ExcelDocument.Create(path);
        doc.AsFluent().Info(i => i
            .Title("Domain Detective — Excel Composition")
            .Author("DomainDetective")
            .Company("Evotec")
            .Application("OfficeIMO.Excel")
            .Keywords("excel,report,domains")).End();

        BuildOverviewSheet(doc, items, order, domains);
        if (profile == ExcelProfile.Dashboard)
        {
            try { BuildDiscoveryDashboardSheet(doc, domains); } catch (Exception ex) { Trace.TraceWarning("ExcelCompositionReport: failed to build dashboard sheet: {0}", ex.Message); }
        }

        // Per-domain sheets (skip in Dashboard profile)
        if (profile != ExcelProfile.Dashboard)
        {
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
                ("DKIM", DomainDetective.Reports.DisplayFormatting.ComposeDkimSummary(b.Dkim, includeSelectorCount: true)),
                ("DMARC", b.Dmarc?.Status ?? "-"),
                ("M365", b.Microsoft365?.Status ?? "-"),
                ("MTA-STS", b.Mtasts?.Status ?? "-"),
                ("TLS-RPT", b.TlsRpt?.Status ?? "-"),
                ("DNSSEC", DomainDetective.Reports.DisplayFormatting.ComposeDnssecSummary(b.Dnssec)),
                ("RPKI", DomainDetective.Reports.DisplayFormatting.ComposeRpkiSummary(b.Rpki))
            }, columns: 3);

            // Column block queues: [0] Email Auth, [1] Transport, [2] Infrastructure/Infra-Rep.
            static void ApplyBlock(SheetComposer.ColumnComposer column, Action<SheetComposer.ColumnComposer>? block)
            {
                block?.Invoke(column);
            }

            s.Columns(3, cols =>
            {
                var auth = cols[0];
                ApplyBlock(auth, BuildEmailAuthenticationOverviewBlock(b));
                ApplyBlock(auth, BuildDesiredStateBlock(s, b));
                ApplyBlock(auth, BuildSpfBlock(s, b));
                ApplyBlock(auth, BuildDkimBlock(s, b));
                ApplyBlock(auth, BuildDmarcBlock(b));
                ApplyBlock(auth, BuildBimiBlock(b));
                ApplyBlock(auth, BuildClassificationBlock(b));
                ApplyBlock(auth, BuildMicrosoft365Block(b));
                RenderProviderBlock(s, auth, b);

                var transport = cols[1];
                transport.Section("Transport");
                ApplyBlock(transport, BuildTransportSummaryBlock(b));
                ApplyBlock(transport, BuildMailTlsBlock(s, b));
                ApplyBlock(transport, BuildMxBlock(b));
                ApplyBlock(transport, BuildArcBlock(b));

                var infra = cols[2];
                infra.Section("Infrastructure & Reputation");
                ApplyBlock(infra, BuildDnssecDaneBlock(b));
                ApplyBlock(infra, BuildDnsblBlock(s, b));
                ApplyBlock(infra, BuildNsBlock(b));
                ApplyBlock(infra, BuildSoaBlock(b));
                ApplyBlock(infra, BuildDnsInventoryBlock(b));
                ApplyBlock(infra, BuildDnsTraceBlock(b));
                ApplyBlock(infra, BuildDnsPropagationBlock(b));
                ApplyBlock(infra, BuildDnsAmplificationBlock(b));
                ApplyBlock(infra, BuildDnsOverTlsBlock(b));
                ApplyBlock(infra, BuildCtTimelineBlock(b));
                ApplyBlock(infra, BuildHttpBlock(b));
                ApplyBlock(infra, BuildTyposquattingBlock(b));
                ApplyBlock(infra, BuildIpEnrichmentBlock(b));
                ApplyBlock(infra, BuildCaaBlock(b));
                ApplyBlock(infra, BuildRpkiBlock(b));
                ApplyBlock(infra, BuildZoneTransferBlock(b));
                ApplyBlock(infra, BuildWildcardBlock(b));
                ApplyBlock(infra, BuildSubdomainsBlock(b));
            }, columnWidth: 12, gutter: 2);
            s.Finish(autoFitColumns: true);
        }

        // (duplicate DKIM/DMARC detail blocks removed — handled earlier within the per-domain sheet scope)

        // (no extra per-domain sheets created; all deep tables appended to their domain sheet)

        // Summary sheet (counts by control)
        try
        {
            var sum = new SheetComposer(doc, "Summary");
            sum.Title("Control Summary");
            var controls = new[]{"MX","SPF","DKIM","DMARC","MTA-STS","TLS-RPT"};
            var rows = new List<object>();
            foreach (var c in controls)
            {
                int ok=0, warn=0, err=0, unk=0;
                foreach (var kv in domains)
                {
                    string status = c switch {
                        "MX" => kv.Value.Mx?.Status,
                        "SPF" => kv.Value.Spf?.Status,
                        "DKIM" => (kv.Value.Dkim.Count>0 ? (kv.Value.Dkim.Max(x=>x.Status) ?? "-") : "-"),
                        "DMARC" => kv.Value.Dmarc?.Status,
                        "MTA-STS" => kv.Value.Mtasts?.Status,
                        _ => kv.Value.TlsRpt?.Status
                    } ?? "-";
                    var s = status.Trim().ToLowerInvariant();
                    if (s.Contains("error") || s.Contains("fail")) err++;
                    else if (s.Contains("warn")) warn++;
                    else if (s=="-" || s.Contains("none") || s.Contains("missing")) unk++;
                    else ok++;
                }
                rows.Add(new { Control = c, OK = ok, Warning = warn, Error = err, Unknown = unk });
            }
            sum.TableFrom(rows, title: null, configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => {
                v.NumericColumnFormats["OK"] = "0"; v.NumericColumnFormats["Warning"] = "0"; v.NumericColumnFormats["Error"] = "0"; v.NumericColumnFormats["Unknown"] = "0"; v.FreezeHeaderRow = true;
            });
            sum.Finish(autoFitColumns: true);
        }
        catch { }

        // Status Matrix sheet (Domain x Control)
        try
        {
            var mx = new SheetComposer(doc, "Matrix");
            mx.Title("Status Matrix");
            var matrix = new List<object>();
            foreach (var kv in domains)
            {
                var b = kv.Value; string dom = kv.Key;
                string dkim = b.Dkim.Count>0 ? (b.Dkim.Max(x=>x.Status) ?? "-") : "-";
                matrix.Add(new {
                    Domain = dom,
                    MX = b.Mx?.Status ?? "-",
                    SPF = b.Spf?.Status ?? "-",
                    DKIM = dkim,
                    DMARC = b.Dmarc?.Status ?? "-",
                    MTASTS = b.Mtasts?.Status ?? "-",
                    TLSRPT = b.TlsRpt?.Status ?? "-",
                    DNSBL = b.Dnsbl?.Status ?? "-",
                    NS = b.Ns?.Status ?? "-",
                    SOA = b.Soa?.Status ?? "-",
                    CAA = b.Caa?.Status ?? "-",
                    RPKI = b.Rpki?.Status ?? "-"
                });
            }
            mx.TableFrom(matrix, title: null, configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => {
                var ok = "#D1E7DD"; var warn = "#FFF4CE"; var err = "#F8D7DA"; var none = "#E9ECEF";
                foreach (var col in new[]{"MX","SPF","DKIM","DMARC","MTASTS","TLSRPT","DNSBL","NS","SOA","CAA","RPKI"})
                {
                    v.TextBackgrounds[col] = new System.Collections.Generic.Dictionary<string,string>(System.StringComparer.OrdinalIgnoreCase) {
                        {"OK", ok},{"Pass", ok},{"Valid", ok},{"Warning", warn},{"Warn", warn},{"Error", err},{"Fail", err},{"-", none},{"None", none},{"Missing", none}
                    };
                }
                v.FreezeHeaderRow = true;
            });
            mx.Finish(autoFitColumns: true);
        }
        catch { }

        // SPF Providers summary sheet
        try
        {
            var sp = new SheetComposer(doc, "SPF Providers");
            sp.Title("SPF Providers");
            var agg = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in domains)
            {
                var pc = kv.Value.Spf?.ProviderCounts;
                if (pc == null) continue;
                foreach (var p in pc) agg[p.Key] = (agg.TryGetValue(p.Key, out var c) ? c : 0) + p.Value;
            }
            var rows = agg.OrderByDescending(kv2 => kv2.Value).Select(kv2 => new { Provider = kv2.Key, Tokens = kv2.Value }).ToList();
            sp.TableFrom(rows, title: null, configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => { v.NumericColumnFormats["Tokens"] = "0"; v.FreezeHeaderRow = true; });
            sp.Finish(autoFitColumns: true);
        }
        catch { }

        // All Recommendations sheet
        try
        {
            var recSheet = new SheetComposer(doc, "Recommendations");
            recSheet.Title("All Recommendations");
            var recRows = new List<object>();
            foreach (var kv in domains)
            {
                string d = kv.Key; var b = kv.Value;
                void AddRecs(string section, IEnumerable<DomainDetective.RecommendationAdvice>? list)
                {
                    if (list == null) return;
                    foreach (var r in list) recRows.Add(new { Domain = d, Section = section, Title = r.Title ?? r.Code });
                }
                AddRecs("MX", b.Mx?.Recommendations);
                AddRecs("SPF", b.Spf?.Recommendations);
                if (b.Dkim.Count>0) AddRecs("DKIM", b.Dkim.SelectMany(x => x.Recommendations ?? new List<DomainDetective.RecommendationAdvice>()));
                AddRecs("DMARC", b.Dmarc?.Recommendations);
                AddRecs("MTA-STS", b.Mtasts?.Recommendations);
                AddRecs("TLS-RPT", b.TlsRpt?.Recommendations);
                AddRecs("DNSBL", b.Dnsbl?.Recommendations);
                AddRecs("Microsoft 365", b.Microsoft365?.Recommendations);
                AddRecs("NS", b.Ns?.Recommendations);
                AddRecs("SOA", b.Soa?.Recommendations);
                AddRecs("DNS Amplification", b.DnsAmplification?.Recommendations);
                AddRecs("DNS over TLS", b.DnsOverTls?.Recommendations);
                AddRecs("CAA", b.Caa?.Recommendations);
                AddRecs("RPKI", b.Rpki?.Recommendations);
                AddRecs("ZoneTransfer", b.ZoneTransfer?.Recommendations);
                AddRecs("Wildcard", b.Wildcard?.Recommendations);
            }
            if (recRows.Count == 0) recRows.Add(new { Domain = "—", Section = "—", Title = "No recommendations" });
            var recRange = recSheet.TableFrom(recRows, title: null, configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => { v.FreezeHeaderRow = true; });
            recSheet.ApplyColumnSizing(recRange, opt => {
                opt.MediumHeaders.Add("Domain");
                opt.ShortHeaders.Add("Section");
                opt.LongHeaders.Add("Title");
                opt.WrapHeaders.Add("Title");
            });
            recSheet.Finish(autoFitColumns: true);
        }
        catch { }

        // References sheet (Word parity)
        try
        {
            var comp = CompositionBuilder.GroupBySubject(items);
            var refs = ReferencesCollector.CollectAll(comp.Values);
            var refSheet = new SheetComposer(doc, "References");
            refSheet.Title("All References");
            if (refs.Count == 0) { refSheet.BulletedList(new[] { "No references" }); }
            else
            {
                var rows = refs.Select(u => {
                    var f = LinkFormatter.Format(u);
                    return new { Title = f.Title, Url = f.Url };
                }).ToList();
                var refRange = refSheet.TableFrom(rows, title: null, configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => v.FreezeHeaderRow = true);
                try
                {
                    foreach (var row in refSheet.Sheet.RowsObjects(refRange))
                    {
                        var titleCell = row.CellByHeader("Title");
                        var urlCell = row.CellByHeader("Url");
                        string urlRef = IndexToCol(urlCell.ColumnIndex) + titleCell.RowIndex.ToString();
                        string safeTitle = (row.GetOrDefault<string>("Title", string.Empty) ?? string.Empty).Replace("\"", "\"\"");
                        row.SetFormula("Title", $"=HYPERLINK({urlRef},\"{safeTitle}\")");
                    }
                }
                catch { }
                // Clamp widths for readable references
                refSheet.ApplyColumnSizing(refRange, opt => {
                    opt.LongHeaders.Add("Url");
                    opt.MediumHeaders.Add("Title");
                    // Do not wrap URLs; titles are hyperlinks already
                });
            }
            // Disable AutoFit here — URLs can be long and blow out column widths.
            refSheet.Finish(autoFitColumns: false);
        }
        catch { }

        } // end if (profile != ExcelProfile.Dashboard)

        // Index
        SheetIndex.Add(doc, sheetName: "Index", placeFirst: true, includeNamedRanges: false);
        SheetIndex.AddBackLinks(doc, tocSheetName: "Index", row: 2, col: 1, text: "← Index");

        doc.SafeSave();
//#if NET8_0
        // try
        // {

        Console.WriteLine($"Validating generated Excel document: {path}");
            var errs = doc.ValidateDocument();
            if (errs.Count > 0)
            {
                Console.WriteLine($"Validation found {errs.Count} issues; see '{Path.ChangeExtension(path, ".xlsx.validation.txt")}' for details.");
                foreach (var e in errs)
                {
                    Console.WriteLine($"{e.ErrorType}: {e.Description} at {e.Path?.XPath}");
                }
                var report = string.Join(Environment.NewLine, errs.Select(e => $"{e.ErrorType}: {e.Description} at {e.Path?.XPath}"));
                File.WriteAllText(Path.ChangeExtension(path, ".xlsx.validation.txt"), report);
            } else {
                Console.WriteLine("No validation issues found.");
            }
        // }
        // catch { }
//#endif
    }

}


