using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using DomainDetective.Reports;
using System.IO;
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;
using DocumentFormat.OpenXml.Spreadsheet;
using SixLabors.ImageSharp;

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
                ApplyBlock(auth, BuildSpfBlock(s, b));
                ApplyBlock(auth, BuildDkimBlock(s, b));
                ApplyBlock(auth, BuildDmarcBlock(b));
                ApplyBlock(auth, BuildBimiBlock(b));
                ApplyBlock(auth, BuildClassificationBlock(b));
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

    private static Action<SheetComposer.ColumnComposer> BuildEmailAuthenticationOverviewBlock(DomainBucket bucket)
    {
        return column => column.Section("Email Authentication");
    }

    private static Action<SheetComposer.ColumnComposer>? BuildSpfBlock(SheetComposer composer, DomainBucket bucket)
    {
        if (bucket.Spf == null)
        {
            return null;
        }

        var spf = bucket.Spf;
        var projection = DomainDetective.Reports.SectionProjectors.BuildSpf(spf);

        return column =>
        {
            column.Section("SPF");

            var props = new List<(string, object?)>
            {
                ("Status", spf.Status ?? "-"),
                ("Record Present", spf.SpfRecordExists ? "Yes" : "No"),
                ("Starts Correctly", spf.StartsCorrectly ? "Yes" : "No"),
                ("DNS TTL (s)", spf.DnsRecordTtl?.ToString() ?? "-"),
                ("CNAME Resolved", spf.IsCnameResolved ? "Yes" : "No"),
                ("CNAME TTL (s)", spf.CnameTtl?.ToString() ?? "-"),
                ("DNS Lookups", projection?.DnsLookupsCount ?? spf.DnsLookupsCount)
            };

            if (!string.IsNullOrWhiteSpace(spf.Raw?.AllMechanism))
            {
                props.Add(("All Mechanism", spf.Raw!.AllMechanism!));
            }

            column.KeyValues(props);

            if ((projection?.Findings.Count ?? 0) > 0)
            {
                var rows = projection!.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList();
                var range = column.TableFrom(rows, title: "Findings", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
                composer.ApplyColumnSizing(range, opt =>
                {
                    opt.ShortHeaders.Add("Severity");
                    opt.MediumHeaders.UnionWith(new[] { "Code", "Target" });
                    opt.LongHeaders.Add("Message");
                    opt.WrapHeaders.Add("Message");
                });
            }

            if (!string.IsNullOrWhiteSpace(projection?.SpfRecord))
            {
                column.Section("Evidence").KeyValues(new (string, object?)[] { ("SPF Record", projection!.SpfRecord) });
            }

            if ((projection?.Mechanisms.Count ?? 0) > 0)
            {
                var mech = projection!.Mechanisms.Select(m => new { Prefix = m.Qualifier, Type = m.Type, Value = m.Value, Provider = m.Provider }).ToList();
                var range = column.TableFrom(mech, title: "Mechanisms", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
                composer.ApplyColumnSizing(range, opt =>
                {
                    opt.ShortHeaders.Add("Prefix");
                    opt.MediumHeaders.Add("Type");
                    opt.LongHeaders.Add("Value");
                    opt.WrapHeaders.Add("Value");
                });
            }

            if ((projection?.FlattenedUniqueIpCount ?? 0) + (projection?.FlattenedDuplicateIpCount ?? 0) + (projection?.FlattenedTokenCount ?? 0) > 0)
            {
                column.Section("Flattened IP Analysis").KeyValues(new (string, object?)[]
                {
                    ("Unique IPs", projection!.FlattenedUniqueIpCount),
                    ("Duplicate IPs", projection.FlattenedDuplicateIpCount),
                    ("Tokens Resolved", projection.FlattenedTokenCount)
                });
            }

            if ((projection?.ProviderHelp.Count ?? 0) > 0)
            {
                var list = projection!.ProviderHelp.Take(8)
                    .Select(t => string.IsNullOrWhiteSpace(t.Title) ? t.Url ?? string.Empty : t.Title!)
                    .ToArray();
                column.Section("Provider Help").BulletedList(list);
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildDkimBlock(SheetComposer composer, DomainBucket bucket)
    {
        if (bucket.Dkim == null || bucket.Dkim.Count == 0)
        {
            return null;
        }

        var projection = DomainDetective.Reports.SectionProjectors.BuildDkim(bucket.Dkim, bucket.Ttl);

        return column =>
        {
            column.Section("DKIM").KeyValues(new (string, object?)[]
            {
                ("Selectors", bucket.Dkim.Count),
                ("Any Weak", bucket.Dkim.Any(x => x.WeakKey) ? "Yes" : "No")
            });

            if (projection != null && projection.Rows.Count > 0)
            {
                var rows = projection.Rows.Select(r => new
                {
                    Selector = r.Selector,
                    Status = string.IsNullOrWhiteSpace(r.Status) ? "-" : r.Status,
                    KeyBits = string.IsNullOrWhiteSpace(r.KeyBits) ? "-" : r.KeyBits,
                    Alg = string.IsNullOrWhiteSpace(r.Hash) ? "-" : r.Hash,
                    Weak = r.Weak ? "Yes" : "No",
                    Flags = string.IsNullOrWhiteSpace(r.Flags) ? string.Empty : r.Flags,
                    TTL = r.TtlSeconds.HasValue ? r.TtlSeconds.Value.ToString() : "-",
                    CnameResolved = r.CnameResolved ? "Yes" : "No",
                    CnameTtl = r.CnameTtlSeconds?.ToString() ?? "-"
                }).ToList();
                var range = column.TableFrom(rows, title: "Selectors", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
                composer.ApplyColumnSizing(range, opt =>
                {
                    opt.ShortHeaders.UnionWith(new[] { "Status", "Weak", "Key Bits", "Alg", "TTL", "Cname Resolved", "Cname Ttl" });
                    opt.MediumHeaders.UnionWith(new[] { "Selector", "Flags" });
                });
            }

            if (projection != null && projection.Findings.Count > 0)
            {
                var rows = projection.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList();
                var range = column.TableFrom(rows, title: "Findings", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
                composer.ApplyColumnSizing(range, opt =>
                {
                    opt.ShortHeaders.Add("Severity");
                    opt.MediumHeaders.UnionWith(new[] { "Code", "Target" });
                    opt.LongHeaders.Add("Message");
                    opt.WrapHeaders.Add("Message");
                });
            }

            if (projection != null && projection.Rows.Any(r => !string.IsNullOrWhiteSpace(r.Record)))
            {
                var rows = projection.Rows
                    .Where(r => !string.IsNullOrWhiteSpace(r.Record))
                    .Select(r => new { r.Selector, Record = r.Record })
                    .ToList();
                var range = column.TableFrom(rows, title: "Evidence", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
                composer.ApplyColumnSizing(range, opt =>
                {
                    opt.MediumHeaders.Add("Selector");
                    opt.LongHeaders.Add("Record");
                    opt.WrapHeaders.Add("Record");
                });
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildDmarcBlock(DomainBucket bucket)
    {
        if (bucket.Dmarc == null)
        {
            return null;
        }

        var d = bucket.Dmarc;
        return column =>
        {
            column.Section("DMARC").KeyValues(new (string, object?)[]
            {
                ("Record Present", d.DmarcRecordExists ? "Yes" : "No"),
                ("Starts Correctly", d.StartsCorrectly ? "Yes" : "No"),
                ("DNS TTL (s)", d.DnsRecordTtl?.ToString() ?? "-"),
                ("CNAME Resolved", d.IsCnameResolved ? "Yes" : "No"),
                ("CNAME TTL (s)", d.CnameTtl?.ToString() ?? "-"),
                ("Policy (p)", d.Policy ?? "-"),
                ("Subdomain Policy (sp)", d.SubPolicy ?? "-"),
                ("Percent (pct)", d.Percent ?? "-"),
                ("Alignment", $"dkim={d.DkimAlignment ?? "?"} / spf={d.SpfAlignment ?? "?"}"),
                ("Public Suffix Policy", string.IsNullOrWhiteSpace(d.PublicSuffixPolicy) ? "-" : d.PublicSuffixPolicy),
                ("Nonexistent Policy", string.IsNullOrWhiteSpace(d.NonexistentPolicy) ? "-" : d.NonexistentPolicy),
                ("Is Policy Valid", d.IsPolicyValid ? "Yes" : "No")
            });

            if ((d.MailtoRua?.Count ?? 0) > 0 || (d.HttpRua?.Count ?? 0) > 0)
            {
                var list = new List<string>();
                if (d.MailtoRua != null) list.AddRange(d.MailtoRua);
                if (d.HttpRua != null) list.AddRange(d.HttpRua);
                column.Section("RUA Destinations").BulletedList(list.ToArray());
            }

            if ((d.MailtoRuf?.Count ?? 0) > 0 || (d.HttpRuf?.Count ?? 0) > 0)
            {
                var list = new List<string>();
                if (d.MailtoRuf != null) list.AddRange(d.MailtoRuf);
                if (d.HttpRuf != null) list.AddRange(d.HttpRuf);
                column.Section("RUF Destinations").BulletedList(list.ToArray());
            }

            var deprecatedTags = d.DeprecatedTags;
            if (deprecatedTags != null && deprecatedTags.Count > 0)
            {
                column.Section("Deprecated Tags").BulletedList(deprecatedTags.ToArray());
            }

            var dmarcRecommendations = d.Recommendations;
            if (dmarcRecommendations != null && dmarcRecommendations.Count > 0)
            {
                column.Section("Recommendations").BulletedList(dmarcRecommendations.Select(r => r.Title ?? r.Code).ToArray());
            }

            var dmarcPositives = d.Positives;
            if (dmarcPositives != null && dmarcPositives.Count > 0)
            {
                column.Section("Positives").BulletedList(dmarcPositives.Select(p => p.Title ?? p.Code).ToArray());
            }

            var dmarcHighlights = d.Highlights;
            if (dmarcHighlights != null && dmarcHighlights.Count > 0)
            {
                column.Section("Highlights").BulletedList(dmarcHighlights);
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildBimiBlock(DomainBucket bucket)
    {
        if (bucket.Bimi == null)
        {
            return null;
        }

        var bi = bucket.Bimi;
        return column =>
        {
            column.Section("BIMI").KeyValues(new (string, object?)[]
            {
                ("Record Present", bi.BimiRecordExists ? "Yes" : "No"),
                ("Starts Correctly", bi.StartsCorrectly ? "Yes" : "No"),
                ("Location", string.IsNullOrWhiteSpace(bi.Location) ? "-" : bi.Location),
                ("Authority", string.IsNullOrWhiteSpace(bi.Authority) ? "-" : bi.Authority),
                ("SVG Valid", bi.SvgValid ? "Yes" : (string.IsNullOrWhiteSpace(bi.SvgInvalidReason) ? "No" : $"No: {bi.SvgInvalidReason}")),
                ("VMC Present", bi.ValidVmc ? "Yes" : "No")
            });
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildClassificationBlock(DomainBucket bucket)
    {
        if (bucket.Classification == null)
        {
            return null;
        }

        var classification = bucket.Classification;
        return column =>
        {
            column.Section("Classification").KeyValues(new (string, object?)[]
            {
                ("Category", classification.Classification),
                ("Confidence", classification.Confidence),
                ("Status", classification.Status)
            });

            if (classification.ScoreBreakdown != null && classification.ScoreBreakdown.Count > 0)
            {
                var list = classification.ScoreBreakdown.Select(kv => $"{kv.Key}: {kv.Value:0.##}").ToArray();
                column.Section("Score Breakdown").BulletedList(list);
            }
        };
    }

    private static void RenderProviderBlock(SheetComposer composer, SheetComposer.ColumnComposer column, DomainBucket bucket)
    {
        try
        {
            var chain = ProviderChainBuilder.Build(bucket.Mx, bucket.Spf);
            var summary = new List<(string, object?)>();

            if (!string.IsNullOrWhiteSpace(chain.Primary)) summary.Add(("Primary", chain.Primary));
            if ((chain.Gateways?.Count ?? 0) > 0) summary.Add(("Gateways", string.Join(", ", chain.Gateways!)));
            if (chain.Outbound.Count > 0) summary.Add(("Outbound", string.Join(", ", chain.Outbound)));

            try
            {
                var hints = ProviderHintsBuilder.Build(bucket.Mx, chain.Primary);
                if (hints.ConfidencePercent > 0) summary.Add(("Confidence", $"{hints.ConfidencePercent}%"));
                if (hints.SingleMxOk) summary.Add(("Single-MX OK", "Yes"));
                if (hints.MinDkimSelectorsToPass > 0) summary.Add(("Min DKIM Selectors", hints.MinDkimSelectorsToPass));
                if (hints.RecommendedMinMxRecords > 0) summary.Add(("Recommended Min MX", hints.RecommendedMinMxRecords));
            }
            catch { }

            var legend = "Legend: Confidence = detection certainty; Single‑MX OK = vendor supports single MX; Gateway = inbound security gateway; Outbound = separate sender platform.";

            var topLinks = new List<(string Title, string Url)>();
            try
            {
                var links = bucket.Mx?.ProviderHelp ?? bucket.Spf?.ProviderHelp;
                var primaryHelp = links?.FirstOrDefault(p => string.Equals(p?.ProviderName, chain.Primary, StringComparison.OrdinalIgnoreCase)) ?? links?.FirstOrDefault();
                var topics = primaryHelp?.Topics;
                if (topics != null && topics.Count > 0)
                {
                    topLinks = topics
                        .Where(t => !string.IsNullOrWhiteSpace(t?.Url))
                        .Take(3)
                        .Select(t =>
                        {
                            var fmt = LinkFormatter.Format(t!.Url ?? string.Empty);
                            var title = string.IsNullOrWhiteSpace(t.Title) ? (t.Topic ?? fmt.Title) : t.Title!;
                            return (title, fmt.Url);
                        })
                        .ToList();
                }
            }
            catch { }

            if (summary.Count == 0 && topLinks.Count == 0)
            {
                return;
            }

            column.Section("Providers");
            if (summary.Count > 0)
            {
                column.KeyValues(summary);
            }

            column.BulletedList(new[] { legend });

            if (topLinks.Count > 0)
            {
                column.Section("Top Links");
                var range = column.TableFrom(topLinks.Select(t => new { Title = t.Title, Url = t.Url }).ToList(), title: null, configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
                try
                {
                    foreach (var row in composer.Sheet.RowsObjects(range))
                    {
                        var titleCell = row.CellByHeader("Title");
                        var urlCell = row.CellByHeader("Url");
                        string urlRef = IndexToCol(urlCell.ColumnIndex) + titleCell.RowIndex.ToString();
                        string safeTitle = (row.GetOrDefault<string>("Title", string.Empty) ?? string.Empty).Replace("\"", "\"\"");
                        row.SetFormula("Title", $"=HYPERLINK({urlRef},\"{safeTitle}\")");
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private static Action<SheetComposer.ColumnComposer>? BuildTransportSummaryBlock(DomainBucket bucket)
    {
        if (bucket.Mtasts == null && bucket.TlsRpt == null)
        {
            return null;
        }

        return column =>
        {
            var details = new List<(string, object?)>();

            if (bucket.Mtasts != null)
            {
                var m = bucket.Mtasts;
                details.Add(("MTA-STS", m.Status ?? "-"));
                details.Add(("Mode", m.Mode ?? "-"));
                details.Add(("Max-Age", m.MaxAge));
                details.Add(("DNS Present", m.DnsRecordPresent ? "Yes" : "No"));
                details.Add(("DNS TTL (s)", m.DnsRecordTtl?.ToString() ?? "-"));
                details.Add(("CNAME Resolved", m.IsCnameResolved ? "Yes" : "No"));
                details.Add(("CNAME TTL (s)", m.CnameTtl?.ToString() ?? "-"));
                details.Add(("Policy Valid", m.PolicyValid ? "Yes" : "No"));
                details.Add(("Has MX", m.HasMx ? "Yes" : "No"));
                details.Add(("MX Aligned", m.MxAligned ? "Yes" : "No"));
            }

            if (bucket.TlsRpt != null)
            {
                var t = bucket.TlsRpt;
                details.Add(("TLS-RPT", t.Status ?? "-"));
                details.Add(("Record Exists", t.TlsRptRecordExists ? "Yes" : "No"));
                details.Add(("DNS TTL (s)", t.DnsRecordTtl?.ToString() ?? "-"));
                details.Add(("CNAME Resolved", t.IsCnameResolved ? "Yes" : "No"));
                details.Add(("CNAME TTL (s)", t.CnameTtl?.ToString() ?? "-"));
                details.Add(("Policy Valid", t.PolicyValid ? "Yes" : "No"));
                details.Add(("mailto RUA", t.MailtoRua?.Count ?? 0));
                details.Add(("http RUA", t.HttpRua?.Count ?? 0));
            }

            if (details.Count > 0)
            {
                column.Section("Transport Summary").KeyValues(details);
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildMailTlsBlock(SheetComposer composer, DomainBucket bucket)
    {
        if (bucket.SmtpTls == null && bucket.ImapTls == null && bucket.PopTls == null)
        {
            return null;
        }

        return column =>
        {
            column.Section("MailTLS");

            void Render(string label, DomainDetective.Views.MailTlsInfo? info)
            {
                if (info == null)
                {
                    return;
                }

                column.Section(label);
                if (info.Servers != null && info.Servers.Count > 0)
                {
                    var rows = info.Servers.Select(v => new
                    {
                        Server = v.Key,
                        Grade = v.Grade.ToString(),
                        CertValid = v.CertificateValid ? "Yes" : "No",
                        Chain = v.ChainValid ? "Yes" : "No",
                        DaysToExp = v.DaysToExpire,
                        Expired = v.IsExpired ? "Yes" : "No",
                        Proto = v.Protocol,
                        TLS13 = v.Tls13Used ? "Yes" : (v.SupportsTls13 ? "Supported" : "No"),
                        Cipher = v.CipherSuite,
                        Issuer = v.Issuer,
                        ValidTo = v.ValidTo?.ToString("yyyy-MM-dd") ?? string.Empty
                    }).ToList();

                    var range = column.TableFrom(rows, title: $"{label} Servers", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                    {
                        v.NumericColumnFormats["DaysToExp"] = "0";
                        v.FreezeHeaderRow = true;
                        v.TextBackgrounds["Grade"] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                        {
                            { "A", "#D1E7DD" },
                            { "B", "#E2E3FF" },
                            { "C", "#FFF4CE" },
                            { "D", "#F8D7DA" },
                            { "F", "#F8D7DA" }
                        };
                    });

                    composer.ApplyColumnSizing(range, opt =>
                    {
                        opt.MediumHeaders.UnionWith(new[] { "Server", "Proto", "Cipher", "Issuer" });
                        opt.ShortHeaders.UnionWith(new[] { "Grade", "CertValid", "Chain", "Hostname", "TLS13", "DaysToExp", "Expired", "ValidTo" });
                        opt.WrapHeaders.Add("Server");
                    });
                }
            }

            Render("SMTP", bucket.SmtpTls);
            Render("IMAP", bucket.ImapTls);
            Render("POP3", bucket.PopTls);
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildMxBlock(DomainBucket bucket)
    {
        if (bucket.Mx == null)
        {
            return null;
        }

        var mx = bucket.Mx;
        return column =>
        {
            column.Section("MX").KeyValues(new (string, object?)[]
            {
                ("Record Present", mx.MxRecordExists ? "Yes" : "No"),
                ("IPv6 Supported", mx.Ipv6Supported ? "Yes" : "No"),
                ("Has Backup Servers", mx.HasBackupServers ? "Yes" : "No"),
                ("Null MX", mx.HasNullMx ? "Yes" : "No"),
                ("Priorities In Order", mx.PrioritiesInOrder ? "Yes" : "No"),
                ("TTL Uniform", mx.MxTtlUniform ? "Yes" : "No"),
                ("MX TTL Min (s)", mx.MinMxTtl?.ToString() ?? "-"),
                ("MX TTL Avg (s)", mx.AvgMxTtl.HasValue ? ((int)Math.Round(mx.AvgMxTtl.Value)).ToString() : "-"),
                ("MX TTL Max (s)", mx.MaxMxTtl?.ToString() ?? "-"),
                ("Points to CNAME", mx.PointsToCname ? "Yes" : "No"),
                ("Points to IP", mx.PointsToIpAddress ? "Yes" : "No"),
                ("Target Consistent Across NS", mx.TargetAddressConsistentAcrossNs ? "Yes" : "No")
            });

            var mxRecords = mx.MxRecords;
            if (mxRecords != null && mxRecords.Count > 0)
            {
                var rows = mxRecords.Select(r => new { Host = r }).ToList();
                column.TableFrom(rows, title: "MX Records", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }

            var mxRecommendations = mx.Recommendations;
            if (mxRecommendations != null && mxRecommendations.Count > 0)
            {
                column.Section("Recommendations").BulletedList(mxRecommendations.Select(r => r.Title ?? r.Code).ToArray());
            }

            var mxPositives = mx.Positives;
            if (mxPositives != null && mxPositives.Count > 0)
            {
                column.Section("Positives").BulletedList(mxPositives.Select(p => p.Title ?? p.Code).ToArray());
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildArcBlock(DomainBucket bucket)
    {
        if (bucket.Arc == null)
        {
            return null;
        }

        var arc = bucket.Arc;
        return column =>
        {
            column.Section("ARC").KeyValues(new (string, object?)[]
            {
                ("ARC Headers Present", arc.ArcHeadersFound ? "Yes" : "No"),
                ("Seal Count", arc.SealCount),
                ("AAR Count", arc.AarCount),
                ("Valid Chain", arc.ValidChain ? "Yes" : "No"),
                ("Chain State", arc.ChainState)
            });

            var arcHighlights = arc.Highlights;
            if (arcHighlights != null && arcHighlights.Count > 0)
            {
                column.Section("Highlights").BulletedList(arcHighlights);
            }

            var arcRecommendations = arc.Recommendations;
            if (arcRecommendations != null && arcRecommendations.Count > 0)
            {
                column.Section("Recommendations").BulletedList(arcRecommendations.Select(r => r.Title ?? r.Code).ToArray());
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildDnssecDaneBlock(DomainBucket bucket)
    {
        if (bucket.Dnssec == null && bucket.Dane == null)
        {
            return null;
        }

        return column =>
        {
            var rows = new List<(string, object?)>();
            if (bucket.Dnssec != null)
            {
                rows.Add(("DNSSEC", bucket.Dnssec.Status ?? "-"));
            }
            if (bucket.Dane != null)
            {
                rows.Add(("DANE", bucket.Dane.Status ?? "-"));
            }

            if (rows.Count > 0)
            {
                column.Section("DNSSEC/DANE").KeyValues(rows);
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildDnsblBlock(SheetComposer composer, DomainBucket bucket)
    {
        if (bucket.Dnsbl == null)
        {
            return null;
        }

        var dnsbl = bucket.Dnsbl;
        return column =>
        {
            column.Section("DNSBL").KeyValues(new (string, object?)[]
            {
                ("Providers Checked", dnsbl.ProvidersChecked),
                ("Hosts Checked", dnsbl.HostsChecked),
                ("Hosts Listed", dnsbl.HostsListed)
            });

            if (dnsbl.HostSummaries != null && dnsbl.HostSummaries.Count > 0)
            {
                var hostRows = dnsbl.HostSummaries.Select(h => new
                {
                    Host = h.Key,
                    Listed = h.Listed,
                    Total = h.Total,
                    Blacklists = string.Join(", ", h.Blacklists ?? new List<string>())
                }).ToList();
                var range = column.TableFrom(hostRows, title: "Host Summaries", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                {
                    v.NumericColumnFormats["Listed"] = "0";
                    v.NumericColumnFormats["Total"] = "0";
                    v.FreezeHeaderRow = true;
                });

                composer.ApplyColumnSizing(range, opt =>
                {
                    opt.MediumHeaders.Add("Host");
                    opt.NumericHeaders.UnionWith(new[] { "Listed", "Total" });
                    opt.LongHeaders.Add("Blacklists");
                    opt.WrapHeaders.Add("Blacklists");
                });
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildNsBlock(DomainBucket bucket)
    {
        if (bucket.Ns == null)
        {
            return null;
        }

        var ns = bucket.Ns;
        return column =>
        {
            column.Section("Name Servers").KeyValues(new (string, object?)[]
            {
                ("Records Present", ns.NsRecordExists ? "Yes" : "No"),
                ("Record Count", ns.NsRecords?.Count ?? 0),
                ("Has Duplicates", ns.HasDuplicates ? "Yes" : "No"),
                ("ASN Diversity", ns.AsnDistinctCount),
                ("Geo Diverse", ns.HasDiverseLocations ? "Yes" : "No"),
                ("Delegation Matches", ns.DelegationMatches ? "Yes" : "No")
            });

            var nsRecords = ns.NsRecords;
            if (nsRecords != null && nsRecords.Count > 0)
            {
                var rows = nsRecords.Select(host => new { Host = host }).ToList();
                column.TableFrom(rows, title: "Authoritative NS", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }

            var parentNsRecords = ns.ParentNsRecords;
            if (parentNsRecords != null && parentNsRecords.Count > 0)
            {
                var rows = parentNsRecords.Select(host => new { Parent = host }).ToList();
                column.TableFrom(rows, title: "Parent Delegation", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildSoaBlock(DomainBucket bucket)
    {
        if (bucket.Soa == null)
        {
            return null;
        }

        var soa = bucket.Soa;
        return column =>
        {
            column.Section("SOA").KeyValues(new (string, object?)[]
            {
                ("Primary", string.IsNullOrWhiteSpace(soa.PrimaryNameServer) ? "-" : soa.PrimaryNameServer),
                ("Responsible", string.IsNullOrWhiteSpace(soa.ResponsibleMailbox) ? "-" : soa.ResponsibleMailbox),
                ("Serial", soa.SerialNumber),
                ("Serial Format Valid", soa.SerialFormatValid ? "Yes" : "No"),
                ("Refresh", soa.Refresh),
                ("Retry", soa.Retry),
                ("Expire", soa.Expire),
                ("Minimum", soa.Minimum),
                ("Neg Cache TTL", soa.NegativeCacheTtl)
            });

            if (!string.IsNullOrWhiteSpace(soa.SerialFormatSuggestion))
            {
                column.Section("Serial Suggestion").Paragraph(soa.SerialFormatSuggestion);
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildDnsInventoryBlock(DomainBucket bucket)
    {
        if (bucket.DnsInventory == null)
        {
            return null;
        }

        var inv = bucket.DnsInventory;
        return column =>
        {
            column.Section("DNS Inventory").KeyValues(new (string, object?)[]
            {
                ("Status", inv.Status ?? "-"),
                ("Query OK", inv.QuerySucceeded ? "Yes" : "No"),
                ("Failure", string.IsNullOrWhiteSpace(inv.FailureReason) ? "-" : inv.FailureReason),
                ("Types Queried", inv.RecordTypesQueried),
                ("Types Failed", inv.RecordTypesFailed),
                ("Records", inv.TotalRecords),
                ("Provider", inv.Provider != DomainDetective.Providers.Dns.DnsProvider.Unknown ? inv.Provider.ToString() : "-"),
                ("Mail Provider", inv.MailProvider != DomainDetective.Providers.Email.MailProviderKind.Unknown ? inv.MailProvider.ToString() : "-"),
                ("CNAME Provider", inv.CnameTargetProvider != DomainDetective.Providers.Dns.DnsCnameTargetProvider.Unknown ? inv.CnameTargetProvider.ToString() : "-"),
                ("CNAME Flags", inv.CnameTargetFlags != DomainDetective.Providers.Dns.DnsCnameTargetFlags.None ? inv.CnameTargetFlags.ToString() : "-"),
                ("TXT Signals", inv.TxtSignals != DomainDetective.Providers.Dns.DnsTxtSignals.None ? inv.TxtSignals.ToString() : "-"),
                ("CAA Issuers", inv.CaaIssuers != DomainDetective.Providers.Dns.DnsCaaIssuers.None ? inv.CaaIssuers.ToString() : "-"),
                ("Authority Included", inv.IncludeAuthorities ? "Yes" : "No"),
                ("Additional Included", inv.IncludeAdditional ? "Yes" : "No")
            });

            if (inv.ProviderEvidence != null && inv.ProviderEvidence.Count > 0)
            {
                column.Section("Provider Evidence").BulletedList(inv.ProviderEvidence.Take(10).ToArray());
            }

            if (inv.MailProviderEvidence != null && inv.MailProviderEvidence.Count > 0)
            {
                column.Section("Mail Provider Evidence").BulletedList(inv.MailProviderEvidence.Take(10).ToArray());
            }

            if (inv.CnameTargetEvidence != null && inv.CnameTargetEvidence.Count > 0)
            {
                column.Section("CNAME Evidence").BulletedList(inv.CnameTargetEvidence.Take(10).ToArray());
            }

            if (inv.TxtSignalsEvidence != null && inv.TxtSignalsEvidence.Count > 0)
            {
                column.Section("TXT Signals Evidence").BulletedList(inv.TxtSignalsEvidence.Take(10).ToArray());
            }

            if (inv.CaaIssuersEvidence != null && inv.CaaIssuersEvidence.Count > 0)
            {
                column.Section("CAA Evidence").BulletedList(inv.CaaIssuersEvidence.Take(10).ToArray());
            }

            var queries = inv.Queries;
            if (queries != null && queries.Count > 0)
            {
                var qrows = queries
                    .OrderBy(q => q.RecordType)
                    .Select(q => new
                    {
                        RecordType = q.RecordType,
                        Status = q.Status.ToString(),
                        Response = q.ResponseStatus.ToString(),
                        Records = q.Records.Count,
                        Failure = string.IsNullOrWhiteSpace(q.FailureReason) ? "-" : q.FailureReason
                    })
                    .ToList();

                column.TableFrom(qrows, title: "Query Results", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                {
                    v.NumericColumnFormats["Records"] = "0";
                    v.FreezeHeaderRow = true;
                });

                const int maxRows = 200;
                var rows = new List<object>(Math.Min(inv.TotalRecords, maxRows));
                foreach (var q in queries)
                {
                    foreach (var r in q.Records)
                    {
                        if (rows.Count >= maxRows) break;
                        rows.Add(new
                        {
                            QueryType = q.RecordType,
                            Section = r.Section.ToString(),
                            RecordType = r.Type,
                            r.Name,
                            TTL = r.Ttl,
                            r.Data
                        });
                    }
                    if (rows.Count >= maxRows) break;
                }

                if (rows.Count > 0)
                {
                    column.TableFrom(rows, title: "Records (Sample)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                    {
                        v.NumericColumnFormats["TTL"] = "0";
                        v.FreezeHeaderRow = true;
                    });
                }
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildDnsTraceBlock(DomainBucket bucket)
    {
        if (bucket.DnsTrace == null)
        {
            return null;
        }

        var tr = bucket.DnsTrace;
        var projection = DomainDetective.Reports.SectionProjectors.BuildDnsTrace(tr);

        return column =>
        {
            var recordTypes = "-";
            try
            {
                if (tr.Raw?.RecordTypesToTrace != null && tr.Raw.RecordTypesToTrace.Length > 0)
                {
                    recordTypes = string.Join(", ", tr.Raw.RecordTypesToTrace.Select(x => x.ToString()));
                }
            }
            catch { }

            column.Section("DNS Trace").KeyValues(new (string, object?)[]
            {
                ("Status", tr.Status ?? "-"),
                ("Trace OK", tr.TraceSucceeded ? "Yes" : "No"),
                ("Failure", string.IsNullOrWhiteSpace(tr.FailureReason) ? "-" : tr.FailureReason),
                ("Record Types", recordTypes),
                ("IPv6 Roots", tr.Raw?.IncludeIpv6RootServers == true ? "Yes" : "No"),
                ("Max Depth", tr.Raw?.MaxDepth.ToString() ?? "-"),
                ("Max Steps", tr.Raw?.MaxTotalSteps.ToString() ?? "-"),
                ("Queries", tr.TraceQueries),
                ("Queries Failed", tr.TraceQueriesFailed),
                ("Steps", tr.TotalSteps)
            });

            var queries = tr.Queries;
            if (queries != null && queries.Count > 0)
            {
                var qrows = queries
                    .OrderBy(q => q.RecordType)
                    .Select(q => new
                    {
                        RecordType = q.RecordType.ToString(),
                        Status = q.Status.ToString(),
                        FinalStatus = q.FinalResponseStatus.ToString(),
                        FinalName = string.IsNullOrWhiteSpace(q.FinalName) ? "-" : q.FinalName,
                        Steps = q.Steps.Count,
                        Failure = string.IsNullOrWhiteSpace(q.FailureReason) ? "-" : q.FailureReason
                    })
                    .ToList();

                column.TableFrom(qrows, title: "Trace Results", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                {
                    v.NumericColumnFormats["Steps"] = "0";
                    v.FreezeHeaderRow = true;
                });
            }

            if (projection != null && projection.Rows.Count > 0)
            {
                const int maxRows = 200;
                var rows = projection.Rows
                    .Take(maxRows)
                    .Select(r => new
                    {
                        Trace = r.TraceType.ToString(),
                        Kind = r.Kind.ToString(),
                        r.Depth,
                        r.Server,
                        r.Name,
                        Type = r.RecordType.ToString(),
                        Status = r.ResponseStatus.ToString(),
                        RTT = r.RttMs,
                        Next = r.NextServers
                    })
                    .ToList();

                column.TableFrom(rows, title: "Trace Steps (Sample)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                {
                    v.NumericColumnFormats["Depth"] = "0";
                    v.NumericColumnFormats["RTT"] = "0";
                    v.FreezeHeaderRow = true;
                });
            }

            if (projection != null && projection.Findings.Count > 0)
            {
                var frows = projection.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList();
                column.TableFrom(frows, title: "Findings", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildCtTimelineBlock(DomainBucket bucket)
    {
        if (bucket.CtTimeline == null)
        {
            return null;
        }

        var ct = bucket.CtTimeline;
        var projection = DomainDetective.Reports.SectionProjectors.BuildCtTimeline(ct);

        return column =>
        {
            column.Section("CT Timeline").KeyValues(new (string, object?)[]
            {
                ("Status", ct.Status ?? "-"),
                ("Query OK", ct.QuerySucceeded ? "Yes" : "No"),
                ("Failure", string.IsNullOrWhiteSpace(ct.FailureReason) ? "-" : ct.FailureReason),
                ("Observations", ct.CertificateObservationCount),
                ("Unique Certificates", ct.UniqueCertificateCount),
                ("Active", ct.ActiveCertificateCount),
                ("Expired", ct.ExpiredCertificateCount),
                ("Not Yet Valid", ct.NotYetValidCertificateCount),
                ("Wildcards", ct.WildcardCertificateCount),
                ("Issued (7d)", ct.IssuedLast7Days),
                ("Issued (30d)", ct.IssuedLast30Days),
                ("First Seen (UTC)", ct.FirstSeenUtc?.ToString("yyyy-MM-dd") ?? "-"),
                ("Last Seen (UTC)", ct.LastSeenUtc?.ToString("yyyy-MM-dd") ?? "-"),
                ("Issuer Diversity", ct.IssuerCounts?.Count ?? 0),
                ("Capped", ct.ResultsCapped ? "Yes" : "No")
            });

            if (projection != null && projection.Timeline.Count > 0)
            {
                var rows = projection.Timeline
                    .Select(x => new { x.Month, Certificates = x.Certificates, Issuers = x.Issuers })
                    .ToList();

                column.TableFrom(rows, title: "Timeline (Monthly)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                {
                    v.NumericColumnFormats["Certificates"] = "0";
                    v.NumericColumnFormats["Issuers"] = "0";
                    v.FreezeHeaderRow = true;
                });
            }

            if (projection != null && projection.RecentCertificates.Count > 0)
            {
                const int maxRows = 200;
                var rows = projection.RecentCertificates
                    .Take(maxRows)
                    .Select(x => new
                    {
                        x.EntryUtc,
                        x.NotAfterUtc,
                        Validity = x.Validity.ToString(),
                        Wildcard = x.Wildcard ? "Yes" : "No",
                        x.Issuer,
                        x.CommonName
                    })
                    .ToList();

                column.TableFrom(rows, title: "Recent Certificates (Sample)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                {
                    v.FreezeHeaderRow = true;
                });
            }

            if (projection != null && projection.Findings.Count > 0)
            {
                var frows = projection.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList();
                column.TableFrom(frows, title: "Findings", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildHttpBlock(DomainBucket bucket)
    {
        if (bucket.Http == null)
        {
            return null;
        }

        var http = bucket.Http;
        var projection = DomainDetective.Reports.SectionProjectors.BuildHttp(http);

        return column =>
        {
            column.Section("HTTP").KeyValues(new (string, object?)[]
            {
                ("Status", http.Status ?? "-"),
                ("Reachable", http.IsReachable ? "Yes" : "No"),
                ("Status Code", http.StatusCode?.ToString() ?? "-"),
                ("Grade", http.Grade != GradeLevel.Unknown ? http.Grade.ToString() : "-"),
                ("Method", http.RequestMethodUsed.ToString()),
                ("Effective URL", projection?.EffectiveUrl ?? (http.Url ?? http.Subject ?? "-")),
                ("Proxy", string.IsNullOrWhiteSpace(http.ProxyUsed) ? "-" : http.ProxyUsed),
                ("TLS Validation", http.TlsValidationDisabled ? "Disabled" : "Enabled"),
                ("HSTS", http.HstsPresent ? "Yes" : "No"),
                ("HTTP/2", http.Http2Supported ? "Yes" : "No"),
                ("HTTP/3", http.Http3Supported ? "Yes" : "No"),
                ("CSP frame-ancestors", http.CspFrameAncestorsPresent ? "Yes" : "No"),
                ("Missing Security Headers", http.MissingSecurityHeaders?.Count ?? 0),
                ("Info Disclosure Headers", http.InformationDisclosureHeaders?.Count ?? 0),
                ("Caching Headers", http.CachingHeaders?.Count ?? 0),
                ("Deprecated Present", http.DeprecatedHeadersPresent?.Count ?? 0),
                ("Deprecated Missing", http.MissingDeprecatedHeaders?.Count ?? 0),
                ("Mixed Content", http.MixedContentDetected ? "Yes" : "No"),
                ("Response Time", http.ResponseTime.ToString()),
                ("Body Length (bytes)", http.BodyLength?.ToString() ?? "-"),
                ("Body SHA-256", string.IsNullOrWhiteSpace(http.BodySha256) ? "-" : http.BodySha256)
            });

            try
            {
                var visited = http.Raw?.VisitedUrls;
                if (visited != null && visited.Count > 0)
                {
                    var rows = visited.Select((u, i) => new { Step = i + 1, Url = u }).ToList();
                    column.TableFrom(rows, title: "Redirect Chain", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
                }
            }
            catch
            {
            }

            if (projection != null && projection.PresentSecurityHeaders.Count > 0)
            {
                var rows = projection.PresentSecurityHeaders.Select(x => new { x.Name, x.Value }).ToList();
                column.TableFrom(rows, title: "Present Security Headers", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }

            if (projection != null && projection.MissingSecurityHeaders.Count > 0)
            {
                var rows = projection.MissingSecurityHeaders.Select(x => new { Header = x }).ToList();
                column.TableFrom(rows, title: "Missing Security Headers", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }

            if (projection != null && projection.InformationDisclosureHeaders.Count > 0)
            {
                var rows = projection.InformationDisclosureHeaders.Select(x => new { x.Name, x.Value }).ToList();
                column.TableFrom(rows, title: "Information Disclosure Headers", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }

            if (projection != null && projection.CachingHeaders.Count > 0)
            {
                var rows = projection.CachingHeaders.Select(x => new { x.Name, x.Value }).ToList();
                column.TableFrom(rows, title: "Caching Headers", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }

            if (projection != null && (projection.DeprecatedPresent.Count > 0 || projection.DeprecatedMissing.Count > 0))
            {
                var rows = new[]
                {
                    new { Group = "Deprecated Present", Headers = projection.DeprecatedPresent.Count > 0 ? string.Join(", ", projection.DeprecatedPresent) : "-" },
                    new { Group = "Deprecated Missing", Headers = projection.DeprecatedMissing.Count > 0 ? string.Join(", ", projection.DeprecatedMissing) : "-" }
                }.ToList();
                column.TableFrom(rows, title: "Deprecated Header Signals", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }

            if (projection != null && projection.Findings.Count > 0)
            {
                var frows = projection.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList();
                column.TableFrom(frows, title: "Findings", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildIpEnrichmentBlock(DomainBucket bucket)
    {
        if (bucket.IpEnrichment == null)
        {
            return null;
        }

        var ip = bucket.IpEnrichment;
        var projection = DomainDetective.Reports.SectionProjectors.BuildIpEnrichment(ip);

        return column =>
        {
            column.Section("IP Enrichment").KeyValues(new (string, object?)[]
            {
                ("Status", ip.Status ?? "-"),
                ("Query OK", ip.QuerySucceeded ? "Yes" : "No"),
                ("Failure", string.IsNullOrWhiteSpace(ip.FailureReason) ? "-" : ip.FailureReason),
                ("Unique IPs", ip.UniqueIpCount),
                ("Rows", ip.RowCount),
                ("ASNs", ip.DistinctAsnCount),
                ("Countries", ip.DistinctCountryCount),
                ("Capped", ip.ResultsCapped ? "Yes" : "No")
            });

            try
            {
                if (ip.AsnCounts != null && ip.AsnCounts.Count > 0)
                {
                    var rows = ip.AsnCounts
                        .OrderByDescending(kv => kv.Value)
                        .ThenBy(kv => kv.Key)
                        .Take(50)
                        .Select(kv => new { Asn = "AS" + kv.Key, Count = kv.Value })
                        .ToList();
                    column.TableFrom(rows, title: "ASN Counts (Top)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => { v.FreezeHeaderRow = true; v.NumericColumnFormats["Count"] = "0"; });
                }
            }
            catch
            {
            }

            try
            {
                if (ip.CountryCounts != null && ip.CountryCounts.Count > 0)
                {
                    var rows = ip.CountryCounts
                        .OrderByDescending(kv => kv.Value)
                        .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                        .Take(50)
                        .Select(kv => new { Country = kv.Key, Count = kv.Value })
                        .ToList();
                    column.TableFrom(rows, title: "Country Counts (Top)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => { v.FreezeHeaderRow = true; v.NumericColumnFormats["Count"] = "0"; });
                }
            }
            catch
            {
            }

            if (projection != null && projection.Rows.Count > 0)
            {
                const int maxRows = 500;
                var rows = projection.Rows
                    .Take(maxRows)
                    .Select(x => new
                    {
                        x.IpAddress,
                        Family = x.Family.ToString(),
                        SourceKind = x.SourceKind.ToString(),
                        x.SourceHost,
                        x.Ptr,
                        Asn = x.Asn.HasValue ? "AS" + x.Asn.Value : string.Empty,
                        x.AsName,
                        x.Cidr,
                        x.Country,
                        x.Region
                    })
                    .ToList();

                column.TableFrom(rows, title: "Enriched IP Rows (Sample)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }

            if (projection != null && projection.Findings.Count > 0)
            {
                var frows = projection.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList();
                column.TableFrom(frows, title: "Findings", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildCaaBlock(DomainBucket bucket)
    {
        if (bucket.Caa == null)
        {
            return null;
        }

        var caa = bucket.Caa;
        return column =>
        {
            column.Section("CAA").KeyValues(new (string, object?)[]
            {
                ("Valid Records", caa.ValidRecords),
                ("Invalid Records", caa.InvalidRecords),
                ("Conflicting", caa.Conflicting ? "Yes" : "No"),
                ("Duplicate Issuers", caa.HasDuplicateIssuers ? "Yes" : "No")
            });

            void RenderList(string title, IReadOnlyList<string>? items)
            {
                if (items == null || items.Count == 0)
                {
                    return;
                }

                column.Section(title);
                column.BulletedList(items);
            }

            RenderList("Issue", caa.CanIssueCertificatesForDomain);
            RenderList("Wildcard Issue", caa.CanIssueWildcardCertificatesForDomain);
            RenderList("Mail Issue", caa.CanIssueMail);
            RenderList("Report Email", caa.ReportViolationEmail);
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildRpkiBlock(DomainBucket bucket)
    {
        if (bucket.Rpki == null)
        {
            return null;
        }

        var rpki = bucket.Rpki;
        return column =>
        {
            column.Section("RPKI").KeyValues(new (string, object?)[]
            {
                ("Total Checked", rpki.TotalChecked),
                ("Valid", rpki.ValidCount),
                ("All Valid", rpki.AllValid ? "Yes" : "No")
            });

            var rpkiResults = rpki.Results;
            if (rpkiResults != null && rpkiResults.Count > 0)
            {
                var rows = rpkiResults.Select(r => new { r.IpAddress, r.Prefix, r.Asn, Valid = r.Valid ? "Yes" : "No" }).ToList();
                column.TableFrom(rows, title: "RPKI Results", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                {
                    v.NumericColumnFormats["Asn"] = "0";
                    v.FreezeHeaderRow = true;
                });
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildZoneTransferBlock(DomainBucket bucket)
    {
        if (bucket.ZoneTransfer == null)
        {
            return null;
        }

        var zone = bucket.ZoneTransfer;
        return column =>
        {
            column.Section("Zone Transfer").KeyValues(new (string, object?)[]
            {
                ("Open", $"{zone.OpenCount}/{zone.TotalChecked}")
            });

            var zoneServerResults = zone.ServerResults;
            if (zoneServerResults != null && zoneServerResults.Count > 0)
            {
                var rows = zoneServerResults.Select(kv => new { Server = kv.Key, Open = kv.Value ? "Yes" : "No" }).ToList();
                column.TableFrom(rows, title: "Servers", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildWildcardBlock(DomainBucket bucket)
    {
        if (bucket.Wildcard == null)
        {
            return null;
        }

        var wc = bucket.Wildcard;
        return column =>
        {
            column.Section("Wildcard DNS").KeyValues(new (string, object?)[] { ("Catch-All", wc.CatchAll ? "Yes" : "No") });
            var testedNames = wc.TestedNames;
            if (testedNames != null && testedNames.Count > 0)
            {
                column.Section("Tested Names").BulletedList(testedNames.ToArray());
            }
            var resolvedNames = wc.ResolvedNames;
            if (resolvedNames != null && resolvedNames.Count > 0)
            {
                column.Section("Resolved Names").BulletedList(resolvedNames.ToArray());
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildSubdomainsBlock(DomainBucket bucket)
    {
        if (bucket.Subdomains == null)
        {
            return null;
        }

        var sub = bucket.Subdomains;
        return column =>
        {
            string range = "-";
            if (sub.FirstSeenUtc.HasValue || sub.LastSeenUtc.HasValue)
            {
                var a = sub.FirstSeenUtc?.ToString("yyyy-MM-dd") ?? "-";
                var b = sub.LastSeenUtc?.ToString("yyyy-MM-dd") ?? "-";
                range = a + " .. " + b;
            }

            var dnsVerification = sub.Raw?.VerifyStillResolves == true
                ? (sub.ResolutionReduced ? "Capped" : "Yes")
                : "No";

            column.Section("Subdomains (Discovery)").KeyValues(new (string, object?)[]
            {
                ("Status", sub.Status ?? "-"),
                ("Query OK", sub.QuerySucceeded ? "Yes" : "No"),
                ("Failure", string.IsNullOrWhiteSpace(sub.FailureReason) ? "-" : sub.FailureReason),
                ("Subdomains", sub.SubdomainCount),
                ("CT Rows", sub.CertificateObservationCount),
                ("CT Processing", sub.ResultsCapped ? "Capped" : "OK"),
                ("Issuer Diversity", sub.DistinctIssuerCount),
                ("Seen (UTC)", range),
                ("DNS Verification", dnsVerification)
            });

            var issuerCounts = sub.IssuerCounts;
            if (issuerCounts != null && issuerCounts.Count > 0)
            {
                const int maxIssuers = 25;
                var issuerRows = issuerCounts
                    .OrderByDescending(kv => kv.Value)
                    .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                    .Take(maxIssuers)
                    .Select(kv => new { Issuer = kv.Key, Count = kv.Value })
                    .ToList();

                column.TableFrom(issuerRows, title: "Issuers (Top)", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v =>
                {
                    v.NumericColumnFormats["Count"] = "0";
                    v.FreezeHeaderRow = true;
                });
            }

            var subdomains = sub.Subdomains;
            if (subdomains != null && subdomains.Count > 0)
            {
                const int maxRows = 200;
                var rows = subdomains
                    .Take(maxRows)
                    .Select(s => new
                    {
                        s.Name,
                        FirstSeenUtc = s.FirstSeenUtc?.ToString("yyyy-MM-dd") ?? "-",
                        LastSeenUtc = s.LastSeenUtc?.ToString("yyyy-MM-dd") ?? "-",
                        Resolution = s.ResolutionStatus.ToString()
                    })
                    .ToList();

                column.TableFrom(rows, title: "Subdomains", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
            }
        };
    }
}
