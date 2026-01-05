using System;
using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;
using DocumentFormat.OpenXml.Spreadsheet;
using SixLabors.ImageSharp;

namespace DomainDetective.Reports.Office;

public static partial class ExcelCompositionReport
{
    private static void BuildOverviewSheet(ExcelDocument doc, IReadOnlyList<object> items, DomainDetective.Reports.DomainOrder order, List<KeyValuePair<string, DomainBucket>> domains)
    {
        var overview = new SheetComposer(doc, "Overview");
        overview.Title("Security Overview", $"Generated {DateTime.Now:yyyy-MM-dd HH:mm}");

        var execRows = ExecutiveSummaryBuilder.Build(items, order);
        int totalWarn = execRows.Sum(r => r.Warnings);
        int totalErr = execRows.Sum(r => r.Errors);
        var sumRows = new List<object>(execRows.Count + 1);
        foreach (var r in execRows)
        {
            sumRows.Add(new {
                Domain = r.Domain,
                MX = r.Mx,
                SPF = r.Spf,
                DKIM = r.Dkim,
                DMARC = r.Dmarc,
                MTASTS = r.Mtasts,
                TLSRPT = r.TlsRpt,
                DNSSEC = r.Dnssec,
                RPKI = r.Rpki,
                Warnings = r.Warnings,
                Errors = r.Errors
            });
        }
        sumRows.Add(new { Domain = "TOTAL", MX = string.Empty, SPF = string.Empty, DKIM = string.Empty, DMARC = string.Empty, MTASTS = string.Empty, TLSRPT = string.Empty, DNSSEC = string.Empty, RPKI = string.Empty, Warnings = totalWarn, Errors = totalErr });

        overview.KpiRow(new (string, object?)[] {
            ("Domains", domains.Count),
            ("Warnings", totalWarn),
            ("Errors", totalErr)
        }, perRow: 3);

        try { var overviewLine = OverviewWording.ComposeFromItems(items); overview.Section("Overview"); overview.PropertiesGrid(new (string, object?)[] { ("Summary", overviewLine) }, columns: 1); } catch { }

        var range = overview.TableFrom(sumRows, title: "Domains", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => {
            v.NumericColumnFormats["Warnings"] = "0"; v.NumericColumnFormats["Errors"] = "0";
            v.DataBars["Warnings"] = SixLabors.ImageSharp.Color.ParseHex("#FFA500");
            v.DataBars["Errors"] = SixLabors.ImageSharp.Color.ParseHex("#DC3545");
            var ok = "#D1E7DD"; var warn = "#FFF4CE"; var err = "#F8D7DA"; var none = "#E9ECEF";
            foreach (var col in new[] { "MX", "SPF", "DKIM", "DMARC", "MTASTS", "TLSRPT", "DNSSEC", "RPKI" })
            {
                v.TextBackgrounds[col] = new System.Collections.Generic.Dictionary<string, string>(System.StringComparer.OrdinalIgnoreCase) {
                    { "OK", ok }, { "Pass", ok }, { "Valid", ok }, { "Warning", warn }, { "Warn", warn }, { "Error", err }, { "Fail", err }, { "-", none }, { "None", none }, { "Missing", none }
                };
                v.BoldByText[col] = new System.Collections.Generic.HashSet<string>(System.StringComparer.OrdinalIgnoreCase) { "Error", "Fail" };
            }
            v.FreezeHeaderRow = true;
        });

        try {
            var coords = ParseRange(range ?? string.Empty);
            if (coords.startCol != 0)
            {
                int errorsCol = coords.startCol + 11 - 1;
                string colLetter = IndexToCol(errorsCol);
                string errRange = $"{colLetter}{coords.startRow + 1}:{colLetter}{coords.endRow}";
                overview.ConditionalIconSet(errRange, IconSetValues.ThreeTrafficLights1);
            }
        } catch { }

        try
        {
            var providerRows = new List<object>();
            foreach (var kv in domains)
            {
                var chain = DomainDetective.Reports.ProviderChainBuilder.Build(kv.Value.Mx, kv.Value.Spf);
                var primary = string.IsNullOrWhiteSpace(chain.Primary) ? "-" : chain.Primary;
                var gateways = chain.Gateways.Count > 0 ? string.Join(", ", chain.Gateways) : "-";
                var outbound = chain.Outbound.Count > 0 ? string.Join(", ", chain.Outbound) : "-";
                providerRows.Add(new { Domain = kv.Key, Primary = primary, Gateways = gateways, Outbound = outbound });
            }
            if (providerRows.Count > 0)
            {
                var providerRange = overview.TableFrom(providerRows, title: "Mail Providers", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => { v.FreezeHeaderRow = true; });
                overview.ApplyColumnSizing(providerRange, opt =>
                {
                    opt.MediumHeaders.Add("Domain");
                    opt.LongHeaders.UnionWith(new[] { "Gateways", "Outbound" });
                    opt.WrapHeaders.UnionWith(new[] { "Gateways", "Outbound" });
                });
            }
        }
        catch { }

        overview.Finish(autoFitColumns: true);
    }
}

