using System;
using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;

namespace DomainDetective.Reports.Office;

public static partial class ExcelCompositionReport
{
    private static void BuildSummarySheet(ExcelDocument doc, List<KeyValuePair<string, DomainBucket>> domains)
    {
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
    }
}

