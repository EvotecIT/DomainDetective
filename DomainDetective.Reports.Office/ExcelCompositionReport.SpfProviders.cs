using System;
using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;

namespace DomainDetective.Reports.Office;

public static partial class ExcelCompositionReport
{
    private static void BuildSpfProvidersSheet(ExcelDocument doc, List<KeyValuePair<string, DomainBucket>> domains)
    {
        try
        {
            var sp = new SheetComposer(doc, "SPF Providers");
            sp.Title("SPF Providers");
            var rows = new List<object>();
            foreach (var kv in domains)
            {
                var b = kv.Value;
                if (b.Spf?.Mechanisms == null) continue;
                foreach (var m in b.Spf.Mechanisms)
                {
                    if (string.IsNullOrWhiteSpace(m.Provider)) continue;
                    rows.Add(new { Domain = kv.Key, Provider = m.Provider, Type = m.Type, Value = m.Value });
                }
            }
            if (rows.Count > 0) sp.TableFrom(rows, title: null, configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => v.FreezeHeaderRow = true);
            sp.Finish(autoFitColumns: true);
        }
        catch { }
    }
}

