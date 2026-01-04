using System;
using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;

namespace DomainDetective.Reports.Office;

public static partial class ExcelCompositionReport
{
    private static void BuildRecommendationsSheet(ExcelDocument doc, List<KeyValuePair<string, DomainBucket>> domains)
    {
        try
        {
            var recSheet = new SheetComposer(doc, "Recommendations");
            recSheet.Title("Consolidated Recommendations");
            var rows = new List<object>();
            foreach (var kv in domains)
            {
                var b = kv.Value;
                var recs = new List<DomainDetective.RecommendationAdvice>();
                void Pull(IEnumerable<DomainDetective.RecommendationAdvice>? r) { if (r == null) return; recs.AddRange(r); }
                Pull(b.Mx?.Recommendations); Pull(b.Spf?.Recommendations); Pull(b.Dmarc?.Recommendations); Pull(b.Dnsbl?.Recommendations);
                foreach (var d in b.Dkim) Pull(d.Recommendations);
                foreach (var g in recs.GroupBy(x => x.Code ?? x.Title))
                {
                    var first = g.First();
                    rows.Add(new { Domain = kv.Key, Code = first.Code, Title = first.Title, How = first.How });
                }
            }
            if (rows.Count > 0)
            {
                recSheet.TableFrom(rows, title: null, configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => v.FreezeHeaderRow = true);
            }
            recSheet.Finish(autoFitColumns: true);
        }
        catch { }
    }
}

