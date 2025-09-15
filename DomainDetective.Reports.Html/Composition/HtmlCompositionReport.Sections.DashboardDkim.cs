using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;

namespace DomainDetective.Reports.Html;

public static partial class HtmlCompositionReport
{
    private static void RenderDashboardDkim(HtmlForgeX.TablerPage page, List<KeyValuePair<string, DomainBucket>> ordered)
    {
        var rows = new List<object>();
        foreach (var kv in ordered)
        {
            if (kv.Value.Dkim == null || kv.Value.Dkim.Count == 0) continue;
            var sec = DomainDetective.Reports.SectionProjectors.BuildDkim(kv.Value.Dkim);
            if (sec == null || sec.Rows.Count == 0) continue;
            foreach (var r in sec.Rows)
            {
                rows.Add(new { Domain = kv.Key, r.Selector, r.Status, Bits = r.KeyBits, Alg = r.Hash, Weak = r.Weak ? "Yes" : "No", r.Flags });
            }
        }
        if (rows.Count == 0) return;
        page.Row(r => r.Column(TablerColumnNumber.Twelve, c => {
            c.Card(card => {
                card.Header(h => h.Title("DKIM Selectors (all domains)"));
                card.Body(b => {
                    var t = (DataTablesTable)b.Table(rows, TableType.DataTables);
                    t.EnablePaging(10, new[] { 10, 25, 50 }).EnableSearching().EnableOrdering();
                    t.HighlightWhen(g => g.Or(x => x.StringContains("Status", "error", false)), a => a.Column("Status").Danger());
                    t.HighlightWhen(g => g.Or(x => x.StringContains("Status", "warn", false)), a => a.Column("Status").Warning());
                });
            });
        }));
    }
}

