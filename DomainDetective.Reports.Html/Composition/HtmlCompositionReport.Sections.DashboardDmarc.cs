using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;

namespace DomainDetective.Reports.Html;

public static partial class HtmlCompositionReport
{
    private static void RenderDashboardDmarc(HtmlForgeX.TablerPage page, List<KeyValuePair<string, DomainBucket>> ordered)
    {
        var rows = new List<object>();
        foreach (var kv in ordered)
        {
            if (kv.Value.Dmarc == null) continue;
            var sec = DomainDetective.Reports.SectionProjectors.BuildDmarc(kv.Value.Dmarc);
            if (sec == null) continue;
            rows.Add(new {
                Domain = kv.Key,
                Status = sec.Status,
                Policy = sec.Policy,
                adkim = sec.DkimAlignment ?? "-",
                aspf = sec.SpfAlignment ?? "-",
                RUA = sec.RuaCount,
                RUF = sec.RufCount
            });
        }
        if (rows.Count == 0) return;
        page.Row(r => r.Column(TablerColumnNumber.Twelve, c => {
            c.Card(card => {
                card.Header(h => h.Title("DMARC Overview (per domain)"));
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

