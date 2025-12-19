using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HtmlCompositionReport partial: All References section (Word parity).
/// </summary>
public static partial class HtmlCompositionReport
{
    private static void RenderAllReferencesSection(HtmlForgeX.TablerPage page, IReadOnlyList<object> items)
    {
        var comp = DomainDetective.Reports.CompositionBuilder.GroupBySubject(items);
        var refs = DomainDetective.Reports.ReferencesCollector.CollectAll(comp.Values);
        if (refs.Count == 0) return;

        page.Divider("All References");
        page.Row(r => r.Column(TablerColumnNumber.Twelve, c => {
            c.Card(card => {
                card.Header(h => h.Title("References cited across all sections"));
                card.Body(b => {
                    var rows = refs.Select(u => {
                        var f = DomainDetective.Reports.LinkFormatter.Format(u);
                        return new { Title = f.Title, Url = f.Url };
                    }).ToList();
                    var t = (TablerTable)b.Table(rows, TableType.Tabler);
                    t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                });
            });
        }));
    }
}

