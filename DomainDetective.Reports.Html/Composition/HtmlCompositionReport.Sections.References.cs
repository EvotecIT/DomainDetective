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
                    b.Row(rr => {
                        rr.Gap(2);
                        foreach (var u in refs)
                        {
                            var f = DomainDetective.Reports.LinkFormatter.Format(u);
                            rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(f.Title, TablerBadgeColor.Blue, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true, href: f.Url));
                        }
                    });
                });
            });
        }));
    }
}
