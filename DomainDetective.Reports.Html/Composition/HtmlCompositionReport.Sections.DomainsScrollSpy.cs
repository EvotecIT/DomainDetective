using System.Collections.Generic;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HtmlCompositionReport partial: multi-domain scrollspy navigation view.
/// </summary>
public static partial class HtmlCompositionReport
{
    private static void RenderDomainsScrollSpy(HtmlForgeX.TablerPage page, List<KeyValuePair<string, DomainBucket>> ordered, SectionOrderMode sectionOrderMode, string[] normalizedCustom, Dictionary<string, List<string>> inputSectionOrder)
    {
        page.Divider("Domains");
        page.ScrollSpy(spy => {
            spy.Settings(s => s
                .LeftWidth(TablerColumnNumber.Three)
                .Mode(TablerScrollSpy.ScrollSpyMode.PageScroll)
                .UsePills(true)
                .StickyNav(true)
                .WrapContentInCard(false, large: false)
                .IntraSectionGap(TablerSpacing.Small)
                .SectionGap(TablerSpacing.Medium)
            );

            foreach (var kv in ordered)
            {
                var domain = kv.Key;
                var bucket = kv.Value;
                spy.AddSection(domain, c => {
                    RenderSingleDomain(c, domain, bucket, sectionOrderMode, normalizedCustom, inputSectionOrder, includeDivider: false);
                });
            }
        });
    }
}
