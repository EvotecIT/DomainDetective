using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HtmlCompositionReport partial: multi-domain accordion with search.
/// </summary>
public static partial class HtmlCompositionReport
{
    private static void RenderDomainsAccordion(Element page, List<KeyValuePair<string, DomainBucket>> ordered, SectionOrderMode sectionOrderMode, string[] normalizedCustom, Dictionary<string, List<string>> inputSectionOrder)
    {
        page.Divider("Domains");
        page.Row(row => {
            row.Column(TablerColumnNumber.Twelve, col => {
                col.Card(card => {
                    card.Header(h => h.Title("Domains").Subtitle("Search and expand to view each domain").Icon(TablerIconType.Stack2));
                    card.Body(body => {
                        body.Accordion(acc => {
                            ConfigureAccordion(acc, persistKey: "domains");
                            foreach (var kv in ordered)
                            {
                                var domain = kv.Key;
                                var b = kv.Value;
                                var warnCount = (b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + b.Dkim.Sum(x => x.WarningCount) + (b.Arc?.WarningCount ?? 0) + (b.Bimi?.WarningCount ?? 0);
                                var errCount = (b.Mx?.ErrorCount ?? 0) + (b.Spf?.ErrorCount ?? 0) + (b.Dmarc?.ErrorCount ?? 0) + (b.Mtasts?.ErrorCount ?? 0) + (b.TlsRpt?.ErrorCount ?? 0) + b.Dkim.Sum(x => x.ErrorCount) + (b.Arc?.ErrorCount ?? 0) + (b.Bimi?.ErrorCount ?? 0);
                                var dkimSummary = DisplayFormatting.ComposeDkimSummary(b.Dkim, includeSelectorCount: true);
                                var dnssecSummary = DisplayFormatting.ComposeDnssecSummary(b.Dnssec);
                                var rpkiSummary = DisplayFormatting.ComposeRpkiSummary(b.Rpki);

                                acc.AddItem(domain, item => {
                                    item.Icon(TablerIconType.World);
                                    item.HeaderRight(rr => {
                                        rr.Badge(errCount > 0 ? $"{errCount} Error" + (errCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                        rr.Badge(warnCount > 0 ? $"{warnCount} Warning" + (warnCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                    });
                                    item.HeaderTrailing(tt => {
                                        if (b.Mx != null) tt.Badge($"MX {b.Mx.Status ?? "-"}", ColorForStatus(b.Mx.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                        if (b.Spf != null) tt.Badge($"SPF {b.Spf.Status ?? "-"}", ColorForStatus(b.Spf.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                        if (b.Dkim.Count > 0) tt.Badge($"DKIM {dkimSummary}", ColorForStatus(dkimSummary), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                        if (b.Dmarc != null) tt.Badge($"DMARC {b.Dmarc.Status ?? "-"}", ColorForStatus(b.Dmarc.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                        if (b.Mtasts != null) tt.Badge($"MTA-STS {b.Mtasts.Status ?? "-"}", ColorForStatus(b.Mtasts.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                        if (b.TlsRpt != null) tt.Badge($"TLS-RPT {b.TlsRpt.Status ?? "-"}", ColorForStatus(b.TlsRpt.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                        if (b.Dnssec != null) tt.Badge($"DNSSEC {dnssecSummary}", ColorForStatus(dnssecSummary), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                        if (b.Rpki != null) tt.Badge($"RPKI {rpkiSummary}", ColorForStatus(rpkiSummary), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                    });
                                    item.Content(content => {
                                        RenderSingleDomain(content, domain, b, sectionOrderMode, normalizedCustom, inputSectionOrder, includeDivider: false);
                                    });
                                });
                            }
                        });
                    });
                });
            });
        });
    }
}
