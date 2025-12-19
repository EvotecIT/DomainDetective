using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HtmlCompositionReport partial: multi-domain tabbed section with per-domain cards + ordered accordions.
/// </summary>
public static partial class HtmlCompositionReport
{
    private static void RenderDomainsTabbed(HtmlForgeX.TablerPage page, List<KeyValuePair<string, DomainBucket>> ordered, SectionOrderMode sectionOrderMode, string[] normalizedCustom, Dictionary<string, List<string>> inputSectionOrder)
    {
        page.Divider("Domains");
        page.Row(rr => rr.Column(TablerColumnNumber.Twelve, c => {
            c.Card(card => {
                card.Header(h => h.Title("Domains").Subtitle("Switch tabs to view each domain"));
                card.Body(body => {
                    body.SmartTab(tabs => {
                        tabs.WithTheme(SmartTabTheme.Pills)
                            .WithNavStyle(SmartTabNavStyle.Tabs)
                            .WithSelectedTab(0)
                            .Justified(true)
                            .AutoAdjustHeight(true)
                            .WithCardHeaderLook(true);

                        foreach (var kv in ordered)
                        {
                            var d = kv.Key;
                            var b = kv.Value;
                            tabs.AddTab(d, TablerIconType.Globe, panel => {
                                var warnCount = (b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + b.Dkim.Sum(x => x?.WarningCount ?? 0) + (b.Arc?.WarningCount ?? 0) + (b.Bimi?.WarningCount ?? 0);
                                var errCount = (b.Mx?.ErrorCount ?? 0) + (b.Spf?.ErrorCount ?? 0) + (b.Dmarc?.ErrorCount ?? 0) + (b.Mtasts?.ErrorCount ?? 0) + (b.TlsRpt?.ErrorCount ?? 0) + b.Dkim.Sum(x => x?.ErrorCount ?? 0) + (b.Arc?.ErrorCount ?? 0) + (b.Bimi?.ErrorCount ?? 0);
                                var dkimSummary = DisplayFormatting.ComposeDkimSummary(b.Dkim, includeSelectorCount: true);
                                var dnssecSummary = DisplayFormatting.ComposeDnssecSummary(b.Dnssec);
                                var rpkiSummary = DisplayFormatting.ComposeRpkiSummary(b.Rpki);

                                panel.Card(domainCard => {
                                    var sevColor = TablerColor.Blue;
                                    var statusText = "OK";
                                    if (errCount > 0) { sevColor = TablerColor.Danger; statusText = $"{errCount} Error" + (errCount > 1 ? "s" : ""); }
                                    else if (warnCount > 0) { sevColor = TablerColor.Warning; statusText = $"{warnCount} Warning" + (warnCount > 1 ? "s" : ""); }
                                    domainCard.Ribbon(statusText, sevColor)
                                        .Header(h => {
                                            h.Title($"Mail & DNS - {d}")
                                             .Subtitle($"{warnCount} warning(s), {errCount} error(s)")
                                             .SubtitleStyle(TablerTextStyle.Muted)
                                             .WithActions(a => {
                                                 a.Badge(errCount > 0 ? $"{errCount} Error" + (errCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                                 a.Badge(warnCount > 0 ? $"{warnCount} Warning" + (warnCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                                 if (b.Mx != null) a.Badge($"MX: {b.Mx.Status ?? "-"}", ColorForStatus(b.Mx.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                                 if (b.Spf != null) a.Badge($"SPF: {b.Spf.Status ?? "-"}", ColorForStatus(b.Spf.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                                 if (b.Dkim.Count > 0) a.Badge($"DKIM: {dkimSummary}", ColorForStatus(dkimSummary), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                                 if (b.Dmarc != null) a.Badge($"DMARC: {b.Dmarc.Status ?? "-"}", ColorForStatus(b.Dmarc.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                                 if (b.Arc != null) a.Badge($"ARC: {b.Arc.Status ?? "-"}", ColorForStatus(b.Arc.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                                 if (b.Bimi != null) a.Badge($"BIMI: {b.Bimi.Status ?? "-"}", ColorForStatus(b.Bimi.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                                 if (b.Dnssec != null) a.Badge($"DNSSEC: {dnssecSummary}", ColorForStatus(dnssecSummary), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                                 if (b.Rpki != null) a.Badge($"RPKI: {rpkiSummary}", ColorForStatus(rpkiSummary), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                                 if (b.Mtasts != null) a.Badge($"MTA-STS: {b.Mtasts.Status ?? "-"}", ColorForStatus(b.Mtasts.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                                 if (b.TlsRpt != null) a.Badge($"TLS-RPT: {b.TlsRpt.Status ?? "-"}", ColorForStatus(b.TlsRpt.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                             });
                                        });
                                    domainCard.Body(bdy => {
                                        bdy.DataGrid(g =>
                                        {
                                            g.Settings(s => s.Layout(TablerDataGridLayout.Compact).Spacing(TablerDataGridSpacing.Small).NarrowTitles());
                                            if (b.Mx != null) g.AddItem("MX", b.Mx.Status ?? "-").AsPanel(PanelColorForStatus(b.Mx.Status), light: true);
                                            if (b.Spf != null) g.AddItem("SPF", b.Spf.Status ?? "-").AsPanel(PanelColorForStatus(b.Spf.Status), light: true);
                                            if (b.Dkim.Count > 0) g.AddItem("DKIM", dkimSummary).AsPanel(PanelColorForStatus(dkimSummary), light: true);
                                            if (b.Dmarc != null) g.AddItem("DMARC", b.Dmarc.Status ?? "-").AsPanel(PanelColorForStatus(b.Dmarc.Status), light: true);
                                            if (b.Mtasts != null) g.AddItem("MTA-STS", b.Mtasts.Status ?? "-").AsPanel(PanelColorForStatus(b.Mtasts.Status), light: true);
                                            if (b.TlsRpt != null) g.AddItem("TLS-RPT", b.TlsRpt.Status ?? "-").AsPanel(PanelColorForStatus(b.TlsRpt.Status), light: true);
                                            if (b.Dnssec != null) g.AddItem("DNSSEC", dnssecSummary).AsPanel(PanelColorForStatus(dnssecSummary), light: true);
                                            if (b.Rpki != null) g.AddItem("RPKI", rpkiSummary).AsPanel(PanelColorForStatus(rpkiSummary), light: true);
                                        });
                                        var summaryParts = new List<string>
                                        {
                                            $"Warnings: {warnCount}",
                                            $"Errors: {errCount}"
                                        };
                                        if (b.Classification != null && !string.IsNullOrWhiteSpace(b.Classification.Classification))
                                            summaryParts.Add($"Classification: {b.Classification.Classification}");
                                        var providerSummary = BuildProviderSummary(b.Classification);
                                        if (!string.IsNullOrWhiteSpace(providerSummary))
                                            summaryParts.Add(providerSummary!);
                                        bdy.Text(string.Join(" • ", summaryParts)).Style(TablerTextStyle.Muted);
                                    });
                                });

                                var topFindings = BuildTopFindings(new[] { b }, 3);
                                if (topFindings.Count > 0)
                                {
                                    panel.Card(topCard =>
                                    {
                                        topCard.Header(h => h.Title("Top Findings").Subtitle("Most frequent warnings/errors"));
                                        topCard.Body(body =>
                                        {
                                            body.DataGrid(g =>
                                            {
                                                g.Settings(s => s.Layout(TablerDataGridLayout.Compact).Spacing(TablerDataGridSpacing.Small).NarrowTitles());
                                                foreach (var f in topFindings)
                                                {
                                                    var label = string.IsNullOrWhiteSpace(f.Code) ? f.Title : $"{f.Code}: {f.Title}";
                                                    var title = TrimForDisplay(label, 120);
                                                    var color = SeverityRank(f.Severity) == 0 ? TablerColor.Red : TablerColor.Orange;
                                                    g.AddItem(title, $"x{f.Count}").AsPanel(color, light: true);
                                                }
                                            });
                                        });
                                    });
                                }

                                panel.Accordion(acc => {
                                    RenderDomainSections(acc, d, b, sectionOrderMode, normalizedCustom, inputSectionOrder);
                                });
                            });
                        }
                    });
                });
            });
        }));
    }
}
