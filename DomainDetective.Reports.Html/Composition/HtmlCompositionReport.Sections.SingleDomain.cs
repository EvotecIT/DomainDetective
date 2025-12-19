using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HtmlCompositionReport partial: single-domain view (header + ordered sections).
/// </summary>
public static partial class HtmlCompositionReport
{
    private static void RenderSingleDomain(HtmlForgeX.TablerPage page, string d, DomainBucket b, SectionOrderMode sectionOrderMode, string[] normalizedCustom, Dictionary<string, List<string>> inputSectionOrder)
    {
        page.Divider(d);
        page.Row(row => {
            row.Column(TablerColumnNumber.Twelve, col => {
                col.Card(card => {
                    var warnCount = (b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + b.Dkim.Sum(x => x.WarningCount) + (b.Arc?.WarningCount ?? 0) + (b.Bimi?.WarningCount ?? 0);
                    var errCount = (b.Mx?.ErrorCount ?? 0) + (b.Spf?.ErrorCount ?? 0) + (b.Dmarc?.ErrorCount ?? 0) + (b.Mtasts?.ErrorCount ?? 0) + (b.TlsRpt?.ErrorCount ?? 0) + b.Dkim.Sum(x => x.ErrorCount) + (b.Arc?.ErrorCount ?? 0) + (b.Bimi?.ErrorCount ?? 0);
                    var sevColor = TablerColor.Blue;
                    var statusText = "OK";
                    if (errCount > 0) { sevColor = TablerColor.Danger; statusText = $"{errCount} Error" + (errCount > 1 ? "s" : ""); }
                    else if (warnCount > 0) { sevColor = TablerColor.Warning; statusText = $"{warnCount} Warning" + (warnCount > 1 ? "s" : ""); }
                    var dkimSummary = DisplayFormatting.ComposeDkimSummary(b.Dkim, includeSelectorCount: true);
                    var dnssecSummary = DisplayFormatting.ComposeDnssecSummary(b.Dnssec);
                    var rpkiSummary = DisplayFormatting.ComposeRpkiSummary(b.Rpki);

                    card.Ribbon(statusText, sevColor)
                        .Header(h => {
                            h.Title($"Mail & DNS - {d}")
                             .Subtitle($"{warnCount} warning(s), {errCount} error(s)")
                             .SubtitleStyle(TablerTextStyle.Muted)
                             .WithActions(a => {
                                 a.Badge(errCount > 0 ? $"{errCount} Error" + (errCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                 a.Badge(warnCount > 0 ? $"{warnCount} Warning" + (warnCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                 a.Badge($"MX: {b.Mx?.Status ?? "-"}", ColorForStatus(b.Mx?.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                 a.Badge($"SPF: {b.Spf?.Status ?? "-"}", ColorForStatus(b.Spf?.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                 a.Badge($"DKIM: {dkimSummary}", ColorForStatus(dkimSummary), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                 a.Badge($"DMARC: {b.Dmarc?.Status ?? "-"}", ColorForStatus(b.Dmarc?.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                 if (b.Arc != null) a.Badge($"ARC: {b.Arc.Status ?? "-"}", ColorForStatus(b.Arc.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                 if (b.Bimi != null) a.Badge($"BIMI: {b.Bimi.Status ?? "-"}", ColorForStatus(b.Bimi.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                 if (b.Dnssec != null) a.Badge($"DNSSEC: {dnssecSummary}", ColorForStatus(dnssecSummary), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                 if (b.Rpki != null) a.Badge($"RPKI: {rpkiSummary}", ColorForStatus(rpkiSummary), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                 a.Badge($"MTA-STS: {b.Mtasts?.Status ?? "-"}", ColorForStatus(b.Mtasts?.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                                 a.Badge($"TLS-RPT: {b.TlsRpt?.Status ?? "-"}", ColorForStatus(b.TlsRpt?.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                             });
                        });
                    card.Body(body => {
                        body.DataGrid(g =>
                        {
                            g.Settings(s => s.Layout(TablerDataGridLayout.Compact).Spacing(TablerDataGridSpacing.Small).NarrowTitles());
                            g.AddItem("MX", b.Mx?.Status ?? "-").AsPanel(PanelColorForStatus(b.Mx?.Status), light: true);
                            g.AddItem("SPF", b.Spf?.Status ?? "-").AsPanel(PanelColorForStatus(b.Spf?.Status), light: true);
                            g.AddItem("DKIM", dkimSummary).AsPanel(PanelColorForStatus(dkimSummary), light: true);
                            g.AddItem("DMARC", b.Dmarc?.Status ?? "-").AsPanel(PanelColorForStatus(b.Dmarc?.Status), light: true);
                            g.AddItem("MTA-STS", b.Mtasts?.Status ?? "-").AsPanel(PanelColorForStatus(b.Mtasts?.Status), light: true);
                            g.AddItem("TLS-RPT", b.TlsRpt?.Status ?? "-").AsPanel(PanelColorForStatus(b.TlsRpt?.Status), light: true);
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
                        body.Text(string.Join(" • ", summaryParts)).Style(TablerTextStyle.Muted);
                    });
                });
            });
        });

        var topFindings = BuildTopFindings(new[] { b }, 3);
        if (topFindings.Count > 0)
        {
            page.Row(row =>
            {
                row.Column(TablerColumnNumber.Twelve, col =>
                {
                    col.Card(card =>
                    {
                        card.Header(h => h.Title("Top Findings").Subtitle("Most frequent warnings/errors"));
                        card.Body(body =>
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
                });
            });
        }

        page.Row(row => {
            row.Column(TablerColumnNumber.Twelve, col => {
                col.Card(card => {
                    card.Header(h => h.Title("Details").Subtitle("Ordered sections"));
                    card.Body(body => {
                        body.Accordion(acc => {
                            RenderDomainSections(acc, d, b, sectionOrderMode, normalizedCustom, inputSectionOrder);
                        });
                    });
                });
            });
        });
    }
}
