using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using DomainDetective.Reports;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;

namespace DomainDetective.Reports.Html;

public static partial class HtmlCompositionReport
{
    private static void RenderSitemapSection(TablerAccordion acc, DomainBucket b)
    {
        var sitemap = b.Sitemap;
        if (sitemap == null)
        {
            return;
        }

        var sec = SectionProjectors.BuildSitemap(sitemap);
        var status = sitemap.Status ?? "Unknown";
        var findingsCount = sitemap.WarningCount + sitemap.ErrorCount;
        var findingsBadgeColor = sitemap.ErrorCount > 0
            ? TablerBadgeColor.Danger
            : (sitemap.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);

        acc.AddItem("Sitemap", item =>
        {
            item.Icon(TablerIconType.FileText);
            item.HeaderRight(c =>
            {
                c.Badge(sitemap.ErrorCount > 0 ? $"{sitemap.ErrorCount} Error" + (sitemap.ErrorCount > 1 ? "s" : string.Empty) : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(sitemap.WarningCount > 0 ? $"{sitemap.WarningCount} Warning" + (sitemap.WarningCount > 1 ? "s" : string.Empty) : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge($"{sitemap.UrlCount.ToString(CultureInfo.InvariantCulture)} URLs", TablerBadgeColor.Blue, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(status, ColorForStatus(status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content =>
            {
                content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 =>
                {
                    RenderExecutionSnapshotCard(c2, g =>
                    {
                        var seen = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
                        AddGridPanelUnique(g, seen, "Documents", sitemap.DocumentCount.ToString(CultureInfo.InvariantCulture), sitemap.DocumentCount > 0 ? TablerColor.Green : TablerColor.Orange, light: true);
                        AddGridPanelUnique(g, seen, "URLs", sitemap.UrlCount.ToString(CultureInfo.InvariantCulture), sitemap.UrlCount > 0 ? TablerColor.Green : TablerColor.Orange, light: true);
                        AddGridPanelUnique(g, seen, "Problems", findingsCount.ToString(CultureInfo.InvariantCulture), findingsCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                        AddGridPanelUnique(g, seen, "Redirect Loops", sitemap.RedirectLoopCount.ToString(CultureInfo.InvariantCulture), sitemap.RedirectLoopCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                        if (sec != null)
                        {
                            AddGridSummaryPanelsUnique(g, seen, sec.Summary);
                        }
                    }, subtitle: "Validates sitemap XML and probes sitemap-listed URLs for crawl, redirect, indexing, and canonical issues.");

                    RenderResultsTabsCard(c2, tabs =>
                    {
                        tabs.AddTab("Summary", panel =>
                        {
                            panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                            {
                                RenderSummaryGrid(col, sec?.Summary);
                                RenderSignalsSummary(col, null, sec?.Positives);
                            }));
                        }).WithIcon(TablerIconType.Cards);

                        tabs.AddTab("Documents", panel =>
                        {
                            panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                            {
                                if (sec == null || sec.Documents.Count == 0)
                                {
                                    col.Text("No sitemap documents available.").Style(TablerTextStyle.Muted);
                                    return;
                                }

                                col.Card(card =>
                                {
                                    card.Header(h => h.Title("Sitemap documents").Icon(TablerIconType.FileText));
                                    card.Body(body =>
                                    {
                                        var rows = sec.Documents.Select(document => new
                                        {
                                            document.Url,
                                            document.StatusCode,
                                            document.ContentType,
                                            document.Present,
                                            document.XmlValid,
                                            document.NamespaceValid,
                                            document.Kind,
                                            document.UrlCount,
                                            document.SitemapCount,
                                            document.Error
                                        }).ToList();

                                        var table = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                        ConfigureStandardDataTable(table, defaultMode: ToggleViewMode.ScrollX);
                                        table.EnablePaging(10, new[] { 10, 25, 50 })
                                            .EnableSearching()
                                            .EnableOrdering();
                                    });
                                });
                            }));
                        }).WithIcon(TablerIconType.FileText);

                        tabs.AddTab("Problem URLs", panel =>
                        {
                            panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                            {
                                if (sec == null || sec.ProblemUrls.Count == 0)
                                {
                                    col.Text("No problem URL probes retained.").Style(TablerTextStyle.Muted);
                                    return;
                                }

                                col.Card(card =>
                                {
                                    card.Header(h => h.Title("Problem URL probes").Icon(TablerIconType.Link));
                                    card.Body(body =>
                                    {
                                        var rows = sec.ProblemUrls.Select(probe => new
                                        {
                                            probe.Url,
                                            probe.FinalUrl,
                                            probe.StatusCode,
                                            probe.ContentType,
                                            probe.Success,
                                            probe.WasRedirected,
                                            probe.RedirectLoop,
                                            probe.RedirectHopCount,
                                            probe.NoIndex,
                                            probe.CanonicalUrl,
                                            probe.CanonicalMismatch,
                                            probe.Error
                                        }).ToList();

                                        var table = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                        ConfigureStandardDataTable(table, defaultMode: ToggleViewMode.ScrollX);
                                        table.EnablePaging(25, new[] { 10, 25, 50, 100 })
                                            .EnableSearching()
                                            .EnableOrdering();
                                    });
                                });
                            }));
                        }).WithIcon(TablerIconType.Link);

                        var findingsTab = tabs.AddTab("Findings", panel =>
                        {
                            panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                            {
                                RenderFindings(col, sec?.Findings);
                            }));
                        }).WithIcon(TablerIconType.AlertTriangle);
                        if (findingsCount > 0)
                        {
                            findingsTab.WithBadge(findingsCount.ToString(CultureInfo.InvariantCulture), findingsBadgeColor);
                        }

                        tabs.AddTab("References", panel =>
                        {
                            panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                            {
                                RenderReferences(col, sec?.References);
                            }));
                        }).WithIcon(TablerIconType.Book);
                    });
                }));
            });
        });
    }
}
