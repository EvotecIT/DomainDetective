using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using DomainDetective.Reports;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;

namespace DomainDetective.Reports.Html;

public static partial class HtmlCompositionReport
{
    private static void RenderAgentReadinessSection(TablerAccordion acc, DomainBucket b)
    {
        var agent = b.AgentReadiness;
        if (agent == null)
        {
            return;
        }

        var sec = SectionProjectors.BuildAgentReadiness(agent);
        var status = agent.Status ?? "Unknown";
        var findingsCount = agent.WarningCount + agent.ErrorCount;
        var findingsBadgeColor = agent.ErrorCount > 0
            ? TablerBadgeColor.Danger
            : (agent.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);

        acc.AddItem("Agent Readiness", item =>
        {
            item.Icon(TablerIconType.Globe);
            item.HeaderRight(c =>
            {
                c.Badge(agent.ErrorCount > 0 ? $"{agent.ErrorCount} Error" + (agent.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(agent.WarningCount > 0 ? $"{agent.WarningCount} Warning" + (agent.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(string.Create(CultureInfo.InvariantCulture, $"{agent.Score:0.##}/100"), TablerBadgeColor.Blue, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(status, ColorForStatus(status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content =>
            {
                content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 =>
                {
                    RenderExecutionSnapshotCard(c2, g =>
                    {
                        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        AddGridPanelUnique(g, seen, "Score", agent.Score.ToString("0.##", CultureInfo.InvariantCulture), ScoreColor(agent.Score), light: true);
                        AddGridPanelUnique(g, seen, "Warnings", agent.WarningCount.ToString(CultureInfo.InvariantCulture), agent.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                        AddGridPanelUnique(g, seen, "Errors", agent.ErrorCount.ToString(CultureInfo.InvariantCulture), agent.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                        AddGridPanelUnique(g, seen, "llms.txt", agent.LlmsTxtPresent ? "Present" : "Missing", agent.LlmsTxtPresent ? TablerColor.Green : TablerColor.Orange, light: true);
                        AddGridPanelUnique(g, seen, "Markdown", agent.MarkdownDirect ? "Direct" : (!string.IsNullOrWhiteSpace(agent.MarkdownAlternateUrl) ? "Alternate" : "Missing"), agent.MarkdownDirect || !string.IsNullOrWhiteSpace(agent.MarkdownAlternateUrl) ? TablerColor.Green : TablerColor.Orange, light: true);
                        if (sec != null)
                        {
                            AddGridSummaryPanelsUnique(g, seen, sec.Summary);
                        }
                    }, subtitle: "Checks machine-readable discovery resources for AI crawlers and web agents.");

                    RenderResultsTabsCard(c2, tabs =>
                    {
                        tabs.AddTab("Summary", panel =>
                        {
                            panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                            {
                                RenderSummaryGrid(col, sec?.Summary);
                                RenderSignalsSummary(col, sec?.Highlights, sec?.Positives);
                            }));
                        }).WithIcon(TablerIconType.Cards);

                        tabs.AddTab("Categories", panel =>
                        {
                            panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                            {
                                if (sec == null || sec.Categories.Count == 0)
                                {
                                    col.Text("No category scores available.").Style(TablerTextStyle.Muted);
                                    return;
                                }

                                col.Card(card =>
                                {
                                    card.Header(h => h.Title("Weighted category scores").Icon(TablerIconType.ChartBar));
                                    card.Body(body =>
                                    {
                                        var rows = sec.Categories.Select(category => new
                                        {
                                            category.Category,
                                            Score = string.Create(CultureInfo.InvariantCulture, $"{category.Score:0.##}/{category.MaxScore:0.##}"),
                                            Weighted = string.Create(CultureInfo.InvariantCulture, $"{category.WeightedScore:0.##}/{category.Weight:0.##}"),
                                            category.Passed,
                                            category.Warnings,
                                            category.Failed
                                        }).ToList();

                                        var table = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                        ConfigureStandardDataTable(table);
                                        table.EnablePaging(10, new[] { 10, 25, 50 })
                                            .EnableSearching()
                                            .EnableOrdering();
                                    });
                                });
                            }));
                        }).WithIcon(TablerIconType.ChartBar);

                        tabs.AddTab("Checks", panel =>
                        {
                            panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                            {
                                if (sec == null || sec.Checks.Count == 0)
                                {
                                    col.Text("No check results available.").Style(TablerTextStyle.Muted);
                                    return;
                                }

                                col.Card(card =>
                                {
                                    card.Header(h => h.Title("Readiness checks").Icon(TablerIconType.ListCheck));
                                    card.Body(body =>
                                    {
                                        var rows = sec.Checks.Select(check => new
                                        {
                                            check.Id,
                                            check.Category,
                                            check.Name,
                                            check.Status,
                                            Score = string.Create(CultureInfo.InvariantCulture, $"{check.Score:0.##}/{check.MaxScore:0.##}"),
                                            check.Code,
                                            check.Evidence
                                        }).ToList();

                                        var table = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                        ConfigureStandardDataTable(table, defaultMode: ToggleViewMode.ScrollX);
                                        table.EnablePaging(25, new[] { 10, 25, 50, 100 })
                                            .EnableSearching()
                                            .EnableOrdering();
                                    });
                                });
                            }));
                        }).WithIcon(TablerIconType.ListCheck);

                        tabs.AddTab("Discovery", panel =>
                        {
                            panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                            {
                                if (sec != null && sec.Endpoints.Count > 0)
                                {
                                    col.Card(card =>
                                    {
                                        card.Header(h => h.Title("Endpoint probes").Icon(TablerIconType.Server2));
                                        card.Body(body =>
                                        {
                                            var rows = sec.Endpoints.Select(endpoint => new
                                            {
                                                endpoint.Kind,
                                                endpoint.Url,
                                                endpoint.StatusCode,
                                                endpoint.ContentType,
                                                endpoint.Present,
                                                endpoint.ValidJson,
                                                endpoint.ShapeValid,
                                                endpoint.Shape,
                                                endpoint.DiscoverySource,
                                                endpoint.Error
                                            }).ToList();

                                            var table = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                            ConfigureStandardDataTable(table, defaultMode: ToggleViewMode.ScrollX);
                                            table.EnablePaging(25, new[] { 10, 25, 50, 100 })
                                                .EnableSearching()
                                                .EnableOrdering();
                                        });
                                    });
                                }

                                if (sec != null && sec.Links.Count > 0)
                                {
                                    col.Card(card =>
                                    {
                                        card.Header(h => h.Title("Link header relations").Icon(TablerIconType.Link));
                                        card.Body(body =>
                                        {
                                            var rows = sec.Links.Select(link => new
                                            {
                                                link.Relation,
                                                link.Target,
                                                link.Type,
                                                link.SourceUrl
                                            }).ToList();

                                            var table = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                            ConfigureStandardDataTable(table, defaultMode: ToggleViewMode.ScrollX);
                                            table.EnablePaging(10, new[] { 10, 25, 50 })
                                                .EnableSearching()
                                                .EnableOrdering();
                                        });
                                    });
                                }

                                if (sec != null && sec.ContentSignals.Count > 0)
                                {
                                    col.Card(card =>
                                    {
                                        card.Header(h => h.Title("Content Signals").Icon(TablerIconType.FileText));
                                        card.Body(body =>
                                        {
                                            var rows = sec.ContentSignals.Select(signal => new
                                            {
                                                signal.Source,
                                                signal.Search,
                                                signal.AiInput,
                                                signal.AiTrain,
                                                signal.RawValue
                                            }).ToList();

                                            var table = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                            ConfigureStandardDataTable(table, defaultMode: ToggleViewMode.ScrollX);
                                            table.EnablePaging(10, new[] { 10, 25, 50 })
                                                .EnableSearching()
                                                .EnableOrdering();
                                        });
                                    });
                                }
                            }));
                        }).WithIcon(TablerIconType.Server2);

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

    private static TablerColor ScoreColor(double score)
    {
        if (score >= 80) return TablerColor.Green;
        if (score >= 60) return TablerColor.Orange;
        return TablerColor.Red;
    }
}
