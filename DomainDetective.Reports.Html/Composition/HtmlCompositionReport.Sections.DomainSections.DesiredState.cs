using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Html;

public static partial class HtmlCompositionReport
{
    private static void RenderDesiredStateSection(TablerAccordion acc, DomainBucket b)
    {
        var ds = b.DesiredState;
        if (ds == null)
        {
            return;
        }

        var sec = SectionProjectors.BuildDesiredState(ds);
        if (sec == null)
        {
            return;
        }

        var desiredFindingsCount = sec.DesiredWarningCount + sec.DesiredErrorCount;
        var bestFindingsCount = sec.BestPracticeWarningCount + sec.BestPracticeErrorCount;
        var desiredBadgeColor = sec.DesiredErrorCount > 0
            ? TablerBadgeColor.Danger
            : (sec.DesiredWarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);
        var bestBadgeColor = sec.BestPracticeErrorCount > 0
            ? TablerBadgeColor.Danger
            : (sec.BestPracticeWarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);

        acc.AddItem("Desired State", item =>
        {
            item.Icon(TablerIconType.ShieldCheck);
            item.HeaderRight(c =>
            {
                c.Badge(sec.DesiredErrorCount > 0 ? $"{sec.DesiredErrorCount} Error" + (sec.DesiredErrorCount > 1 ? "s" : string.Empty) : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(sec.DesiredWarningCount > 0 ? $"{sec.DesiredWarningCount} Warning" + (sec.DesiredWarningCount > 1 ? "s" : string.Empty) : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(sec.Status ?? "Unknown", ColorForStatus(sec.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content =>
            {
                content.Row(r =>
                {
                    r.Column(TablerColumnNumber.Twelve, c2 =>
                    {
                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                            AddGridPanelUnique(g, seen, "Mode", sec.Mode, TablerColor.Blue, light: true);
                            AddGridPanelUnique(g, seen, "Conforms", sec.Conforms ? "Yes" : "No", sec.Conforms ? TablerColor.Green : TablerColor.Red, light: true);
                            AddGridPanelUnique(g, seen, "Desired Warnings", sec.DesiredWarningCount.ToString(), sec.DesiredWarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            AddGridPanelUnique(g, seen, "Desired Errors", sec.DesiredErrorCount.ToString(), sec.DesiredErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                            AddGridPanelUnique(g, seen, "Best-Practice Warnings", sec.BestPracticeWarningCount.ToString(), sec.BestPracticeWarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            AddGridPanelUnique(g, seen, "Best-Practice Errors", sec.BestPracticeErrorCount.ToString(), sec.BestPracticeErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                            AddGridSummaryPanelsUnique(g, seen, sec.Summary);
                        });

                        RenderGuidanceWizardCard(c2, narrative: null, providerHelp: null, providerHelpTopics: null, references: sec.References);

                        RenderResultsTabsCard(c2, tabs =>
                        {
                            var desiredTab = tabs.AddTab("Desired State", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderSignalsSummary(col, null, sec.DesiredPositives);
                                    RenderFindings(col, sec.DesiredFindings);
                                    RenderRecommendations(col, sec.DesiredRecommendations);
                                }));
                            }).WithIcon(TablerIconType.CircleCheck);
                            if (desiredFindingsCount > 0)
                            {
                                desiredTab.WithBadge(desiredFindingsCount.ToString(), desiredBadgeColor);
                            }

                            if (!sec.IsBaselineOnly)
                            {
                                var bestTab = tabs.AddTab("Best-Practice Gaps", panel =>
                                {
                                    panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                    {
                                        RenderSignalsSummary(col, null, sec.BestPracticePositives);
                                        RenderFindings(col, sec.BestPracticeFindings);
                                        RenderRecommendations(col, sec.BestPracticeRecommendations);
                                    }));
                                }).WithIcon(TablerIconType.AlertTriangle);
                                if (bestFindingsCount > 0)
                                {
                                    bestTab.WithBadge(bestFindingsCount.ToString(), bestBadgeColor);
                                }
                            }
                        });
                    });
                });
            });
        });
    }

    private static void RenderRecommendations(TablerColumn c2, IEnumerable<SectionProjectors.SimpleRecommendation>? recommendations)
    {
        if (recommendations == null)
        {
            return;
        }

        var rows = recommendations
            .Where(r => r != null)
            .Select(r => new { r.Code, r.Title, r.How })
            .ToList();
        if (rows.Count == 0)
        {
            return;
        }

        var t = (DataTablesTable)c2.Table(rows, TableType.DataTables);
        ConfigureStandardDataTable(t, defaultMode: ToggleViewMode.ScrollX);
        t.EnablePaging(10, new[] { 10, 25, 50 })
            .EnableSearching()
            .EnableOrdering();
    }
}
