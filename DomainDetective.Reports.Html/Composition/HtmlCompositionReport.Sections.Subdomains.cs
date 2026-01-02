using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;
using DomainDetective.Narratives;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Html;

public static partial class HtmlCompositionReport
{
    private static void RenderSubdomainsSection(TablerAccordion acc, DomainBucket b)
    {
        var sub = b.Subdomains;
        if (sub == null)
        {
            return;
        }

        var sec = SectionProjectors.BuildSubdomains(sub);
        var narrative = SubdomainsNarrative.Build(sub.Raw, sub.Assessments);

        acc.AddItem("Subdomains (Discovery)", item =>
        {
            item.Icon(TablerIconType.Search);
            item.HeaderRight(c =>
            {
                c.Badge(sub.ErrorCount > 0 ? $"{sub.ErrorCount} Error" + (sub.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(sub.WarningCount > 0 ? $"{sub.WarningCount} Warning" + (sub.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(sub.Status ?? "Unknown", ColorForStatus(sub.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content =>
            {
                content.Row(r =>
                {
                    r.Column(TablerColumnNumber.Twelve, c2 =>
                    {
                        var findingsCount = sub.WarningCount + sub.ErrorCount;
                        var findingsBadgeColor = sub.ErrorCount > 0
                            ? TablerBadgeColor.Danger
                            : (sub.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);

                        var refs = MergeReferences(sec?.References, narrative?.References);

                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                            AddGridPanelUnique(g, seen, "Status", sub.Status ?? "-", PanelColorForStatus(sub.Status), light: true);
                            AddGridPanelUnique(g, seen, "Warnings", sub.WarningCount.ToString(), sub.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            AddGridPanelUnique(g, seen, "Errors", sub.ErrorCount.ToString(), sub.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                            if (sec != null)
                            {
                                AddGridSummaryPanelsUnique(g, seen, sec.Summary);
                            }
                        }, subtitle: "CT-backed hostname inventory with optional DNS verification.");

                        RenderGuidanceWizardCard(c2, narrative, providerHelp: null, providerHelpTopics: null, references: refs);

                        RenderResultsTabsCard(
                            c2,
                            tabs =>
                            {
                                tabs.AddTab("Summary", panel =>
                                {
                                    panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                    {
                                        RenderSummaryGrid(col, sec?.Summary);
                                    }));
                                    panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                    {
                                        RenderSignalsSummary(col, sec?.Findings.Select(f => f.Message), sec?.Positives);
                                    }));
                                }).WithIcon(TablerIconType.Cards);

                                var findingsTab = tabs.AddTab("Findings", panel =>
                                {
                                    panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                    {
                                        RenderFindings(col, sec?.Findings);
                                    }));
                                }).WithIcon(TablerIconType.AlertTriangle);
                                if (findingsCount > 0)
                                {
                                    findingsTab.WithBadge(findingsCount.ToString(), findingsBadgeColor);
                                }

                                tabs.AddTab("Evidence", panel =>
                                {
                                    panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                    {
                                        if (!sub.QuerySucceeded)
                                        {
                                            col.Alert("Discovery query failed.", sub.FailureReason ?? string.Empty, TablerColor.Red)
                                                .Icon(TablerIconType.AlertTriangle);
                                        }

                                        var issuerCounts = sub.IssuerCounts;
                                        if (issuerCounts != null && issuerCounts.Count > 0)
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Issuer counts (top)").Icon(TablerIconType.Certificate));
                                                card.Body(body =>
                                                {
                                                    const int maxIssuers = 25;
                                                    var issuerRows = issuerCounts
                                                        .OrderByDescending(kv => kv.Value)
                                                        .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                                                        .Take(maxIssuers)
                                                        .Select(kv => new { Issuer = kv.Key, Count = kv.Value })
                                                        .ToList();

                                                    var t = (DataTablesTable)body.Table(issuerRows, TableType.DataTables);
                                                    ConfigureStandardDataTable(t);
                                                    t.EnablePaging(10, new[] { 10, 25, 50 })
                                                        .EnableSearching()
                                                        .EnableOrdering();

                                                    if (issuerCounts.Count > maxIssuers)
                                                    {
                                                        body.Text($"+{issuerCounts.Count - maxIssuers} more issuer(s)…").Style(TablerTextStyle.Muted);
                                                    }
                                                });
                                            });
                                        }

                                        var subdomains = sub.Subdomains;
                                        if (subdomains != null && subdomains.Count > 0)
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Discovered subdomains").Icon(TablerIconType.ListSearch));
                                                card.Body(body =>
                                                {
                                                    const int maxRows = 200;
                                                    var rows = subdomains
                                                        .Take(maxRows)
                                                        .Select(s => new
                                                        {
                                                            s.Name,
                                                            FirstSeenUtc = s.FirstSeenUtc?.ToString("yyyy-MM-dd") ?? "-",
                                                            LastSeenUtc = s.LastSeenUtc?.ToString("yyyy-MM-dd") ?? "-",
                                                            Resolution = s.ResolutionStatus
                                                        })
                                                        .ToList();

                                                    var t = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                                    ConfigureStandardDataTable(t);
                                                    t.EnablePaging(10, new[] { 10, 25, 50 })
                                                        .EnableSearching()
                                                        .EnableOrdering();

                                                    if (subdomains.Count > maxRows)
                                                    {
                                                        body.Text($"+{subdomains.Count - maxRows} more subdomain(s)…").Style(TablerTextStyle.Muted);
                                                    }
                                                });
                                            });
                                        }
                                        else
                                        {
                                            col.Text("No subdomains found.").Style(TablerTextStyle.Muted);
                                        }

                                        RenderReferences(col, refs);
                                    }));
                                }).WithIcon(TablerIconType.Table);
                            });
                    });
                });
            });
        });
    }
}
