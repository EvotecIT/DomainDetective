using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Html;

public static partial class HtmlCompositionReport
{
    private static void RenderMicrosoft365Section(TablerAccordion acc, DomainBucket b)
    {
        var info = b.Microsoft365;
        if (info == null)
        {
            return;
        }

        if (SectionProjectors.BuildMicrosoft365(info) is not { } sec)
        {
            return;
        }

        acc.AddItem("Microsoft 365", item =>
        {
            item.Icon(TablerIconType.Building);
            item.HeaderRight(c =>
            {
                c.Badge(info.ErrorCount > 0 ? $"{info.ErrorCount} Error" + (info.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(info.WarningCount > 0 ? $"{info.WarningCount} Warning" + (info.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(info.Status ?? "Unknown", ColorForStatus(info.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content =>
            {
                content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 =>
                {
                    RenderExecutionSnapshotCard(c2, grid =>
                    {
                        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        AddGridPanelUnique(grid, seen, "Status", info.Status ?? "-", PanelColorForStatus(info.Status), light: true);
                        AddGridPanelUnique(grid, seen, "Tenant", info.IsMicrosoft365Tenant ? "Detected" : "Not detected", info.IsMicrosoft365Tenant ? TablerColor.Green : TablerColor.Blue, light: true);
                        AddGridPanelUnique(grid, seen, "Confidence", sec.DetectionConfidence, TablerColor.Blue, light: true);
                        AddGridSummaryPanelsUnique(grid, seen, sec.Summary);
                    }, subtitle: "Tenant identity, authentication posture, workloads, and DNS application evidence.");

                    RenderResultsTabsCard(c2, tabs =>
                    {
                        tabs.AddTab("Summary", panel =>
                        {
                            panel.Row(rr => rr.Column(TablerColumnNumber.Six, col => RenderSummaryGrid(col, sec.Summary)));
                            panel.Row(rr => rr.Column(TablerColumnNumber.Six, col => RenderSignalsSummary(col, sec.Highlights, sec.Positives)));
                        }).WithIcon(TablerIconType.Cards);

                        var findingsTab = tabs.AddTab("Findings", panel =>
                        {
                            panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col => RenderFindings(col, sec.Findings)));
                        }).WithIcon(TablerIconType.AlertTriangle);
                        if (sec.Findings.Count > 0)
                        {
                            findingsTab.WithBadge(sec.Findings.Count.ToString(), info.ErrorCount > 0 ? TablerBadgeColor.Danger : TablerBadgeColor.Warning);
                        }

                        tabs.AddTab("Services", panel =>
                        {
                            panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                            {
                                if (sec.Services.Count == 0)
                                {
                                    col.Text("No Microsoft 365 workloads were classified.").Style(TablerTextStyle.Muted);
                                    return;
                                }

                                var rows = sec.Services.Select(x => new { x.Service, x.Status, x.Confidence, x.Evidence }).ToList();
                                var table = (DataTablesTable)col.Table(rows, TableType.DataTables);
                                ConfigureStandardDataTable(table);
                                table.EnablePaging(10, new[] { 10, 25, 50 }).EnableSearching().EnableOrdering();
                            }));
                        }).WithIcon(TablerIconType.Stack);

                        tabs.AddTab("Evidence", panel =>
                        {
                            panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                            {
                                if (sec.Evidence.Count > 0)
                                {
                                    var evidenceRows = sec.Evidence.Select(x => new { x.Label, x.Category, x.Confidence, x.Evidence }).ToList();
                                    var evidenceTable = (DataTablesTable)col.Table(evidenceRows, TableType.DataTables);
                                    ConfigureStandardDataTable(evidenceTable);
                                    evidenceTable.EnablePaging(10, new[] { 10, 25, 50 }).EnableSearching().EnableOrdering();
                                }

                                if (sec.Domains.Count > 0)
                                {
                                    col.H4("Tenant domains");
                                    var domainRows = sec.Domains.Select(x => new { x.Domain, x.Role, x.Confidence, x.Evidence }).ToList();
                                    var domainTable = (DataTablesTable)col.Table(domainRows, TableType.DataTables);
                                    ConfigureStandardDataTable(domainTable);
                                    domainTable.EnablePaging(10, new[] { 10, 25, 50 }).EnableSearching().EnableOrdering();
                                }

                                if (sec.Subdomains.Count > 0)
                                {
                                    col.H4("Known subdomains");
                                    var subdomainRows = sec.Subdomains.Select(x => new { x.Name, x.Role, x.Resolution }).ToList();
                                    var subdomainTable = (DataTablesTable)col.Table(subdomainRows, TableType.DataTables);
                                    ConfigureStandardDataTable(subdomainTable);
                                    subdomainTable.EnablePaging(10, new[] { 10, 25, 50 }).EnableSearching().EnableOrdering();
                                }

                                if (sec.Applications.Count > 0)
                                {
                                    col.H4("Detected DNS applications");
                                    var appRows = sec.Applications.Select(x => new { x.Name, x.Category, x.EvidenceKind, x.Confidence, x.Evidence }).ToList();
                                    var appTable = (DataTablesTable)col.Table(appRows, TableType.DataTables);
                                    ConfigureStandardDataTable(appTable);
                                    appTable.EnablePaging(10, new[] { 10, 25, 50 }).EnableSearching().EnableOrdering();
                                }

                                RenderReferences(col, sec.References);
                            }));
                        }).WithIcon(TablerIconType.Table);
                    });
                }));
            });
        });
    }
}
