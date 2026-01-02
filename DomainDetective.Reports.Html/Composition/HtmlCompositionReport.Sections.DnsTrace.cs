using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Html;

public static partial class HtmlCompositionReport
{
    private static void RenderDnsTraceSection(TablerAccordion acc, DomainBucket b)
    {
        var tr = b.DnsTrace;
        if (tr == null)
        {
            return;
        }

        var sec = SectionProjectors.BuildDnsTrace(tr);

        acc.AddItem("DNS Trace", item =>
        {
            item.Icon(TablerIconType.Route);
            item.HeaderRight(c =>
            {
                c.Badge(tr.ErrorCount > 0 ? $"{tr.ErrorCount} Error" + (tr.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(tr.WarningCount > 0 ? $"{tr.WarningCount} Warning" + (tr.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(tr.Status ?? "Unknown", ColorForStatus(tr.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content =>
            {
                content.Row(r =>
                {
                    r.Column(TablerColumnNumber.Twelve, c2 =>
                    {
                        var findingsCount = tr.WarningCount + tr.ErrorCount;
                        var findingsBadgeColor = tr.ErrorCount > 0
                            ? TablerBadgeColor.Danger
                            : (tr.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);

                        var refs = sec?.References;

                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                            AddGridPanelUnique(g, seen, "Status", tr.Status ?? "-", PanelColorForStatus(tr.Status), light: true);
                            AddGridPanelUnique(g, seen, "Warnings", tr.WarningCount.ToString(), tr.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            AddGridPanelUnique(g, seen, "Errors", tr.ErrorCount.ToString(), tr.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                            if (sec != null)
                            {
                                AddGridSummaryPanelsUnique(g, seen, sec.Summary);
                            }
                        }, subtitle: "Iterative root-to-answer trace with hop-by-hop evidence.");

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
                                        if (!tr.TraceSucceeded)
                                        {
                                            col.Alert("DNS trace did not complete successfully.", tr.FailureReason ?? string.Empty, TablerColor.Red)
                                                .Icon(TablerIconType.AlertTriangle);
                                        }

                                        if (tr.Queries != null && tr.Queries.Count > 0)
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Trace results").Icon(TablerIconType.ListDetails));
                                                card.Body(body =>
                                                {
                                                    var rows = tr.Queries
                                                        .OrderBy(q => q.RecordType)
                                                        .Select(q => new
                                                        {
                                                            RecordType = q.RecordType,
                                                            Status = q.Status,
                                                            FinalStatus = q.FinalResponseStatus,
                                                            FinalName = string.IsNullOrWhiteSpace(q.FinalName) ? "-" : q.FinalName,
                                                            Steps = q.Steps?.Count ?? 0,
                                                            Failure = string.IsNullOrWhiteSpace(q.FailureReason) ? "-" : q.FailureReason
                                                        })
                                                        .ToList();

                                                    var t = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                                    ConfigureStandardDataTable(t);
                                                    t.EnablePaging(10, new[] { 10, 25, 50 })
                                                        .EnableSearching()
                                                        .EnableOrdering();
                                                });
                                            });
                                        }

                                        if (sec != null && sec.Rows.Count > 0)
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Trace steps (sample)").Icon(TablerIconType.Route));
                                                card.Body(body =>
                                                {
                                                    var rows = sec.Rows
                                                        .Select(r2 => new
                                                        {
                                                            TraceType = r2.TraceType,
                                                            r2.Kind,
                                                            r2.Depth,
                                                            r2.Server,
                                                            r2.Name,
                                                            RecordType = r2.RecordType,
                                                            Status = r2.ResponseStatus,
                                                            r2.Answers,
                                                            r2.Authorities,
                                                            r2.Additional,
                                                            RTTms = r2.RttMs,
                                                            r2.CnameTarget,
                                                            r2.NextServers
                                                        })
                                                        .ToList();

                                                    var t = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                                    ConfigureStandardDataTable(t);
                                                    t.EnablePaging(10, new[] { 10, 25, 50 })
                                                        .EnableSearching()
                                                        .EnableOrdering();
                                                });
                                            });
                                        }
                                        else
                                        {
                                            col.Text("No trace steps captured.").Style(TablerTextStyle.Muted);
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

