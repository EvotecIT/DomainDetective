using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Html;

public static partial class HtmlCompositionReport
{
    private static void RenderCtTimelineSection(TablerAccordion acc, DomainBucket b)
    {
        var ct = b.CtTimeline;
        if (ct == null)
        {
            return;
        }

        var sec = SectionProjectors.BuildCtTimeline(ct);

        acc.AddItem("CT Timeline", item =>
        {
            item.Icon(TablerIconType.Certificate);
            item.HeaderRight(c =>
            {
                c.Badge(ct.ErrorCount > 0 ? $"{ct.ErrorCount} Error" + (ct.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(ct.WarningCount > 0 ? $"{ct.WarningCount} Warning" + (ct.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(ct.Status ?? "Unknown", ColorForStatus(ct.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content =>
            {
                content.Row(r =>
                {
                    r.Column(TablerColumnNumber.Twelve, c2 =>
                    {
                        var findingsCount = ct.WarningCount + ct.ErrorCount;
                        var findingsBadgeColor = ct.ErrorCount > 0
                            ? TablerBadgeColor.Danger
                            : (ct.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);

                        var refs = sec?.References;

                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                            AddGridPanelUnique(g, seen, "Status", ct.Status ?? "-", PanelColorForStatus(ct.Status), light: true);
                            AddGridPanelUnique(g, seen, "Warnings", ct.WarningCount.ToString(), ct.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            AddGridPanelUnique(g, seen, "Errors", ct.ErrorCount.ToString(), ct.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                            if (sec != null)
                            {
                                AddGridSummaryPanelsUnique(g, seen, sec.Summary);
                            }
                        }, subtitle: "Certificate transparency timeline: issuance history, issuer diversity, and validity state.");

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
                                        if (!ct.QuerySucceeded)
                                        {
                                            col.Alert("CT timeline did not complete successfully.", ct.FailureReason ?? string.Empty, TablerColor.Red)
                                                .Icon(TablerIconType.AlertTriangle);
                                        }

                                        if (sec != null && sec.Timeline.Count > 0)
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Issuance timeline (monthly)").Icon(TablerIconType.CalendarTime));
                                                card.Body(body =>
                                                {
                                                    var rows = sec.Timeline.Select(x => new
                                                    {
                                                        x.Month,
                                                        Certificates = x.Certificates,
                                                        Issuers = x.Issuers
                                                    }).ToList();

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
                                            col.Text("No CT timeline buckets available.").Style(TablerTextStyle.Muted);
                                        }

                                        if (sec != null && sec.RecentCertificates.Count > 0)
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Recent certificates (sample)").Icon(TablerIconType.Certificate));
                                                card.Body(body =>
                                                {
                                                    var rows = sec.RecentCertificates.Select(x => new
                                                    {
                                                        EntryUtc = x.EntryUtc,
                                                        NotAfterUtc = x.NotAfterUtc,
                                                        x.Validity,
                                                        x.Wildcard,
                                                        x.Issuer,
                                                        x.CommonName
                                                    }).ToList();

                                                    var t = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                                    ConfigureStandardDataTable(t);
                                                    t.EnablePaging(10, new[] { 10, 25, 50 })
                                                        .EnableSearching()
                                                        .EnableOrdering();
                                                });
                                            });
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

