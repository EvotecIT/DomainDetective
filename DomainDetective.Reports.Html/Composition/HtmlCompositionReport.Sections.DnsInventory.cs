using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;
using DomainDetective.Providers.Email;
using DomainDetective.Providers.Dns;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Html;

public static partial class HtmlCompositionReport
{
    private static void RenderDnsInventorySection(TablerAccordion acc, DomainBucket b)
    {
        var inv = b.DnsInventory;
        if (inv == null)
        {
            return;
        }

        var sec = SectionProjectors.BuildDnsInventory(inv);

        acc.AddItem("DNS Inventory", item =>
        {
            item.Icon(TablerIconType.Database);
            item.HeaderRight(c =>
            {
                c.Badge(inv.ErrorCount > 0 ? $"{inv.ErrorCount} Error" + (inv.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(inv.WarningCount > 0 ? $"{inv.WarningCount} Warning" + (inv.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(inv.Status ?? "Unknown", ColorForStatus(inv.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content =>
            {
                content.Row(r =>
                {
                    r.Column(TablerColumnNumber.Twelve, c2 =>
                    {
                        var findingsCount = inv.WarningCount + inv.ErrorCount;
                        var findingsBadgeColor = inv.ErrorCount > 0
                            ? TablerBadgeColor.Danger
                            : (inv.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);

                        var refs = sec?.References;

                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                            AddGridPanelUnique(g, seen, "Status", inv.Status ?? "-", PanelColorForStatus(inv.Status), light: true);
                            AddGridPanelUnique(g, seen, "Warnings", inv.WarningCount.ToString(), inv.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            AddGridPanelUnique(g, seen, "Errors", inv.ErrorCount.ToString(), inv.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                            if (sec != null)
                            {
                                AddGridSummaryPanelsUnique(g, seen, sec.Summary);
                            }
                        }, subtitle: "Common record inventory with TTLs for quick review.");

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
                                        if (!inv.QuerySucceeded)
                                        {
                                            col.Alert("DNS inventory did not complete successfully.", inv.FailureReason ?? string.Empty, TablerColor.Red)
                                                .Icon(TablerIconType.AlertTriangle);
                                        }

                                        if (inv.Provider != DnsProvider.Unknown || (inv.ProviderEvidence != null && inv.ProviderEvidence.Count > 0))
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Inferred DNS Provider").Icon(TablerIconType.Building));
                                                card.Body(body =>
                                                {
                                                    body.Text(inv.Provider != DnsProvider.Unknown ? inv.Provider.ToString() : "-").Style(TablerTextStyle.Monospace);
                                                    if (inv.ProviderEvidence != null && inv.ProviderEvidence.Count > 0)
                                                    {
                                                        var ul = body.TablerList();
                                                        foreach (var e in inv.ProviderEvidence.Take(10))
                                                        {
                                                            if (!string.IsNullOrWhiteSpace(e))
                                                            {
                                                                ul.AddItem(e, TablerIconType.InfoCircle);
                                                            }
                                                        }
                                                        if (inv.ProviderEvidence.Count > 10)
                                                        {
                                                            body.Text($"+{inv.ProviderEvidence.Count - 10} more").Style(TablerTextStyle.Muted);
                                                        }
                                                    }
                                                });
                                            });
                                        }

                                        if (inv.MailProvider != MailProviderKind.Unknown || (inv.MailProviderEvidence != null && inv.MailProviderEvidence.Count > 0))
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Inferred Mail Provider").Icon(TablerIconType.Mail));
                                                card.Body(body =>
                                                {
                                                    body.Text(inv.MailProvider != MailProviderKind.Unknown ? inv.MailProvider.ToString() : "-").Style(TablerTextStyle.Monospace);
                                                    if (inv.MailProviderEvidence != null && inv.MailProviderEvidence.Count > 0)
                                                    {
                                                        var ul = body.TablerList();
                                                        foreach (var e in inv.MailProviderEvidence.Take(10))
                                                        {
                                                            if (!string.IsNullOrWhiteSpace(e))
                                                            {
                                                                ul.AddItem(e, TablerIconType.InfoCircle);
                                                            }
                                                        }
                                                        if (inv.MailProviderEvidence.Count > 10)
                                                        {
                                                            body.Text($"+{inv.MailProviderEvidence.Count - 10} more").Style(TablerTextStyle.Muted);
                                                        }
                                                    }
                                                });
                                            });
                                        }

                                        if (inv.CnameTargetProvider != DnsCnameTargetProvider.Unknown ||
                                            inv.CnameTargetFlags != DnsCnameTargetFlags.None ||
                                            (inv.CnameTargetEvidence != null && inv.CnameTargetEvidence.Count > 0))
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Apex CNAME Insight").Icon(TablerIconType.Link));
                                                card.Body(body =>
                                                {
                                                    var provider = inv.CnameTargetProvider != DnsCnameTargetProvider.Unknown ? inv.CnameTargetProvider.ToString() : "-";
                                                    var flags = inv.CnameTargetFlags != DnsCnameTargetFlags.None ? inv.CnameTargetFlags.ToString() : "-";
                                                    body.Text($"Provider: {provider}").Style(TablerTextStyle.Monospace);
                                                    body.Text($"Flags: {flags}").Style(TablerTextStyle.Monospace);

                                                    if (inv.CnameTargetEvidence != null && inv.CnameTargetEvidence.Count > 0)
                                                    {
                                                        var ul = body.TablerList();
                                                        foreach (var e in inv.CnameTargetEvidence.Take(10))
                                                        {
                                                            if (!string.IsNullOrWhiteSpace(e))
                                                            {
                                                                ul.AddItem(e, TablerIconType.InfoCircle);
                                                            }
                                                        }
                                                        if (inv.CnameTargetEvidence.Count > 10)
                                                        {
                                                            body.Text($"+{inv.CnameTargetEvidence.Count - 10} more").Style(TablerTextStyle.Muted);
                                                        }
                                                    }
                                                });
                                            });
                                        }

                                        if (inv.TxtSignals != DnsTxtSignals.None || (inv.TxtSignalsEvidence != null && inv.TxtSignalsEvidence.Count > 0))
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("TXT Signals").Icon(TablerIconType.FileText));
                                                card.Body(body =>
                                                {
                                                    body.Text(inv.TxtSignals != DnsTxtSignals.None ? inv.TxtSignals.ToString() : "-").Style(TablerTextStyle.Monospace);
                                                    if (inv.TxtSignalsEvidence != null && inv.TxtSignalsEvidence.Count > 0)
                                                    {
                                                        var ul = body.TablerList();
                                                        foreach (var e in inv.TxtSignalsEvidence.Take(10))
                                                        {
                                                            if (!string.IsNullOrWhiteSpace(e))
                                                            {
                                                                ul.AddItem(e, TablerIconType.InfoCircle);
                                                            }
                                                        }
                                                        if (inv.TxtSignalsEvidence.Count > 10)
                                                        {
                                                            body.Text($"+{inv.TxtSignalsEvidence.Count - 10} more").Style(TablerTextStyle.Muted);
                                                        }
                                                    }
                                                });
                                            });
                                        }

                                        if (inv.CaaIssuers != DnsCaaIssuers.None || (inv.CaaIssuersEvidence != null && inv.CaaIssuersEvidence.Count > 0))
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("CAA Issuers").Icon(TablerIconType.Certificate));
                                                card.Body(body =>
                                                {
                                                    body.Text(inv.CaaIssuers != DnsCaaIssuers.None ? inv.CaaIssuers.ToString() : "-").Style(TablerTextStyle.Monospace);
                                                    if (inv.CaaIssuersEvidence != null && inv.CaaIssuersEvidence.Count > 0)
                                                    {
                                                        var ul = body.TablerList();
                                                        foreach (var e in inv.CaaIssuersEvidence.Take(10))
                                                        {
                                                            if (!string.IsNullOrWhiteSpace(e))
                                                            {
                                                                ul.AddItem(e, TablerIconType.InfoCircle);
                                                            }
                                                        }
                                                        if (inv.CaaIssuersEvidence.Count > 10)
                                                        {
                                                            body.Text($"+{inv.CaaIssuersEvidence.Count - 10} more").Style(TablerTextStyle.Muted);
                                                        }
                                                    }
                                                });
                                            });
                                        }

                                        if (inv.Queries != null && inv.Queries.Count > 0)
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Query results").Icon(TablerIconType.ListDetails));
                                                card.Body(body =>
                                                {
                                                    var rows = inv.Queries
                                                        .OrderBy(q => q.RecordType)
                                                        .Select(q => new
                                                        {
                                                            RecordType = q.RecordType,
                                                            Status = q.Status,
                                                            ResponseStatus = q.ResponseStatus,
                                                            Records = q.Records?.Count ?? 0,
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
                                                card.Header(h => h.Title("Captured records (sample)").Icon(TablerIconType.Database));
                                                card.Body(body =>
                                                {
                                                    var rows = sec.Rows
                                                        .Select(r2 => new
                                                        {
                                                            QueryType = r2.QueryType,
                                                            Section = r2.Section,
                                                            RecordType = r2.RecordType,
                                                            r2.Name,
                                                            TTL = r2.Ttl,
                                                            r2.Data
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
                                            col.Text("No records captured.").Style(TablerTextStyle.Muted);
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
