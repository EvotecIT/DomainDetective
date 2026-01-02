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
    private static void RenderIpEnrichmentSection(TablerAccordion acc, DomainBucket b)
    {
        var ip = b.IpEnrichment;
        if (ip == null)
        {
            return;
        }

        var sec = SectionProjectors.BuildIpEnrichment(ip);
        var narrative = IpEnrichmentNarrative.Build(ip.Raw);
        var refs = MergeReferences(sec?.References, narrative?.References);

        acc.AddItem("IP Enrichment", item =>
        {
            item.Icon(TablerIconType.Route);
            item.HeaderRight(c =>
            {
                c.Badge(ip.ErrorCount > 0 ? $"{ip.ErrorCount} Error" + (ip.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(ip.WarningCount > 0 ? $"{ip.WarningCount} Warning" + (ip.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(ip.Status ?? "Unknown", ColorForStatus(ip.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content =>
            {
                content.Row(r =>
                {
                    r.Column(TablerColumnNumber.Twelve, c2 =>
                    {
                        var findingsCount = ip.WarningCount + ip.ErrorCount;
                        var findingsBadgeColor = ip.ErrorCount > 0
                            ? TablerBadgeColor.Danger
                            : (ip.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);

                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                            AddGridPanelUnique(g, seen, "Status", ip.Status ?? "-", PanelColorForStatus(ip.Status), light: true);
                            AddGridPanelUnique(g, seen, "Warnings", ip.WarningCount.ToString(), ip.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            AddGridPanelUnique(g, seen, "Errors", ip.ErrorCount.ToString(), ip.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                            if (sec != null)
                            {
                                AddGridSummaryPanelsUnique(g, seen, sec.Summary);
                            }
                        }, subtitle: "IP footprint summary (reverse DNS, ASN/org, and country/region hints) across apex/MX/NS discoveries.");

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
                                        if (!ip.QuerySucceeded)
                                        {
                                            col.Alert("IP enrichment did not complete successfully.", ip.FailureReason ?? string.Empty, TablerColor.Red)
                                                .Icon(TablerIconType.AlertTriangle);
                                        }

                                        if (sec != null)
                                        {
                                            if (ip.AsnCounts != null && ip.AsnCounts.Count > 0)
                                            {
                                                col.Card(card =>
                                                {
                                                    card.Header(h => h.Title("ASN counts (top)").Icon(TablerIconType.Building));
                                                    card.Body(body =>
                                                    {
                                                        var rows = ip.AsnCounts
                                                            .OrderByDescending(kv => kv.Value)
                                                            .ThenBy(kv => kv.Key)
                                                            .Take(25)
                                                            .Select(kv => new { Asn = "AS" + kv.Key, Count = kv.Value })
                                                            .ToList();
                                                        var t = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                                        ConfigureStandardDataTable(t);
                                                        t.EnablePaging(10, new[] { 10, 25, 50 })
                                                            .EnableSearching()
                                                            .EnableOrdering();
                                                    });
                                                });
                                            }

                                            if (ip.CountryCounts != null && ip.CountryCounts.Count > 0)
                                            {
                                                col.Card(card =>
                                                {
                                                    card.Header(h => h.Title("Country counts (top)").Icon(TablerIconType.World));
                                                    card.Body(body =>
                                                    {
                                                        var rows = ip.CountryCounts
                                                            .OrderByDescending(kv => kv.Value)
                                                            .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                                                            .Take(25)
                                                            .Select(kv => new { Country = kv.Key, Count = kv.Value })
                                                            .ToList();
                                                        var t = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                                        ConfigureStandardDataTable(t);
                                                        t.EnablePaging(10, new[] { 10, 25, 50 })
                                                            .EnableSearching()
                                                            .EnableOrdering();
                                                    });
                                                });
                                            }

                                            if (sec.Rows.Count > 0)
                                            {
                                                col.Card(card =>
                                                {
                                                    card.Header(h => h.Title("Enriched IP rows (sample)").Icon(TablerIconType.Table));
                                                    card.Body(body =>
                                                    {
                                                        const int maxRows = 500;
                                                        var rows = sec.Rows
                                                            .Take(maxRows)
                                                            .Select(x => new
                                                            {
                                                                x.IpAddress,
                                                                Family = x.Family.ToString(),
                                                                SourceKind = x.SourceKind.ToString(),
                                                                x.SourceHost,
                                                                x.Ptr,
                                                                Asn = x.Asn.HasValue ? "AS" + x.Asn.Value : string.Empty,
                                                                x.AsName,
                                                                x.Cidr,
                                                                x.Country,
                                                                x.Region
                                                            })
                                                            .ToList();

                                                        var t = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                                        ConfigureStandardDataTable(t, defaultMode: ToggleViewMode.ScrollX);
                                                        t.EnablePaging(10, new[] { 10, 25, 50 })
                                                            .EnableSearching()
                                                            .EnableOrdering();

                                                        if (sec.Rows.Count > maxRows)
                                                        {
                                                            body.Text($"+{sec.Rows.Count - maxRows} more row(s)…").Style(TablerTextStyle.Muted);
                                                        }
                                                    });
                                                });
                                            }
                                            else
                                            {
                                                col.Text("No IP enrichment rows available.").Style(TablerTextStyle.Muted);
                                            }
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

