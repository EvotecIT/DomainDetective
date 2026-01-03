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
    private static void RenderDnsAmplificationSection(TablerAccordion acc, DomainBucket b)
    {
        var amp = b.DnsAmplification;
        if (amp == null)
        {
            return;
        }

        var sec = SectionProjectors.BuildDnsAmplification(amp);

        var warnCount = amp.WarningCount;
        var errCount = amp.ErrorCount;
        var status = amp.Status ?? "Unknown";
        var findingsCount = warnCount + errCount;
        var findingsBadgeColor = errCount > 0
            ? TablerBadgeColor.Danger
            : (warnCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);

        acc.AddItem("DNS Amplification", item =>
        {
            item.Icon(TablerIconType.ShieldBolt);
            item.HeaderRight(c =>
            {
                c.Badge(errCount > 0 ? $"{errCount} Error" + (errCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(warnCount > 0 ? $"{warnCount} Warning" + (warnCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(status, ColorForStatus(status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content =>
            {
                content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 =>
                {
                    RenderExecutionSnapshotCard(c2, g =>
                    {
                        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        AddGridPanelUnique(g, seen, "Status", status, PanelColorForStatus(status), light: true);
                        AddGridPanelUnique(g, seen, "Warnings", warnCount.ToString(CultureInfo.InvariantCulture), warnCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                        AddGridPanelUnique(g, seen, "Errors", errCount.ToString(CultureInfo.InvariantCulture), errCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);

                        if (sec != null)
                        {
                            AddGridSummaryPanelsUnique(g, seen, sec.Summary);
                        }
                    }, subtitle: "Assesses recursion exposure and large UDP response behavior on authoritative name servers.");

                    RenderResultsTabsCard(c2, tabs =>
                    {
                        tabs.AddTab("Summary", panel =>
                        {
                            panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                            {
                                if (sec == null)
                                {
                                    col.Text("DNS amplification section could not be projected.").Style(TablerTextStyle.Muted);
                                    return;
                                }

                                RenderSummaryGrid(col, sec.Summary);
                                RenderSignalsSummary(col, sec.Findings.Select(f => f.Message), sec.Positives);
                            }));
                        }).WithIcon(TablerIconType.Cards);

                        tabs.AddTab("Servers", panel =>
                        {
                            panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                            {
                                if (sec == null || sec.Servers.Count == 0)
                                {
                                    col.Text("No server probe results available.").Style(TablerTextStyle.Muted);
                                    return;
                                }

                                col.Card(card =>
                                {
                                    card.Header(h => h.Title("Name servers").Icon(TablerIconType.Server2));
                                    card.Body(body =>
                                    {
                                        var rows = sec.Servers.Select(s => new
                                        {
                                            s.NameServerHost,
                                            s.ServerIp,
                                            OpenRecursion = s.OpenRecursion,
                                            Edns = s.EdnsSupported,
                                            EdnsUdp = s.EdnsUdpPayloadSize.HasValue ? s.EdnsUdpPayloadSize.Value.ToString(CultureInfo.InvariantCulture) : "-",
                                            WorstBytes = s.WorstProbeResponseBytes,
                                            WorstAmp = s.WorstProbeAmplificationFactor.ToString("0.0", CultureInfo.InvariantCulture),
                                            WorstType = s.WorstProbeType,
                                            WorstName = s.WorstProbeName,
                                            Truncated = s.WorstProbeTruncated
                                        }).ToList();

                                        var t = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                        ConfigureStandardDataTable(t);
                                        t.EnablePaging(25, new[] { 10, 25, 50, 100 })
                                            .EnableSearching()
                                            .EnableOrdering();
                                    });
                                });
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
}

