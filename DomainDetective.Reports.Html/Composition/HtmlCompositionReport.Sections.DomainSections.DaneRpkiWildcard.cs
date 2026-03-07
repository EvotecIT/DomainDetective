using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;
using DomainDetective;
using DomainDetective.Reports;
using DomainDetective.Views;
using DomainDetective.Narratives;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HtmlCompositionReport partial: ordered per-domain sections.
/// </summary>
public static partial class HtmlCompositionReport
{
    private static void RenderDaneSection(TablerAccordion acc, DomainBucket b)
    {
        var dane = b.Dane;
        if (dane == null)
        {
            return;
        }
        var sec = SectionProjectors.BuildDane(dane);
        var narrative = DaneNarrative.Build(dane.Raw, dane.Assessments);
        acc.AddItem("DANE", item => {
            item.Icon(TablerIconType.Fingerprint);
            item.HeaderRight(c => {
                c.Badge(dane.ErrorCount > 0 ? $"{dane.ErrorCount} Error" + (dane.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(dane.WarningCount > 0 ? $"{dane.WarningCount} Warning" + (dane.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(dane.Status ?? "Unknown", ColorForStatus(dane.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        bool useNewLayout = true;
                        if (useNewLayout)
                        {
                            var findingsCount = dane.WarningCount + dane.ErrorCount;
                            var findingsBadgeColor = dane.ErrorCount > 0
                                ? TablerBadgeColor.Danger
                                : (dane.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);
                            var refs = MergeReferences(sec?.References, narrative?.References);

                            RenderExecutionSnapshotCard(c2, g =>
                            {
                                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                                AddGridPanelUnique(g, seen, "Status", dane.Status ?? "-", PanelColorForStatus(dane.Status), light: true);
                                AddGridPanelUnique(g, seen, "Warnings", dane.WarningCount.ToString(), dane.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                                AddGridPanelUnique(g, seen, "Errors", dane.ErrorCount.ToString(), dane.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                                if (sec != null)
                                {
                                    AddGridSummaryPanelsUnique(g, seen, sec.Summary);
                                }
                            });

                            RenderGuidanceWizardCard(c2, narrative, providerHelp: null, providerHelpTopics: null, references: refs);

                            RenderResultsTabsCard(
                                c2,
                                tabs =>
                            {
                                tabs.AddTab("Summary", panel =>
                                {
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
                                        var raw = dane.Raw;
                                        if (raw != null && raw.AnalysisResults != null && raw.AnalysisResults.Count > 0)
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Analysis Results").Icon(TablerIconType.Table));
                                                card.Body(body =>
                                                {
                                                    var rows = raw.AnalysisResults.Select(r => new
                                                    {
                                                        Host = r.DomainName,
                                                        Usage = r.CertificateUsage,
                                                        Selector = r.SelectorField,
                                                        Matching = r.MatchingTypeField,
                                                        Valid = r.ValidDANERecord ? "Yes" : "No"
                                                    }).ToList();
                                                    var t = (TablerTable)body.Table(rows, TableType.Tabler);
                                                    t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                                });
                                            });
                                        }
                                        else
                                        {
                                            col.Text("No evidence captured for this section.").Style(TablerTextStyle.Muted);
                                        }
                                    }));
                                }).WithIcon(TablerIconType.FileText);
                            });
                        }
                        else
                        {
                            RenderSummaryGrid(c2, sec?.Summary);
                        RenderPositives(c2, sec?.Positives);
                        RenderFindings(c2, sec?.Findings);
                        RenderNarrative(c2, narrative);
                        var raw = dane.Raw;
                        if (raw != null && raw.AnalysisResults != null && raw.AnalysisResults.Count > 0)
                        {
                            c2.Card(card =>
                            {
                                card.Header(h => h.Title("Analysis Results").Icon(TablerIconType.Table));
                                card.Body(body =>
                                {
                                    var rows = raw.AnalysisResults.Select(r => new
                                    {
                                        Host = r.DomainName,
                                        Usage = r.CertificateUsage,
                                        Selector = r.SelectorField,
                                        Matching = r.MatchingTypeField,
                                        Valid = r.ValidDANERecord ? "Yes" : "No"
                                    }).ToList();
                                    var t = (TablerTable)body.Table(rows, TableType.Tabler);
                                    t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                });
                            });
                        }
                        RenderReferences(c2, MergeReferences(sec?.References, narrative?.References));
                        }
                    });
                });
            });
        });
    }

    private static void RenderRpkiSection(TablerAccordion acc, DomainBucket b)
    {
        var rpki = b.Rpki;
        if (rpki == null)
        {
            return;
        }
        var sec = SectionProjectors.BuildRpki(rpki);
        var narrative = RpkiNarrative.Build(rpki.Raw, rpki.Assessments);
        acc.AddItem("RPKI", item => {
            item.Icon(TablerIconType.Route);
            item.HeaderRight(c => {
                c.Badge(rpki.ErrorCount > 0 ? $"{rpki.ErrorCount} Error" + (rpki.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(rpki.WarningCount > 0 ? $"{rpki.WarningCount} Warning" + (rpki.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(rpki.Status ?? "Unknown", ColorForStatus(rpki.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        bool useNewLayout = true;
                        if (useNewLayout)
                        {
                            var findingsCount = rpki.WarningCount + rpki.ErrorCount;
                            var findingsBadgeColor = rpki.ErrorCount > 0
                                ? TablerBadgeColor.Danger
                                : (rpki.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);
                            var refs = MergeReferences(sec?.References, narrative?.References);

                            RenderExecutionSnapshotCard(c2, g =>
                            {
                                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                                AddGridPanelUnique(g, seen, "Status", rpki.Status ?? "-", PanelColorForStatus(rpki.Status), light: true);
                                AddGridPanelUnique(g, seen, "Warnings", rpki.WarningCount.ToString(), rpki.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                                AddGridPanelUnique(g, seen, "Errors", rpki.ErrorCount.ToString(), rpki.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                                if (sec != null)
                                {
                                    AddGridSummaryPanelsUnique(g, seen, sec.Summary);
                                }
                            });

                            RenderGuidanceWizardCard(c2, narrative, providerHelp: null, providerHelpTopics: null, references: refs);

                            RenderResultsTabsCard(
                                c2,
                                tabs =>
                            {
                                tabs.AddTab("Summary", panel =>
                                {
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
                                        if (rpki.Results != null && rpki.Results.Count > 0)
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Per-IP Results").Icon(TablerIconType.Route));
                                                card.Body(body =>
                                                {
                                                    var rows = rpki.Results.Select(r2 => new { r2.IpAddress, r2.Prefix, r2.Asn, Valid = r2.Valid ? "Yes" : "No" }).ToList();
                                                    var t = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                                    ConfigureStandardDataTable(t, defaultMode: ToggleViewMode.ScrollX);
                                                    t.EnablePaging(10, new[] { 10, 25, 50 })
                                                        .EnableSearching()
                                                        .EnableOrdering();
                                                });
                                            });
                                        }
                                        else
                                        {
                                            col.Text("No evidence captured for this section.").Style(TablerTextStyle.Muted);
                                        }
                                    }));
                                }).WithIcon(TablerIconType.FileText);
                            });
                        }
                        else
                        {
                            RenderSummaryGrid(c2, sec?.Summary);
                        RenderPositives(c2, sec?.Positives);
                        RenderFindings(c2, sec?.Findings);
                        RenderNarrative(c2, narrative);
                        if (rpki.Results != null && rpki.Results.Count > 0)
                        {
                            c2.Card(card =>
                            {
                                card.Header(h => h.Title("Per-IP Results").Icon(TablerIconType.Route));
                                card.Body(body =>
                                {
                                    var rows = rpki.Results.Select(r2 => new { r2.IpAddress, r2.Prefix, r2.Asn, Valid = r2.Valid ? "Yes" : "No" }).ToList();
                                    var t = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                    ConfigureStandardDataTable(t, defaultMode: ToggleViewMode.ScrollX);
                                    t.EnablePaging(10, new[] { 10, 25, 50 })
                                        .EnableSearching()
                                        .EnableOrdering();
                                });
                            });
                        }
                        RenderReferences(c2, MergeReferences(sec?.References, narrative?.References));
                        }
                    });
                });
            });
        });
    }

    private static void RenderZoneTransferSection(TablerAccordion acc, DomainBucket b)
    {
        var zone = b.ZoneTransfer;
        if (zone == null)
        {
            return;
        }
        var sec = SectionProjectors.BuildZoneTransfer(zone);
        var narrative = ZoneTransferNarrative.Build(zone.Raw, zone.Assessments);
        acc.AddItem("Zone Transfer", item => {
            item.Icon(TablerIconType.ArrowsTransferUp);
            item.HeaderRight(c => {
                c.Badge(zone.ErrorCount > 0 ? $"{zone.ErrorCount} Error" + (zone.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(zone.WarningCount > 0 ? $"{zone.WarningCount} Warning" + (zone.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(zone.Status ?? "Unknown", ColorForStatus(zone.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        bool useNewLayout = true;
                        if (useNewLayout)
                        {
                            var findingsCount = zone.WarningCount + zone.ErrorCount;
                            var findingsBadgeColor = zone.ErrorCount > 0
                                ? TablerBadgeColor.Danger
                                : (zone.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);
                            var refs = MergeReferences(sec?.References, narrative?.References);

                            RenderExecutionSnapshotCard(c2, g =>
                            {
                                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                                AddGridPanelUnique(g, seen, "Status", zone.Status ?? "-", PanelColorForStatus(zone.Status), light: true);
                                AddGridPanelUnique(g, seen, "Warnings", zone.WarningCount.ToString(), zone.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                                AddGridPanelUnique(g, seen, "Errors", zone.ErrorCount.ToString(), zone.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                                if (sec != null)
                                {
                                    AddGridSummaryPanelsUnique(g, seen, sec.Summary);
                                }
                            });

                            RenderGuidanceWizardCard(c2, narrative, providerHelp: null, providerHelpTopics: null, references: refs);

                            RenderResultsTabsCard(
                                c2,
                                tabs =>
                            {
                                tabs.AddTab("Summary", panel =>
                                {
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
                                        if (zone.ServerResults != null && zone.ServerResults.Count > 0)
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Server Results").Icon(TablerIconType.Table));
                                                card.Body(body =>
                                                {
                                                    var rows = zone.ServerResults.Select(kv => new { Server = kv.Key, Open = kv.Value ? "Yes" : "No" }).ToList();
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
                                            col.Text("No evidence captured for this section.").Style(TablerTextStyle.Muted);
                                        }
                                    }));
                                }).WithIcon(TablerIconType.FileText);
                            });
                        }
                        else
                        {
                            RenderSummaryGrid(c2, sec?.Summary);
                        RenderFindings(c2, sec?.Findings);
                        RenderNarrative(c2, narrative);
                        if (zone.ServerResults != null && zone.ServerResults.Count > 0)
                        {
                            c2.Card(card =>
                            {
                                card.Header(h => h.Title("Server Results").Icon(TablerIconType.Table));
                                card.Body(body =>
                                {
                                    var rows = zone.ServerResults.Select(kv => new { Server = kv.Key, Open = kv.Value ? "Yes" : "No" }).ToList();
                                    var t = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                    ConfigureStandardDataTable(t);
                                    t.EnablePaging(10, new[] { 10, 25, 50 })
                                        .EnableSearching()
                                        .EnableOrdering();
                                });
                            });
                        }
                        RenderReferences(c2, MergeReferences(sec?.References, narrative?.References));
                        }
                    });
                });
            });
        });
    }

    private static void RenderWildcardSection(TablerAccordion acc, DomainBucket b)
    {
        var wildcard = b.Wildcard;
        if (wildcard == null)
        {
            return;
        }
        var sec = SectionProjectors.BuildWildcard(wildcard);
        var narrative = WildcardNarrative.Build(wildcard.Raw, wildcard.Assessments);
        acc.AddItem("Wildcard DNS", item => {
            item.Icon(TablerIconType.Asterisk);
            item.HeaderRight(c => {
                c.Badge(wildcard.ErrorCount > 0 ? $"{wildcard.ErrorCount} Error" + (wildcard.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(wildcard.WarningCount > 0 ? $"{wildcard.WarningCount} Warning" + (wildcard.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(wildcard.Status ?? "Unknown", ColorForStatus(wildcard.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        bool useNewLayout = true;
                        if (useNewLayout)
                        {
                            var findingsCount = wildcard.WarningCount + wildcard.ErrorCount;
                            var findingsBadgeColor = wildcard.ErrorCount > 0
                                ? TablerBadgeColor.Danger
                                : (wildcard.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);
                            var refs = MergeReferences(sec?.References, narrative?.References);

                            RenderExecutionSnapshotCard(c2, g =>
                            {
                                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                                AddGridPanelUnique(g, seen, "Status", wildcard.Status ?? "-", PanelColorForStatus(wildcard.Status), light: true);
                                AddGridPanelUnique(g, seen, "Warnings", wildcard.WarningCount.ToString(), wildcard.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                                AddGridPanelUnique(g, seen, "Errors", wildcard.ErrorCount.ToString(), wildcard.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                                if (sec != null)
                                {
                                    AddGridSummaryPanelsUnique(g, seen, sec.Summary);
                                }
                            });

                            RenderGuidanceWizardCard(c2, narrative, providerHelp: null, providerHelpTopics: null, references: refs);

                            RenderResultsTabsCard(
                                c2,
                                tabs =>
                            {
                                tabs.AddTab("Summary", panel =>
                                {
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
                                        bool hasEvidence = false;
                                        var raw = wildcard.Raw;
                                        if (raw != null)
                                        {
                                            const int maxItems = 10;
                                            if (raw.TestedNames != null && raw.TestedNames.Count > 0)
                                            {
                                                hasEvidence = true;
                                                col.Card(card =>
                                                {
                                                    card.Header(h => h.Title("Tested names").Icon(TablerIconType.Asterisk));
                                                    card.Body(body =>
                                                    {
                                                        var ul = body.TablerList();
                                                        foreach (var name in raw.TestedNames.Take(maxItems))
                                                        {
                                                            if (!string.IsNullOrWhiteSpace(name))
                                                            {
                                                                ul.AddItem(name, TablerIconType.Asterisk);
                                                            }
                                                        }
                                                        if (raw.TestedNames.Count > maxItems)
                                                        {
                                                            body.Text($"+{raw.TestedNames.Count - maxItems} more").Style(TablerTextStyle.Muted);
                                                        }
                                                    });
                                                });
                                            }
                                            if (raw.ResolvedNames != null && raw.ResolvedNames.Count > 0)
                                            {
                                                hasEvidence = true;
                                                col.Card(card =>
                                                {
                                                    card.Header(h => h.Title("Resolved names").Icon(TablerIconType.Asterisk));
                                                    card.Body(body =>
                                                    {
                                                        var ul = body.TablerList();
                                                        foreach (var name in raw.ResolvedNames.Take(maxItems))
                                                        {
                                                            if (!string.IsNullOrWhiteSpace(name))
                                                            {
                                                                ul.AddItem(name, TablerIconType.Asterisk);
                                                            }
                                                        }
                                                        if (raw.ResolvedNames.Count > maxItems)
                                                        {
                                                            body.Text($"+{raw.ResolvedNames.Count - maxItems} more").Style(TablerTextStyle.Muted);
                                                        }
                                                    });
                                                });
                                            }
                                            if (raw.ResolvedAddresses != null && raw.ResolvedAddresses.Count > 0)
                                            {
                                                hasEvidence = true;
                                                col.Card(card =>
                                                {
                                                    card.Header(h => h.Title("Resolved addresses").Icon(TablerIconType.Asterisk));
                                                    card.Body(body =>
                                                    {
                                                        var ul = body.TablerList();
                                                        foreach (var addr in raw.ResolvedAddresses.Take(maxItems))
                                                        {
                                                            if (!string.IsNullOrWhiteSpace(addr))
                                                            {
                                                                ul.AddItem(addr, TablerIconType.Asterisk);
                                                            }
                                                        }
                                                        if (raw.ResolvedAddresses.Count > maxItems)
                                                        {
                                                            body.Text($"+{raw.ResolvedAddresses.Count - maxItems} more").Style(TablerTextStyle.Muted);
                                                        }
                                                    });
                                                });
                                            }
                                        }

                                        if (!hasEvidence)
                                        {
                                            col.Text("No evidence captured for this section.").Style(TablerTextStyle.Muted);
                                        }
                                    }));
                                }).WithIcon(TablerIconType.FileText);
                            });
                        }
                        else
                        {
                            RenderSummaryGrid(c2, sec?.Summary);
                        RenderFindings(c2, sec?.Findings);
                        RenderNarrative(c2, narrative);
                        var raw = wildcard.Raw;
                        if (raw != null)
                        {
                            const int maxItems = 10;
                            if (raw.TestedNames != null && raw.TestedNames.Count > 0)
                            {
                                c2.Card(card =>
                                {
                                    card.Header(h => h.Title("Tested names").Icon(TablerIconType.Asterisk));
                                    card.Body(body =>
                                    {
                                        var ul = body.TablerList();
                                        foreach (var name in raw.TestedNames.Take(maxItems))
                                        {
                                            if (!string.IsNullOrWhiteSpace(name))
                                            {
                                                ul.AddItem(name, TablerIconType.Asterisk);
                                            }
                                        }
                                        if (raw.TestedNames.Count > maxItems)
                                        {
                                            body.Text($"+{raw.TestedNames.Count - maxItems} more").Style(TablerTextStyle.Muted);
                                        }
                                    });
                                });
                            }
                            if (raw.ResolvedNames != null && raw.ResolvedNames.Count > 0)
                            {
                                c2.Card(card =>
                                {
                                    card.Header(h => h.Title("Resolved names").Icon(TablerIconType.Asterisk));
                                    card.Body(body =>
                                    {
                                        var ul = body.TablerList();
                                        foreach (var name in raw.ResolvedNames.Take(maxItems))
                                        {
                                            if (!string.IsNullOrWhiteSpace(name))
                                            {
                                                ul.AddItem(name, TablerIconType.Asterisk);
                                            }
                                        }
                                        if (raw.ResolvedNames.Count > maxItems)
                                        {
                                            body.Text($"+{raw.ResolvedNames.Count - maxItems} more").Style(TablerTextStyle.Muted);
                                        }
                                    });
                                });
                            }
                            if (raw.ResolvedAddresses != null && raw.ResolvedAddresses.Count > 0)
                            {
                                c2.Card(card =>
                                {
                                    card.Header(h => h.Title("Resolved addresses").Icon(TablerIconType.Asterisk));
                                    card.Body(body =>
                                    {
                                        var ul = body.TablerList();
                                        foreach (var addr in raw.ResolvedAddresses.Take(maxItems))
                                        {
                                            if (!string.IsNullOrWhiteSpace(addr))
                                            {
                                                ul.AddItem(addr, TablerIconType.Asterisk);
                                            }
                                        }
                                        if (raw.ResolvedAddresses.Count > maxItems)
                                        {
                                            body.Text($"+{raw.ResolvedAddresses.Count - maxItems} more").Style(TablerTextStyle.Muted);
                                        }
                                    });
                                });
                            }
                        }
                        RenderReferences(c2, MergeReferences(sec?.References, narrative?.References));
                        }
                    });
                });
            });
        });
    }

}
