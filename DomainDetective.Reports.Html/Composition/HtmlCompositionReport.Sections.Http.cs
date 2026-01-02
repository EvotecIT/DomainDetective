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
    private static void RenderHttpSection(TablerAccordion acc, DomainBucket b)
    {
        var http = b.Http;
        if (http == null)
        {
            return;
        }

        var sec = SectionProjectors.BuildHttp(http);
        var narrative = HttpNarrative.Build(http.Raw);
        var refs = MergeReferences(sec?.References, narrative?.References);

        acc.AddItem("HTTP", item =>
        {
            item.Icon(TablerIconType.Globe);
            item.HeaderRight(c =>
            {
                c.Badge(http.ErrorCount > 0 ? $"{http.ErrorCount} Error" + (http.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(http.WarningCount > 0 ? $"{http.WarningCount} Warning" + (http.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(http.Status ?? "Unknown", ColorForStatus(http.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content =>
            {
                content.Row(r =>
                {
                    r.Column(TablerColumnNumber.Twelve, c2 =>
                    {
                        var findingsCount = http.WarningCount + http.ErrorCount;
                        var findingsBadgeColor = http.ErrorCount > 0
                            ? TablerBadgeColor.Danger
                            : (http.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);

                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                            AddGridPanelUnique(g, seen, "Status", http.Status ?? "-", PanelColorForStatus(http.Status), light: true);
                            AddGridPanelUnique(g, seen, "Warnings", http.WarningCount.ToString(), http.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            AddGridPanelUnique(g, seen, "Errors", http.ErrorCount.ToString(), http.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                            if (http.Grade != GradeLevel.Unknown)
                            {
                                var grade = http.Grade.ToString();
                                AddGridPanelUnique(g, seen, "Grade", grade, GradeColor(grade), light: true);
                            }
                            if (sec != null)
                            {
                                AddGridSummaryPanelsUnique(g, seen, sec.Summary);
                            }
                        }, subtitle: "HTTP posture check: reachability, redirects, protocol versions, and modern security headers.");

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
                                        var raw = http.Raw;
                                        if (!http.IsReachable)
                                        {
                                            col.Alert("HTTP endpoint was not reachable.", raw?.FailureReason ?? string.Empty, TablerColor.Red)
                                                .Icon(TablerIconType.AlertTriangle);
                                        }

                                        // Redirect chain / effective URL
                                        try
                                        {
                                            var visited = raw?.VisitedUrls;
                                            if (visited != null && visited.Count > 0)
                                            {
                                                col.Card(card =>
                                                {
                                                    card.Header(h => h.Title("Redirect chain").Icon(TablerIconType.ArrowRight));
                                                    card.Body(body =>
                                                    {
                                                        var rows = visited
                                                            .Select((u, i) => new { Step = i + 1, Url = u })
                                                            .ToList();
                                                        var t = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                                        ConfigureStandardDataTable(t, defaultMode: ToggleViewMode.ScrollX);
                                                        t.EnablePaging(10, new[] { 10, 25, 50 })
                                                            .EnableSearching()
                                                            .EnableOrdering();
                                                    });
                                                });
                                            }
                                        }
                                        catch
                                        {
                                        }

                                        // Request metadata
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("Request metadata").Icon(TablerIconType.Activity));
                                            card.Body(body =>
                                            {
                                                var kv = new List<(string Key, string Value)>
                                                {
                                                    ("Method Used", http.RequestMethodUsed.ToString()),
                                                    ("TLS Validation", http.TlsValidationDisabled ? "Disabled" : "Enabled"),
                                                    ("Proxy", string.IsNullOrWhiteSpace(http.ProxyUsed) ? "-" : http.ProxyUsed!)
                                                };

                                                var effectiveUrl = sec?.EffectiveUrl;
                                                if (!string.IsNullOrWhiteSpace(effectiveUrl))
                                                {
                                                    kv.Add(("Effective URL", effectiveUrl!));
                                                }

                                                if (raw != null)
                                                {
                                                    kv.Add(("Response Time", raw.ResponseTime.ToString()));
                                                    kv.Add(("Body Length (bytes)", raw.BodyLength?.ToString() ?? "-"));
                                                    kv.Add(("Body SHA-256", raw.BodySha256 ?? "-"));
                                                    kv.Add(("Mixed Content", raw.MixedContentDetected ? "Yes" : "No"));
                                                    kv.Add(("Insecure Forms", raw.InsecureFormsCount > 0 ? raw.InsecureFormsCount.ToString() : "0"));
                                                }

                                                var kvRows = kv.Select(x => new { x.Key, x.Value }).ToList();
                                                var kvTable = (TablerTable)body.Table(kvRows, TableType.Tabler);
                                                kvTable.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);

                                                if (http.RequestHeaderNames != null && http.RequestHeaderNames.Count > 0)
                                                {
                                                    var list = body.TablerList();
                                                    foreach (var h in http.RequestHeaderNames.Take(20))
                                                    {
                                                        if (!string.IsNullOrWhiteSpace(h))
                                                        {
                                                            list.AddItem(h, TablerIconType.InfoCircle);
                                                        }
                                                    }
                                                    if (http.RequestHeaderNames.Count > 20)
                                                    {
                                                        body.Text($"+{http.RequestHeaderNames.Count - 20} more request header name(s)…").Style(TablerTextStyle.Muted);
                                                    }
                                                }

                                                try
                                                {
                                                    var actions = raw?.InsecureFormActions;
                                                    if (actions != null && actions.Count > 0)
                                                    {
                                                        body.Text("Sample insecure form actions:").Style(TablerTextStyle.Muted);
                                                        var list2 = body.TablerList();
                                                        foreach (var a in actions.Take(10))
                                                        {
                                                            if (!string.IsNullOrWhiteSpace(a))
                                                            {
                                                                list2.AddItem(a, TablerIconType.AlertTriangle);
                                                            }
                                                        }
                                                        if (actions.Count > 10)
                                                        {
                                                            body.Text($"+{actions.Count - 10} more action(s)…").Style(TablerTextStyle.Muted);
                                                        }
                                                    }
                                                }
                                                catch
                                                {
                                                }
                                            });
                                        });

                                        // Security headers
                                        if (sec != null)
                                        {
                                            if (sec.PresentSecurityHeaders.Count > 0)
                                            {
                                                col.Card(card =>
                                                {
                                                    card.Header(h => h.Title("Present security headers").Icon(TablerIconType.ShieldLock));
                                                    card.Body(body =>
                                                    {
                                                        var rows = sec.PresentSecurityHeaders.Select(x => new { x.Name, x.Value }).ToList();
                                                        var t = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                                        ConfigureStandardDataTable(t, defaultMode: ToggleViewMode.ScrollX);
                                                        t.EnablePaging(10, new[] { 10, 25, 50 })
                                                            .EnableSearching()
                                                            .EnableOrdering();
                                                    });
                                                });
                                            }

                                            if (sec.MissingSecurityHeaders.Count > 0)
                                            {
                                                col.Card(card =>
                                                {
                                                    card.Header(h => h.Title("Missing recommended security headers").Icon(TablerIconType.AlertTriangle));
                                                    card.Body(body =>
                                                    {
                                                        var rows = sec.MissingSecurityHeaders.Select(x => new { Header = x }).ToList();
                                                        var t = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                                        ConfigureStandardDataTable(t, defaultMode: ToggleViewMode.ScrollX);
                                                        t.EnablePaging(10, new[] { 10, 25, 50 })
                                                            .EnableSearching()
                                                            .EnableOrdering();
                                                    });
                                                });
                                            }

                                            if (sec.InformationDisclosureHeaders.Count > 0)
                                            {
                                                col.Card(card =>
                                                {
                                                    card.Header(h => h.Title("Information disclosure headers").Icon(TablerIconType.InfoCircle));
                                                    card.Body(body =>
                                                    {
                                                        var rows = sec.InformationDisclosureHeaders.Select(x => new { x.Name, x.Value }).ToList();
                                                        var t = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                                        ConfigureStandardDataTable(t, defaultMode: ToggleViewMode.ScrollX);
                                                        t.EnablePaging(10, new[] { 10, 25, 50 })
                                                            .EnableSearching()
                                                            .EnableOrdering();
                                                    });
                                                });
                                            }

                                            if (sec.CachingHeaders.Count > 0)
                                            {
                                                col.Card(card =>
                                                {
                                                    card.Header(h => h.Title("Caching headers").Icon(TablerIconType.Clock));
                                                    card.Body(body =>
                                                    {
                                                        var rows = sec.CachingHeaders.Select(x => new { x.Name, x.Value }).ToList();
                                                        var t = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                                        ConfigureStandardDataTable(t, defaultMode: ToggleViewMode.ScrollX);
                                                        t.EnablePaging(10, new[] { 10, 25, 50 })
                                                            .EnableSearching()
                                                            .EnableOrdering();
                                                    });
                                                });
                                            }

                                            if (sec.DeprecatedPresent.Count > 0 || sec.DeprecatedMissing.Count > 0)
                                            {
                                                col.Card(card =>
                                                {
                                                    card.Header(h => h.Title("Deprecated header signals").Icon(TablerIconType.AlertCircle));
                                                    card.Body(body =>
                                                    {
                                                        if (sec.DeprecatedPresent.Count > 0)
                                                        {
                                                            body.Text("Deprecated headers present:").Style(TablerTextStyle.Muted);
                                                            var list = body.TablerList();
                                                            foreach (var d in sec.DeprecatedPresent) list.AddItem(d, TablerIconType.AlertCircle);
                                                        }
                                                        if (sec.DeprecatedMissing.Count > 0)
                                                        {
                                                            body.Text("Deprecated headers missing:").Style(TablerTextStyle.Muted);
                                                            var list = body.TablerList();
                                                            foreach (var d in sec.DeprecatedMissing) list.AddItem(d, TablerIconType.InfoCircle);
                                                        }
                                                    });
                                                });
                                            }
                                        }

                                        // Misc evidence
                                        if (!string.IsNullOrWhiteSpace(http.Nel) || !string.IsNullOrWhiteSpace(http.ReportTo) || !string.IsNullOrWhiteSpace(http.SpeculationRules))
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Additional headers").Icon(TablerIconType.FileText));
                                                card.Body(body =>
                                                {
                                                    var rows = new List<(string Key, string Value)>();
                                                    if (!string.IsNullOrWhiteSpace(http.Nel)) rows.Add(("NEL", http.Nel!));
                                                    if (!string.IsNullOrWhiteSpace(http.ReportTo)) rows.Add(("Report-To", http.ReportTo!));
                                                    if (!string.IsNullOrWhiteSpace(http.SpeculationRules)) rows.Add(("Speculation-Rules", http.SpeculationRules!));
                                                    var kvRows = rows.Select(x => new { x.Key, x.Value }).ToList();
                                                    var kvTable = (TablerTable)body.Table(kvRows, TableType.Tabler);
                                                    kvTable.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
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
