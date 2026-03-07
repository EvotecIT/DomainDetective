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
    private static void RenderTlsRptReportsSection(TablerAccordion acc, DomainBucket b)
    {
        var reports = b.TlsRptReports;
        if (reports == null)
        {
            return;
        }

        var narrative = DomainDetective.Narratives.TlsRptReportsNarrative.Build(reports.Subject);
        acc.AddItem("TLS-RPT Reports", item =>
        {
            item.Icon(TablerIconType.ChartBar);
            item.HeaderRight(c =>
            {
                c.Badge(reports.ErrorCount > 0 ? $"{reports.ErrorCount} Error" + (reports.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(reports.WarningCount > 0 ? $"{reports.WarningCount} Warning" + (reports.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(reports.Status ?? "Unknown", ColorForStatus(reports.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content =>
            {
                content.Row(r =>
                {
                    r.Column(TablerColumnNumber.Twelve, c2 =>
                    {
                        var help = b.Mx?.ProviderHelp ?? b.Spf?.ProviderHelp;
                        var findingsCount = reports.WarningCount + reports.ErrorCount;
                        var findingsBadgeColor = reports.ErrorCount > 0
                            ? TablerBadgeColor.Danger
                            : (reports.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);
                        var refs = MergeReferences(reports.References, narrative?.References);

                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                            AddGridPanelUnique(g, seen, "Status", reports.Status ?? "-", PanelColorForStatus(reports.Status), light: true);
                            AddGridPanelUnique(g, seen, "Reports", reports.SnapshotCount.ToString());
                            AddGridPanelUnique(g, seen, "OK Sessions", reports.TotalSuccessfulSessions.ToString());
                            AddGridPanelUnique(g, seen, "Failed Sessions", reports.TotalFailedSessions.ToString(), reports.TotalFailedSessions > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            AddGridPanelUnique(g, seen, "Fail %", (reports.TotalSuccessfulSessions + reports.TotalFailedSessions) > 0 ? reports.FailureRatePercent.ToString("0.0") : "-");

                            if (reports.TopFailureTypes != null && reports.TopFailureTypes.Count > 0)
                            {
                                var top = string.Join(", ", reports.TopFailureTypes.Take(3).Select(x => $"{x.Key}={x.Count}"));
                                if (!string.IsNullOrWhiteSpace(top))
                                {
                                    AddGridPanelUnique(g, seen, "Top failures", top);
                                }
                            }
                        });

                        RenderGuidanceWizardCard(c2, narrative, help, new[] { "TLS-RPT" }, refs);

                        var positives = (reports.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
                            .Select(p => p?.Title ?? p?.Code)
                            .Where(s => !string.IsNullOrWhiteSpace(s))
                            .Select(s => s!)
                            .ToList();
                        var findingsAssessments = (reports.Assessments ?? Array.Empty<Assessment>())
                            .Where(a => a != null && a.Severity != AssessmentSeverity.Info)
                            .ToList();

                        RenderResultsTabsCard(c2, tabs =>
                        {
                            tabs.AddTab("Summary", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderSignalsSummary(col, narrative?.Highlights, positives);
                                }));
                            }).WithIcon(TablerIconType.Cards);

                            var findingsTab = tabs.AddTab("Findings", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderFindingsFromAssessments(col, findingsAssessments);
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

                                    if (reports.Daily != null && reports.Daily.Count > 0)
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("Daily Trend").Icon(TablerIconType.ChartBar));
                                            card.Body(body =>
                                            {
                                                var rows = reports.Daily
                                                    .OrderBy(x => x.DateUtc)
                                                    .Select(x => new
                                                    {
                                                        Date = x.DateUtc.ToString("yyyy-MM-dd"),
                                                        Ok = x.SuccessfulSessions,
                                                        Fail = x.FailedSessions,
                                                        FailPct = x.FailureRatePercent.ToString("0.0")
                                                    })
                                                    .ToList();
                                                var t = (TablerTable)body.Table(rows, TableType.Tabler);
                                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                            });
                                        });
                                    }

                                    if (reports.TopFailureTypes != null && reports.TopFailureTypes.Count > 0)
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("Top failure types").Icon(TablerIconType.ListDetails));
                                            card.Body(body =>
                                            {
                                                var rows = reports.TopFailureTypes.Select(x => new { x.Key, x.Count }).ToList();
                                                var t = (TablerTable)body.Table(rows, TableType.Tabler);
                                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                            });
                                        });
                                    }

                                    if (reports.MxHosts != null && reports.MxHosts.Count > 0)
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("Top affected MX hosts").Icon(TablerIconType.Mail));
                                            card.Body(body =>
                                            {
                                                var rows = reports.MxHosts
                                                    .OrderByDescending(x => x.FailedSessions)
                                                    .ThenBy(x => x.MxHost, StringComparer.OrdinalIgnoreCase)
                                                    .Take(20)
                                                    .Select(x => new
                                                    {
                                                        x.MxHost,
                                                        Ok = x.SuccessfulSessions,
                                                        Fail = x.FailedSessions,
                                                        TopFailures = string.Join(", ", (x.FailureByType ?? new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase))
                                                            .OrderByDescending(kv => kv.Value)
                                                            .Take(3)
                                                            .Select(kv => $"{kv.Key}={kv.Value}"))
                                                    })
                                                    .ToList();
                                                var t = (TablerTable)body.Table(rows, TableType.Tabler);
                                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                            });
                                        });
                                    }

                                    if (!hasEvidence)
                                    {
                                        col.Text("No evidence captured for this section.").Style(TablerTextStyle.Muted);
                                    }
                                }));
                            }).WithIcon(TablerIconType.FileText);
                        });
                    });
                });
            });
        });
    }

    private static void RenderRegistrationSection(TablerAccordion acc, DomainBucket b)
    {
        var reg = b.Registration;
        if (reg == null)
        {
            return;
        }

        var narrative = DomainDetective.Narratives.RegistrationNarrative.Build(reg.Subject);
        acc.AddItem("Registration", item =>
        {
            item.Icon(TablerIconType.Fingerprint);
            item.HeaderRight(c =>
            {
                c.Badge(reg.ErrorCount > 0 ? $"{reg.ErrorCount} Error" + (reg.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(reg.WarningCount > 0 ? $"{reg.WarningCount} Warning" + (reg.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(reg.Status ?? "Unknown", ColorForStatus(reg.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content =>
            {
                content.Row(r =>
                {
                    r.Column(TablerColumnNumber.Twelve, c2 =>
                    {
                        var findingsCount = reg.WarningCount + reg.ErrorCount;
                        var findingsBadgeColor = reg.ErrorCount > 0
                            ? TablerBadgeColor.Danger
                            : (reg.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);
                        var refs = MergeReferences(reg.References, narrative?.References);

                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                            AddGridPanelUnique(g, seen, "Status", reg.Status ?? "-", PanelColorForStatus(reg.Status), light: true);
                            AddGridPanelUnique(g, seen, "Snapshots", reg.SnapshotCount.ToString());

                            if (reg.Current != null)
                            {
                                AddGridPanelUnique(g, seen, "Captured (UTC)", reg.Current.CapturedAtUtc.UtcDateTime.ToString("u"));
                                AddGridPanelUnique(g, seen, "Registrar", reg.Current.Registrar ?? "-");
                                var exp = reg.Current.ExpiresAtUtc?.UtcDateTime.ToString("u") ?? reg.Current.ExpiresAtRaw ?? "-";
                                AddGridPanelUnique(g, seen, "Expires", exp);
                                AddGridPanelUnique(g, seen, "RDAP", reg.Current.HasRdap ? "Yes" : "No");
                                AddGridPanelUnique(g, seen, "WHOIS", reg.Current.HasWhois ? "Yes" : "No");
                                if (reg.Current.RegistrarLocked.HasValue)
                                {
                                    AddGridPanelUnique(g, seen, "Registrar lock", reg.Current.RegistrarLocked.Value ? "Yes" : "No");
                                }
                                if (reg.Current.PrivacyProtected.HasValue)
                                {
                                    AddGridPanelUnique(g, seen, "Privacy", reg.Current.PrivacyProtected.Value ? "Yes" : "No");
                                }
                            }

                            var changes = reg.Drift?.Changes?.Count ?? 0;
                            AddGridPanelUnique(g, seen, "Changes", changes.ToString(), changes > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                        });

                        RenderGuidanceWizardCard(c2, narrative, null, new[] { "Registration" }, refs);

                        var positives = (reg.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
                            .Select(p => p?.Title ?? p?.Code)
                            .Where(s => !string.IsNullOrWhiteSpace(s))
                            .Select(s => s!)
                            .ToList();
                        var findingsAssessments = (reg.Assessments ?? Array.Empty<Assessment>())
                            .Where(a => a != null && a.Severity != AssessmentSeverity.Info)
                            .ToList();

                        RenderResultsTabsCard(c2, tabs =>
                        {
                            tabs.AddTab("Summary", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderSignalsSummary(col, narrative?.Highlights, positives);
                                }));
                            }).WithIcon(TablerIconType.Cards);

                            var findingsTab = tabs.AddTab("Findings", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderFindingsFromAssessments(col, findingsAssessments);
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

                                    if (reg.Current != null)
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("Current snapshot").Icon(TablerIconType.FileText));
                                            card.Body(body =>
                                            {
                                                var snapRows = new List<object>
                                                {
                                                    new { Key = "Registrar", Value = reg.Current.Registrar ?? "-" },
                                                    new { Key = "Registrar ID", Value = reg.Current.RegistrarId ?? "-" },
                                                    new { Key = "Created (UTC)", Value = reg.Current.CreatedAtUtc?.UtcDateTime.ToString("u") ?? reg.Current.CreatedAtRaw ?? "-" },
                                                    new { Key = "Updated (UTC)", Value = reg.Current.UpdatedAtUtc?.UtcDateTime.ToString("u") ?? reg.Current.UpdatedAtRaw ?? "-" },
                                                    new { Key = "Expires (UTC)", Value = reg.Current.ExpiresAtUtc?.UtcDateTime.ToString("u") ?? reg.Current.ExpiresAtRaw ?? "-" },
                                                    new { Key = "RDAP available", Value = reg.Current.HasRdap ? "Yes" : "No" },
                                                    new { Key = "WHOIS available", Value = reg.Current.HasWhois ? "Yes" : "No" },
                                                    new { Key = "WHOIS server", Value = reg.Current.WhoisServerUsed ?? "-" },
                                                    new { Key = "WHOIS lookup source", Value = reg.Current.WhoisLookupSource ?? "-" }
                                                };
                                                if (reg.Current.RegistrarLocked.HasValue)
                                                {
                                                    snapRows.Add(new { Key = "Registrar lock", Value = reg.Current.RegistrarLocked.Value ? "Yes" : "No" });
                                                }
                                                if (reg.Current.PrivacyProtected.HasValue)
                                                {
                                                    snapRows.Add(new { Key = "Privacy protected", Value = reg.Current.PrivacyProtected.Value ? "Yes" : "No" });
                                                }
                                                var t = (TablerTable)body.Table(snapRows, TableType.Tabler);
                                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                            });
                                        });

                                        if (reg.Current.NameServers != null && reg.Current.NameServers.Count > 0)
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Name servers").Icon(TablerIconType.World));
                                                card.Body(body =>
                                                {
                                                    var rows = reg.Current.NameServers
                                                        .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                                                        .Select(x => new { NameServer = x })
                                                        .ToList();
                                                    var t = (TablerTable)body.Table(rows, TableType.Tabler);
                                                    t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                                });
                                            });
                                        }

                                        if (reg.Current.Status != null && reg.Current.Status.Count > 0)
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("RDAP status").Icon(TablerIconType.ShieldCheck));
                                                card.Body(body =>
                                                {
                                                    var rows = reg.Current.Status
                                                        .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                                                        .Select(x => new { Status = x })
                                                        .ToList();
                                                    var t = (TablerTable)body.Table(rows, TableType.Tabler);
                                                    t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                                });
                                            });
                                        }
                                    }

                                    if (reg.Drift != null && reg.Drift.Changes != null && reg.Drift.Changes.Count > 0)
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("Structured drift").Icon(TablerIconType.ListDetails));
                                            card.Body(body =>
                                            {
                                                var rows = reg.Drift.Changes.Select(c => new
                                                {
                                                    Change = c.Kind.ToString(),
                                                    Before = c.Before ?? "-",
                                                    After = c.After ?? "-",
                                                    Added = c.Added != null && c.Added.Count > 0 ? string.Join(", ", c.Added.Take(10)) + (c.Added.Count > 10 ? ", …" : "") : "-",
                                                    Removed = c.Removed != null && c.Removed.Count > 0 ? string.Join(", ", c.Removed.Take(10)) + (c.Removed.Count > 10 ? ", …" : "") : "-"
                                                }).ToList();
                                                var t = (TablerTable)body.Table(rows, TableType.Tabler);
                                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                            });
                                        });
                                    }

                                    if (!hasEvidence)
                                    {
                                        col.Text("No evidence captured for this section.").Style(TablerTextStyle.Muted);
                                    }
                                }));
                            }).WithIcon(TablerIconType.FileText);
                        });
                    });
                });
            });
        });
    }

    private static void RenderNsSection(TablerAccordion acc, DomainBucket b)    
    {
        var ns = b.Ns;
        if (ns == null)
        {
            return;
        }
        var sec = SectionProjectors.BuildNs(ns);
        var narrative = ns.Raw != null ? NSNarrative.Build(ns.Raw) : null;
        acc.AddItem("NS (Authoritative)", item => {
            item.Icon(TablerIconType.Server);
            item.HeaderRight(c => {
                c.Badge(ns.ErrorCount > 0 ? $"{ns.ErrorCount} Error" + (ns.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(ns.WarningCount > 0 ? $"{ns.WarningCount} Warning" + (ns.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(ns.Status ?? "Unknown", ColorForStatus(ns.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        var findingsCount = ns.WarningCount + ns.ErrorCount;
                        var findingsBadgeColor = ns.ErrorCount > 0
                            ? TablerBadgeColor.Danger
                            : (ns.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);
                        var refs = MergeReferences(sec?.References, narrative?.References);

                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                            AddGridPanelUnique(g, seen, "Status", ns.Status ?? "-", PanelColorForStatus(ns.Status), light: true);
                            AddGridPanelUnique(g, seen, "Warnings", ns.WarningCount.ToString(), ns.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            AddGridPanelUnique(g, seen, "Errors", ns.ErrorCount.ToString(), ns.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                            if (sec != null)
                            {
                                AddGridSummaryPanelsUnique(g, seen, sec.Summary);
                            }
                        }, subtitle: "Key metrics gathered during this check.");

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
                                    var raw = ns.Raw;
                                    if (raw != null)
                                    {
                                        if (raw.NsRecords != null && raw.NsRecords.Count > 0)
                                        {
                                            hasEvidence = true;
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Child NS").Icon(TablerIconType.Server));
                                                card.Body(body =>
                                                {
                                                    var ul = body.TablerList();
                                                    foreach (var name in raw.NsRecords)
                                                    {
                                                        if (!string.IsNullOrWhiteSpace(name))
                                                        {
                                                            ul.AddItem(name, TablerIconType.Server);
                                                        }
                                                    }
                                                });
                                            });
                                        }

                                        if (raw.ParentNsRecords != null && raw.ParentNsRecords.Count > 0)
                                        {
                                            hasEvidence = true;
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Parent NS").Icon(TablerIconType.Server));
                                                card.Body(body =>
                                                {
                                                    var ul = body.TablerList();
                                                    foreach (var name in raw.ParentNsRecords)
                                                    {
                                                        if (!string.IsNullOrWhiteSpace(name))
                                                        {
                                                            ul.AddItem(name, TablerIconType.Server);
                                                        }
                                                    }
                                                });
                                            });
                                        }

                                        if (raw.RootServerResponses != null && raw.RootServerResponses.Count > 0)
                                        {
                                            hasEvidence = true;
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Root responses").Icon(TablerIconType.Table));
                                                card.Body(body =>
                                                {
                                                    var rows = raw.RootServerResponses.Select(kv => new { Server = kv.Key, Responded = kv.Value ? "Yes" : "No" }).ToList();
                                                    var t = (TablerTable)body.Table(rows, TableType.Tabler);
                                                    t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                                });
                                            });
                                        }

                                        if (raw.RecursionEnabled != null && raw.RecursionEnabled.Count > 0)
                                        {
                                            hasEvidence = true;
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Recursion status").Icon(TablerIconType.Table));
                                                card.Body(body =>
                                                {
                                                    var rows = raw.RecursionEnabled.Select(kv => new { Server = kv.Key, Recursion = kv.Value ? "Yes" : "No" }).ToList();
                                                    var t = (TablerTable)body.Table(rows, TableType.Tabler);
                                                    t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
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
                    });
                });
            });
        });
    }

}
