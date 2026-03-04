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
    private static void RenderMailTransportPostureSection(TablerAccordion acc, DomainBucket b)
    {
        if (b.Mx == null && b.SmtpTls == null && b.ImapTls == null && b.PopTls == null && b.Mtasts == null && b.TlsRpt == null && b.TlsRptReports == null && b.Dane == null)
        {
            return;
        }

        var sec = SectionProjectors.BuildMailTransportPosture(b.Mx, b.SmtpTls, b.ImapTls, b.PopTls, b.Mtasts, b.TlsRpt, b.TlsRptReports, b.Dane);
        if (sec == null)
        {
            return;
        }

        int warnCount = sec.WarningCount;
        int errCount = sec.ErrorCount;
        var status = sec.Status ?? "Unknown";
        var findingsCount = warnCount + errCount;
        var findingsBadgeColor = errCount > 0
            ? TablerBadgeColor.Danger
            : (warnCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);

        acc.AddItem("Mail Transport Posture", item =>
        {
            item.Icon(TablerIconType.Mail);
            item.HeaderRight(c =>
            {
                c.Badge(errCount > 0 ? $"{errCount} Error" + (errCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(warnCount > 0 ? $"{warnCount} Warning" + (warnCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(status, ColorForStatus(status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content =>
            {
                content.Row(r =>
                {
                    r.Column(TablerColumnNumber.Twelve, c2 =>
                    {
                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                            AddGridPanelUnique(g, seen, "Status", status, PanelColorForStatus(status), light: true);
                            AddGridPanelUnique(g, seen, "Warnings", warnCount.ToString(), warnCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            AddGridPanelUnique(g, seen, "Errors", errCount.ToString(), errCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);

                            if (b.Mx != null) AddGridPanelUnique(g, seen, "MX", b.Mx.Status ?? "-", PanelColorForStatus(b.Mx.Status), light: true);
                            if (b.SmtpTls != null) AddGridPanelUnique(g, seen, "SMTP TLS", b.SmtpTls.Status ?? "-", PanelColorForStatus(b.SmtpTls.Status), light: true);
                            if (b.ImapTls != null) AddGridPanelUnique(g, seen, "IMAP TLS", b.ImapTls.Status ?? "-", PanelColorForStatus(b.ImapTls.Status), light: true);
                            if (b.PopTls != null) AddGridPanelUnique(g, seen, "POP3 TLS", b.PopTls.Status ?? "-", PanelColorForStatus(b.PopTls.Status), light: true);
                            if (b.Mtasts != null) AddGridPanelUnique(g, seen, "MTA-STS", b.Mtasts.Status ?? "-", PanelColorForStatus(b.Mtasts.Status), light: true);
                            if (b.TlsRpt != null) AddGridPanelUnique(g, seen, "TLS-RPT", b.TlsRpt.Status ?? "-", PanelColorForStatus(b.TlsRpt.Status), light: true);
                            if (b.TlsRptReports != null) AddGridPanelUnique(g, seen, "TLS-RPT Reports", b.TlsRptReports.Status ?? "-", PanelColorForStatus(b.TlsRptReports.Status), light: true);
                            if (b.TlsRptReports != null)
                            {
                                int total = b.TlsRptReports.TotalSuccessfulSessions + b.TlsRptReports.TotalFailedSessions;
                                AddGridPanelUnique(g, seen, "TLS-RPT Fail %", total > 0 ? b.TlsRptReports.FailureRatePercent.ToString("0.0") : "-", b.TlsRptReports.TotalFailedSessions > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            }
                            if (b.Dane != null) AddGridPanelUnique(g, seen, "DANE", b.Dane.Status ?? "-", PanelColorForStatus(b.Dane.Status), light: true);
                        }, subtitle: "Roll-up of transport security signals used by mail senders when delivering email to this domain.");

                        RenderResultsTabsCard(c2, tabs =>
                        {
                            tabs.AddTab("Summary", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderSummaryGrid(col, sec.Summary);
                                }));
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderSignalsSummary(col, sec.Findings.Select(f => f.Message), sec.Positives);
                                }));
                            }).WithIcon(TablerIconType.Cards);

                            tabs.AddTab("Good Posture", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderPositives(col, sec.Positives);
                                }));
                            }).WithIcon(TablerIconType.CircleCheck);

                            var findingsTab = tabs.AddTab("Findings", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderFindings(col, sec.Findings);
                                }));
                            }).WithIcon(TablerIconType.AlertTriangle);
                            if (findingsCount > 0)
                            {
                                findingsTab.Badge(findingsCount.ToString(), findingsBadgeColor, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                            }

                            tabs.AddTab("References", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderReferences(col, sec.References);
                                }));
                            }).WithIcon(TablerIconType.Link);
                        });
                    });
                });
            });
        });
    }

    private static void RenderSpfSection(TablerAccordion acc, DomainBucket b)   
    {
        var spf = b.Spf;
        if (spf == null)
        {
            return;
        }
        var sec = SectionProjectors.BuildSpf(spf);
        acc.AddItem("SPF (Sender Policy Framework)", item => {
            item.Icon(TablerIconType.ShieldCheck);
            item.HeaderRight(c => {
                c.Badge(spf.ErrorCount > 0 ? $"{spf.ErrorCount} Error" + (spf.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(spf.WarningCount > 0 ? $"{spf.WarningCount} Warning" + (spf.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(spf.Status ?? "Unknown", ColorForStatus(spf.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content => {
                // Stable marker for tooling/tests: keep a contiguous section title in the HTML output.
                content.Add(new HtmlTag("div").ValueRaw("<!-- DD:SECTION SPF (Sender Policy Framework) -->"));

                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        var help = (spf.ProviderHelp != null && spf.ProviderHelp.Count > 0) ? spf.ProviderHelp : b.Mx?.ProviderHelp;
                        var findingsCount = spf.WarningCount + spf.ErrorCount;
                        var findingsBadgeColor = spf.ErrorCount > 0
                            ? TablerBadgeColor.Danger
                            : (spf.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);

                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                            AddGridPanelUnique(g, seen, "Status", spf.Status ?? "-", PanelColorForStatus(spf.Status), light: true);
                            AddGridPanelUnique(g, seen, "Warnings", spf.WarningCount.ToString(), spf.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            AddGridPanelUnique(g, seen, "Errors", spf.ErrorCount.ToString(), spf.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                            if (sec != null)
                            {
                                AddGridSummaryPanelsUnique(g, seen, sec.Summary);
                                if (sec.Mechanisms.Count > 0)
                                {
                                    AddGridPanelUnique(g, seen, "Mechanisms", sec.Mechanisms.Count.ToString());
                                }
                            }
                        });

                        RenderGuidanceWizardCard(c2, spf.Narrative, help, new[] { "SPF" }, sec?.References);

                        RenderResultsTabsCard(
                            c2,
                            tabs =>
                        {
                            tabs.AddTab("Summary", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderSignalsSummary(col, sec?.Highlights, sec?.Positives);
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
                                    var spfRecord = sec?.SpfRecord;
                                    bool hasRecord = !string.IsNullOrWhiteSpace(spfRecord);
                                    bool hasMechanisms = sec != null && sec.Mechanisms.Count > 0;
                                    bool hasFlattened = sec != null && (sec.FlattenedUniqueIpCount + sec.FlattenedDuplicateIpCount + sec.FlattenedTokenCount > 0);

                                    if (hasRecord)
                                    {
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("SPF Record").Icon(TablerIconType.FileText));
                                            card.Body(b =>
                                            {
                                                b.Text(spfRecord!).Style(TablerTextStyle.Monospace);
                                            });
                                        });
                                    }

                                    if (hasMechanisms)
                                    {
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("Mechanisms").Icon(TablerIconType.ListDetails));
                                            card.Body(b =>
                                            {
                                                var rows = sec!.Mechanisms.Select(m => new { m.Qualifier, m.Type, m.Value, m.Provider }).ToList();
                                                var t = (DataTablesTable)b.Table(rows, TableType.DataTables);
                                                ConfigureStandardDataTable(t);
                                                t.EnablePaging(10, new[] { 10, 25, 50 })
                                                    .EnableSearching()
                                                    .EnableOrdering();
                                            });
                                        });
                                    }

                                    if (hasFlattened)
                                    {
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("Flattened IP Analysis").Icon(TablerIconType.ChartBar));
                                            card.Body(b =>
                                            {
                                                b.DataGrid(g =>
                                                {
                                                    g.AsCompact();
                                                    g.AddItem("Unique IPs", sec!.FlattenedUniqueIpCount.ToString());
                                                    g.AddItem("Duplicate IPs", sec.FlattenedDuplicateIpCount.ToString());
                                                    g.AddItem("Tokens Resolved", sec.FlattenedTokenCount.ToString());
                                                });
                                            });
                                        });
                                    }

                                    if (!(hasRecord || hasMechanisms || hasFlattened))
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

    private static void RenderDmarcSection(TablerAccordion acc, DomainBucket b)
    {
        var dmarc = b.Dmarc;
        if (dmarc == null)
        {
            return;
        }
        var sec = SectionProjectors.BuildDmarc(dmarc);
        acc.AddItem("DMARC (Domain-based Message Authentication)", item => {
            item.Icon(TablerIconType.ShieldLock);
            item.HeaderRight(c => {
                c.Badge(dmarc.ErrorCount > 0 ? $"{dmarc.ErrorCount} Error" + (dmarc.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(dmarc.WarningCount > 0 ? $"{dmarc.WarningCount} Warning" + (dmarc.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(dmarc.Status ?? "Unknown", ColorForStatus(dmarc.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content => {
                // Stable marker for tooling/tests: keep a contiguous section title in the HTML output.
                content.Add(new HtmlTag("div").ValueRaw("<!-- DD:SECTION DMARC (Domain-based Message Authentication) -->"));

                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        var help = b.Mx?.ProviderHelp ?? b.Spf?.ProviderHelp;
                        var findingsCount = dmarc.WarningCount + dmarc.ErrorCount;
                        var findingsBadgeColor = dmarc.ErrorCount > 0
                            ? TablerBadgeColor.Danger
                            : (dmarc.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);

                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                            AddGridPanelUnique(g, seen, "Status", dmarc.Status ?? "-", PanelColorForStatus(dmarc.Status), light: true);
                            AddGridPanelUnique(g, seen, "Warnings", dmarc.WarningCount.ToString(), dmarc.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            AddGridPanelUnique(g, seen, "Errors", dmarc.ErrorCount.ToString(), dmarc.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                            if (sec != null)
                            {
                                AddGridSummaryPanelsUnique(g, seen, sec.Summary);
                            }
                        });

                        RenderGuidanceWizardCard(c2, dmarc.Narrative, help, new[] { "DMARC" }, sec?.References);

                        RenderResultsTabsCard(
                            c2,
                            tabs =>
                        {
                            tabs.AddTab("Summary", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderSignalsSummary(col, sec?.Highlights, sec?.Positives);
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
                                    var dmarcRecord = sec?.DmarcRecord;
                                    bool hasRecord = !string.IsNullOrWhiteSpace(dmarcRecord);
                                    bool hasUris = sec != null && (sec.MailtoRua.Count + sec.HttpRua.Count + sec.MailtoRuf.Count + sec.HttpRuf.Count > 0);

                                    if (hasRecord)
                                    {
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("DMARC Record").Icon(TablerIconType.FileText));
                                            card.Body(b => b.Text(dmarcRecord!).Style(TablerTextStyle.Monospace));
                                        });
                                    }

                                    if (hasUris)
                                    {
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("Reporting URIs").Icon(TablerIconType.Mail));
                                            card.Body(b =>
                                            {
                                                if (sec!.MailtoRua.Count + sec.HttpRua.Count > 0)
                                                {
                                                    b.Text("Aggregate (RUA)").Style(TablerTextStyle.Muted);
                                                    var rua = sec.MailtoRua.Select(x => new { Scheme = "mailto", Uri = x })
                                                        .Concat(sec.HttpRua.Select(x => new { Scheme = "http", Uri = x })).ToList();
                                                    var t = (TablerTable)b.Table(rua, TableType.Tabler);
                                                    t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                                }
                                                if (sec.MailtoRuf.Count + sec.HttpRuf.Count > 0)
                                                {
                                                    b.Text("Forensic (RUF)").Style(TablerTextStyle.Muted);
                                                    var ruf = sec.MailtoRuf.Select(x => new { Scheme = "mailto", Uri = x })
                                                        .Concat(sec.HttpRuf.Select(x => new { Scheme = "http", Uri = x })).ToList();
                                                    var t2 = (TablerTable)b.Table(ruf, TableType.Tabler);
                                                    t2.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                                }
                                            });
                                        });
                                    }

                                    if (!(hasRecord || hasUris))
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

    private static void RenderDmarcAggregateSection(TablerAccordion acc, DomainBucket b)
    {
        var agg = b.DmarcAggregate;
        if (agg == null)
        {
            return;
        }

        var narrative = DomainDetective.Narratives.DmarcAggregateNarrative.Build(agg.Subject);
        acc.AddItem("DMARC Aggregate", item =>
        {
            item.Icon(TablerIconType.ChartBar);
            item.HeaderRight(c =>
            {
                c.Badge(agg.ErrorCount > 0 ? $"{agg.ErrorCount} Error" + (agg.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(agg.WarningCount > 0 ? $"{agg.WarningCount} Warning" + (agg.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(agg.Status ?? "Unknown", ColorForStatus(agg.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content =>
            {
                content.Row(r =>
                {
                    r.Column(TablerColumnNumber.Twelve, c2 =>
                    {
                        var help = b.Mx?.ProviderHelp ?? b.Spf?.ProviderHelp;
                        var findingsCount = agg.WarningCount + agg.ErrorCount;
                        var findingsBadgeColor = agg.ErrorCount > 0
                            ? TablerBadgeColor.Danger
                            : (agg.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);
                        var refs = MergeReferences(agg.References, narrative?.References);

                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                            AddGridPanelUnique(g, seen, "Status", agg.Status ?? "-", PanelColorForStatus(agg.Status), light: true);
                            AddGridPanelUnique(g, seen, "Reports", agg.SnapshotCount.ToString());
                            AddGridPanelUnique(g, seen, "Messages", agg.TotalCount.ToString());
                            AddGridPanelUnique(g, seen, "Pass %", agg.TotalCount > 0 ? agg.PassRatePercent.ToString("0.0") : "-");
                            AddGridPanelUnique(g, seen, "Fail", agg.FailCount.ToString(), agg.FailCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);

                            if (agg.DispositionCounts != null && agg.DispositionCounts.Count > 0)
                            {
                                var top = string.Join(", ", agg.DispositionCounts
                                    .OrderByDescending(kv => kv.Value)
                                    .Take(3)
                                    .Select(kv => $"{kv.Key}={kv.Value}"));
                                if (!string.IsNullOrWhiteSpace(top))
                                {
                                    AddGridPanelUnique(g, seen, "Disposition (top)", top);
                                }
                            }
                        });

                        RenderGuidanceWizardCard(c2, narrative, help, new[] { "DMARC" }, refs);

                        var positives = (agg.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
                            .Select(p => p?.Title ?? p?.Code)
                            .Where(s => !string.IsNullOrWhiteSpace(s))
                            .Select(s => s!)
                            .ToList();
                        var findingsAssessments = (agg.Assessments ?? Array.Empty<Assessment>())
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

                                    if (agg.Daily != null && agg.Daily.Count > 0)
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("Daily Trend").Icon(TablerIconType.ChartBar));
                                            card.Body(body =>
                                            {
                                                var rows = agg.Daily
                                                    .OrderBy(x => x.DateUtc)
                                                    .Select(x => new
                                                    {
                                                        Date = x.DateUtc.ToString("yyyy-MM-dd"),
                                                        Total = x.TotalCount,
                                                        Pass = x.PassCount,
                                                        Fail = x.FailCount,
                                                        PassPct = x.PassRatePercent.ToString("0.0")
                                                    })
                                                    .ToList();
                                                var t = (TablerTable)body.Table(rows, TableType.Tabler);
                                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                            });
                                        });
                                    }

                                    void RenderTop(string title, IReadOnlyList<NamedCount>? items)
                                    {
                                        if (items == null || items.Count == 0) return;
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title(title).Icon(TablerIconType.ListDetails));
                                            card.Body(body =>
                                            {
                                                var rows = items.Select(x => new { x.Key, x.Count }).ToList();
                                                var t = (TablerTable)body.Table(rows, TableType.Tabler);
                                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                            });
                                        });
                                    }

                                    RenderTop("Top failing source IPs", agg.TopFailingSourceIps);
                                    RenderTop("Top failing header-from", agg.TopFailingHeaderFrom);
                                    RenderTop("Top failing DKIM domains", agg.TopFailingDkimDomains);
                                    RenderTop("Top failing SPF domains", agg.TopFailingSpfDomains);

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

    private static void RenderDkimSection(TablerAccordion acc, DomainBucket b)
    {
        if (b.Dkim.Count == 0)
        {
            return;
        }
        var sec = SectionProjectors.BuildDkim(b.Dkim, b.Ttl);
        var narrative = b.Dkim.FirstOrDefault()?.Narrative;
        acc.AddItem("DKIM (DomainKeys Identified Mail)", item => {
            item.Icon(TablerIconType.Key);
            item.HeaderRight(c => {
                var err = b.Dkim.Sum(x => x?.ErrorCount ?? 0);
                var warn = b.Dkim.Sum(x => x?.WarningCount ?? 0);
                c.Badge(err > 0 ? $"{err} Error" + (err > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(warn > 0 ? $"{warn} Warning" + (warn > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        var errCount = b.Dkim.Sum(x => x?.ErrorCount ?? 0);
                        var warnCount = b.Dkim.Sum(x => x?.WarningCount ?? 0);
                        var selectors = b.Dkim.Where(d => d != null).ToList();
                        var missing = selectors.Count(x => !x.DkimRecordExists);
                        var weak = selectors.Count(x => x.WeakKey);
                        var old = selectors.Count(x => x.OldKey);
                        var invalid = selectors.Count(x => !x.ValidPublicKey || !x.ValidKeyType || !x.ValidRsaKeyLength);
                        var help = b.Mx?.ProviderHelp ?? b.Spf?.ProviderHelp;
                        var findingsCount = warnCount + errCount;
                        var findingsBadgeColor = errCount > 0
                            ? TablerBadgeColor.Danger
                            : (warnCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);

                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            g.AddItem("Warnings", warnCount.ToString()).AsPanel(warnCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            g.AddItem("Errors", errCount.ToString()).AsPanel(errCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                            g.AddItem("Selectors", selectors.Count.ToString()).AsPanel(TablerColor.Blue, light: true);
                            g.AddItem("Missing", missing.ToString()).AsPanel(missing > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                            g.AddItem("Weak keys", weak.ToString()).AsPanel(weak > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            g.AddItem("Old keys", old.ToString()).AsPanel(old > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            g.AddItem("Invalid", invalid.ToString()).AsPanel(invalid > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                        });

                        RenderGuidanceWizardCard(c2, narrative, help, new[] { "DKIM" }, sec?.References);

                        RenderResultsTabsCard(
                            c2,
                            tabs =>
                        {
                            tabs.AddTab("Summary", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderSignalsSummary(col, sec?.Highlights, sec?.Positives);
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
                                    if (sec != null && sec.Rows.Count > 0)
                                    {
                                        var rows = sec.Rows.Select(k => new
                                        {
                                            Selector = k.Selector,
                                            Status = k.Status,
                                            Key = string.IsNullOrEmpty(k.KeyBits) ? "-" : (k.KeyBits + " bits"),
                                            Alg = string.IsNullOrEmpty(k.Hash) ? "?" : k.Hash,
                                            Weak = k.Weak ? "Yes" : "No",
                                            Flags = k.Flags,
                                            TTL = k.TtlSeconds?.ToString() ?? "-",
                                            CnameResolved = k.CnameResolved ? "Yes" : "No",
                                            CnameTtl = k.CnameTtlSeconds?.ToString() ?? "-"
                                        }).ToList();

                                        var table = (DataTablesTable)col.Table(rows, TableType.DataTables);
                                        ConfigureStandardDataTable(table, defaultMode: ToggleViewMode.ScrollX);
                                        table.EnablePaging(10, new[] { 10, 25, 50 }).EnableSearching().EnableOrdering();
                                        table.HighlightWhen(
                                            where: g => g.Or(c => { c.StringContains("Status", "error", false); c.StringContains("Status", "fail", false); }),  
                                            then: t => t.Column("Status").Danger());
                                        table.HighlightWhen(
                                            where: g => g.Or(c => { c.StringContains("Status", "warn", false); }),
                                            then: t => t.Column("Status").Warning());
                                    }

                                    if (sec != null && sec.Rows.Any(r => !string.IsNullOrWhiteSpace(r.Record)))
                                    {
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("Records").Icon(TablerIconType.Key));
                                            card.Body(body =>
                                            {
                                                foreach (var r2 in sec.Rows.Where(r => !string.IsNullOrWhiteSpace(r.Record)))
                                                {
                                                    body.Text($"Selector {r2.Selector}").Style(TablerTextStyle.Muted);
                                                    body.Text(r2.Record).Style(TablerTextStyle.Monospace);
                                                }
                                            });
                                        });
                                    }

                                    if (sec == null || (sec.Rows.Count == 0 && !sec.Rows.Any(r => !string.IsNullOrWhiteSpace(r.Record))))
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
