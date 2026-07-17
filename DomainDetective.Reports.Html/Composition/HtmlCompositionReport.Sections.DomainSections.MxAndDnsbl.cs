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
    private static void RenderMxSection(TablerAccordion acc, DomainBucket b)
    {
        var mx = b.Mx;
        if (mx == null)
        {
            return;
        }
        var sec = SectionProjectors.BuildMx(mx, b.SmtpTls, b.ImapTls, b.PopTls);
        var narrative = mx.Raw != null ? MxNarrative.Build(mx.Raw) : null;
        acc.AddItem("MX (Mail Exchanger)", item => {
            item.Icon(TablerIconType.Mail);
            item.HeaderRight(c => {
                c.Badge(mx.ErrorCount > 0 ? $"{mx.ErrorCount} Error" + (mx.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(mx.WarningCount > 0 ? $"{mx.WarningCount} Warning" + (mx.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(mx.Status ?? "Unknown", ColorForStatus(mx.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content => {
                // Stable marker for tooling/tests: keep a contiguous section title in the HTML output.
                content.Add(new HtmlComment(" DD:SECTION MX (Mail Exchanger) "));

                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        var helpTopics = new[] { "DMARC", "SPF", "DKIM", "MTA-STS", "TLS-RPT", "Deliverability" };
                        var findingsCount = mx.WarningCount + mx.ErrorCount;
                        var findingsBadgeColor = mx.ErrorCount > 0
                            ? TablerBadgeColor.Danger
                            : (mx.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);
                        var refs = MergeReferences(sec?.References, narrative?.References);

                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                            AddGridPanelUnique(g, seen, "Status", mx.Status ?? "-", PanelColorForStatus(mx.Status), light: true);
                            AddGridPanelUnique(g, seen, "Warnings", mx.WarningCount.ToString(), mx.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            AddGridPanelUnique(g, seen, "Errors", mx.ErrorCount.ToString(), mx.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                            if (sec != null)
                            {
                                if (sec.Records.Count > 0)
                                {
                                    AddGridPanelUnique(g, seen, "MX Records", sec.Records.Count.ToString());
                                }

                                AddGridSummaryPanelsUnique(g, seen, sec.Summary);
                            }
                        });

                        RenderGuidanceWizardCard(c2, narrative, mx.ProviderHelp, helpTopics, refs);

                        RenderResultsTabsCard(c2, tabs =>
                        {
                            tabs.AddTab("Summary", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderSignalsSummary(col, narrative?.Highlights, sec?.Positives);
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
                                    if (sec != null && sec.Records.Count > 0)
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("MX Records").Icon(TablerIconType.Mail));
                                            card.Body(body =>
                                            {
                                                var rows = sec.Records.Select(r2 => new { Host = r2 }).ToList();
                                                var t = (TablerTable)body.Table(rows, TableType.Tabler);
                                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                            });
                                        });
                                    }

                                    if (!string.IsNullOrWhiteSpace(sec?.MailTlsSmtp) || !string.IsNullOrWhiteSpace(sec?.MailTlsImap) || !string.IsNullOrWhiteSpace(sec?.MailTlsPop))
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("MailTLS").Icon(TablerIconType.Lock));
                                            card.Body(body =>
                                            {
                                                var rows = new List<object>
                                                {
                                                    new { Service = "SMTP", Status = sec?.MailTlsSmtp ?? "-" },
                                                    new { Service = "IMAP", Status = sec?.MailTlsImap ?? "-" },
                                                    new { Service = "POP3", Status = sec?.MailTlsPop ?? "-" }
                                                };
                                                var t = (TablerTable)body.Table(rows, TableType.Tabler);
                                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                            });
                                        });
                                    }

                                    var raw = mx.Raw;
                                    if (raw != null && ((raw.MxRecords?.Count ?? 0) > 0 || (raw.MxRecordTtls?.Count ?? 0) > 0))
                                    {
                                        hasEvidence = true;
                                        if (raw.MxRecords != null && raw.MxRecords.Count > 0)
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("MX Records (raw)").Icon(TablerIconType.FileText));
                                                card.Body(body =>
                                                {
                                                    foreach (var rr2 in raw.MxRecords)
                                                    {
                                                        if (!string.IsNullOrWhiteSpace(rr2))
                                                        {
                                                            body.Text(rr2).Style(TablerTextStyle.Monospace);
                                                        }
                                                    }
                                                });
                                            });
                                        }
                                        if (raw.MxRecordTtls != null && raw.MxRecordTtls.Count > 0)
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("TTL (seconds)").Icon(TablerIconType.Clock));
                                                card.Body(body =>
                                                {
                                                    body.Text(string.Join(", ", raw.MxRecordTtls)).Style(TablerTextStyle.Monospace);
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

    private static void RenderArcSection(TablerAccordion acc, DomainBucket b)
    {
        var arc = b.Arc;
        if (arc == null)
        {
            return;
        }
        acc.AddItem("ARC (Authenticated Received Chain)", item => {
            item.Icon(TablerIconType.Link);
            item.HeaderRight(c => {
                c.Badge(arc.ErrorCount > 0 ? $"{arc.ErrorCount} Error" + (arc.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(arc.WarningCount > 0 ? $"{arc.WarningCount} Warning" + (arc.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(arc.Status ?? "Unknown", ColorForStatus(arc.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        var help = b.Mx?.ProviderHelp ?? b.Spf?.ProviderHelp;
                        var findingsCount = arc.WarningCount + arc.ErrorCount;
                        var findingsBadgeColor = arc.ErrorCount > 0
                            ? TablerBadgeColor.Danger
                            : (arc.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);
                        var positives = (arc.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
                            .Select(p => p?.Title ?? p?.Code)
                            .Where(t => !string.IsNullOrWhiteSpace(t))
                            .Select(t => t!.Trim())
                            .ToList();
                        var refs = MergeReferences(arc.References, arc.Narrative?.References);

                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            g.AddItem("Status", arc.Status ?? "-").AsPanel(PanelColorForStatus(arc.Status), light: true);
                            g.AddItem("Warnings", arc.WarningCount.ToString()).AsPanel(arc.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            g.AddItem("Errors", arc.ErrorCount.ToString()).AsPanel(arc.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                            g.AddItem("Headers present", arc.ArcHeadersFound ? "Yes" : "No").AsPanel();
                            g.AddItem("ARC-Seal", arc.SealCount.ToString()).AsPanel();
                            g.AddItem("ARC-Auth-Results", arc.AarCount.ToString()).AsPanel();
                            g.AddItem("Chain", arc.ChainState ?? "-").AsPanel();
                        });

                        RenderGuidanceWizardCard(c2, arc.Narrative, help, new[] { "ARC" }, refs);

                        RenderResultsTabsCard(c2, tabs =>
                        {
                            tabs.AddTab("Summary", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderSignalsSummary(col, arc.Highlights, positives);
                                }));
                            }).WithIcon(TablerIconType.Cards);

                            var findingsTab = tabs.AddTab("Findings", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderFindingsFromAssessments(col, arc.Assessments);
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
                                    var raw = arc.Raw;
                                    if (raw == null)
                                    {
                                        col.Text("No evidence captured for this section.").Style(TablerTextStyle.Muted);
                                        return;
                                    }
                                    const int maxHeaders = 5;

                                    if (raw.ArcSealHeaders.Count > 0)
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("ARC-Seal values").Icon(TablerIconType.Key));
                                            card.Body(body =>
                                            {
                                                foreach (var header in raw.ArcSealHeaders.Take(maxHeaders))
                                                {
                                                    if (!string.IsNullOrWhiteSpace(header))
                                                    {
                                                        body.Text(header).Style(TablerTextStyle.Monospace);
                                                    }
                                                }
                                                if (raw.ArcSealHeaders.Count > maxHeaders)
                                                {
                                                    body.Text($"+{raw.ArcSealHeaders.Count - maxHeaders} more").Style(TablerTextStyle.Muted);
                                                }
                                            });
                                        });
                                    }

                                    if (raw.ArcAuthenticationResultsHeaders.Count > 0)
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("ARC-Authentication-Results values").Icon(TablerIconType.FileText));
                                            card.Body(body =>
                                            {
                                                foreach (var header in raw.ArcAuthenticationResultsHeaders.Take(maxHeaders))
                                                {
                                                    if (!string.IsNullOrWhiteSpace(header))
                                                    {
                                                        body.Text(header).Style(TablerTextStyle.Monospace);
                                                    }
                                                }
                                                if (raw.ArcAuthenticationResultsHeaders.Count > maxHeaders)
                                                {
                                                    body.Text($"+{raw.ArcAuthenticationResultsHeaders.Count - maxHeaders} more").Style(TablerTextStyle.Muted);
                                                }
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

    private static void RenderBimiSection(TablerAccordion acc, DomainBucket b)
    {
        var bimi = b.Bimi;
        if (bimi == null)
        {
            return;
        }
        var narrative = bimi.Raw != null ? BimiNarrative.Build(bimi.Raw) : null;
        acc.AddItem("BIMI (Brand Indicators)", item => {
            item.Icon(TablerIconType.Photo);
            item.HeaderRight(c => {
                c.Badge(bimi.ErrorCount > 0 ? $"{bimi.ErrorCount} Error" + (bimi.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(bimi.WarningCount > 0 ? $"{bimi.WarningCount} Warning" + (bimi.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(bimi.Status ?? "Unknown", ColorForStatus(bimi.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        var help = b.Mx?.ProviderHelp ?? b.Spf?.ProviderHelp;
                        var findingsCount = bimi.WarningCount + bimi.ErrorCount;
                        var findingsBadgeColor = bimi.ErrorCount > 0
                            ? TablerBadgeColor.Danger
                            : (bimi.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);
                        var positives = (bimi.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
                            .Select(p => p?.Title ?? p?.Code)
                            .Where(t => !string.IsNullOrWhiteSpace(t))
                            .Select(t => t!.Trim())
                            .ToList();
                        var refs = MergeReferences(bimi.References, narrative?.References);

                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            g.AddItem("Status", bimi.Status ?? "-").AsPanel(PanelColorForStatus(bimi.Status), light: true);
                            g.AddItem("Warnings", bimi.WarningCount.ToString()).AsPanel(bimi.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            g.AddItem("Errors", bimi.ErrorCount.ToString()).AsPanel(bimi.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                            g.AddItem("Record present", bimi.BimiRecordExists ? "Yes" : "No").AsPanel();
                            g.AddItem("SVG valid", bimi.SvgValid ? "Yes" : "No").AsPanel();
                            g.AddItem("VMC present", bimi.ValidVmc ? "Yes" : "No").AsPanel();
                            g.AddItem("VMC trusted", bimi.ValidVmc ? (bimi.VmcSignedByKnownRoot ? "Yes" : "Untrusted") : "-").AsPanel();
                            g.AddItem("Declined (p=reject)", bimi.DeclinedToPublish ? "Yes" : "No").AsPanel();
                        });

                        RenderGuidanceWizardCard(c2, narrative, help, new[] { "BIMI" }, refs);

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
                                    RenderFindingsFromAssessments(col, bimi.Assessments);
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
                                    var raw = bimi.Raw;

                                    if (!string.IsNullOrWhiteSpace(bimi.BimiRecord))
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("BIMI Record").Icon(TablerIconType.FileText));
                                            card.Body(body =>
                                            {
                                                body.Text(bimi.BimiRecord).Style(TablerTextStyle.Monospace);
                                                if (!string.IsNullOrWhiteSpace(bimi.Location))
                                                {
                                                    body.Text($"Location: {bimi.Location}");
                                                }
                                                if (!string.IsNullOrWhiteSpace(bimi.Authority))
                                                {
                                                    body.Text($"Authority: {bimi.Authority}");
                                                }
                                                if (!bimi.SvgValid && !string.IsNullOrWhiteSpace(bimi.SvgInvalidReason))
                                                {
                                                    body.Text($"SVG invalid: {bimi.SvgInvalidReason}");
                                                }
                                            });
                                        });
                                    }

                                    if (raw != null && !string.IsNullOrWhiteSpace(raw.FailureReason))
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("Failure").Icon(TablerIconType.AlertTriangle));
                                            card.Body(body => body.Text(raw.FailureReason ?? string.Empty));
                                        });
                                    }

                                    if (raw?.VmcCertificate != null)
                                    {
                                        hasEvidence = true;
                                        var cert = raw.VmcCertificate;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("VMC Certificate").Icon(TablerIconType.Certificate));
                                            card.Body(body =>
                                            {
                                                body.DataGrid(g =>
                                                {
                                                    g.AsCompact();
                                                    g.AddItem("Subject", cert.Subject ?? "-");
                                                    g.AddItem("Issuer", cert.Issuer ?? "-");
                                                    g.AddItem("Valid from", cert.NotBefore.ToString("yyyy-MM-dd"));
                                                    g.AddItem("Valid to", cert.NotAfter.ToString("yyyy-MM-dd"));
                                                    g.AddItem("Serial", cert.SerialNumber ?? "-");
                                                });
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

    private static void RenderDnsblSection(TablerAccordion acc, DomainBucket b)
    {
        var dnsbl = b.Dnsbl;
        if (dnsbl == null)
        {
            return;
        }
        var sec = SectionProjectors.BuildDnsbl(dnsbl);
        var narrative = DnsblNarrative.Build(dnsbl.Raw, dnsbl.Assessments);     
        var summaries = dnsbl.HostSummaries ?? Array.Empty<DnsblHostSummary>(); 
        acc.AddItem("DNSBL (Reputation)", item => {
            item.Icon(TablerIconType.ListCheck);
            item.HeaderRight(c => {
                c.Badge(dnsbl.ErrorCount > 0 ? $"{dnsbl.ErrorCount} Error" + (dnsbl.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(dnsbl.WarningCount > 0 ? $"{dnsbl.WarningCount} Warning" + (dnsbl.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(dnsbl.Status ?? "Unknown", ColorForStatus(dnsbl.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        var findingsCount = dnsbl.WarningCount + dnsbl.ErrorCount;
                        var findingsBadgeColor = dnsbl.ErrorCount > 0
                            ? TablerBadgeColor.Danger
                            : (dnsbl.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);
                        var refs = MergeReferences(sec?.References, narrative?.References);

                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                            AddGridPanelUnique(g, seen, "Status", dnsbl.Status ?? "-", PanelColorForStatus(dnsbl.Status), light: true);
                            AddGridPanelUnique(g, seen, "Warnings", dnsbl.WarningCount.ToString(), dnsbl.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            AddGridPanelUnique(g, seen, "Errors", dnsbl.ErrorCount.ToString(), dnsbl.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                            if (sec != null)
                            {
                                AddGridSummaryPanelsUnique(g, seen, sec.Summary);
                            }
                        });

                        RenderGuidanceWizardCard(c2, narrative, providerHelp: null, providerHelpTopics: null, references: refs);

                        RenderResultsTabsCard(c2, tabs =>
                        {
                            tabs.AddTab("Summary", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderSignalsSummary(col, narrative?.Highlights, sec?.Positives);
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
                                    var listed = dnsbl.ListedRecords ?? Array.Empty<DNSBLRecord>();

                                    if (summaries.Count > 0)
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("Provider Trust Grid").Icon(TablerIconType.ChartBar));
                                            card.Body(body =>
                                            {
                                                body.DataGrid(g =>
                                                {
                                                    g.Settings(s => s.Layout(TablerDataGridLayout.Compact).Spacing(TablerDataGridSpacing.Small).NarrowTitles());
                                                    foreach (var s in summaries.OrderBy(h => h.Key, StringComparer.OrdinalIgnoreCase))
                                                    {
                                                        if (string.IsNullOrWhiteSpace(s.Key))
                                                        {
                                                            continue;
                                                        }
                                                        var label = s.Total > 0 ? $"{s.Listed}/{s.Total} listed" : "-";
                                                        var color = s.Total == 0 ? TablerColor.Blue : (s.Listed > 0 ? TablerColor.Red : TablerColor.Green);
                                                        g.AddItem(s.Key, label).AsPanel(color, light: true);
                                                    }
                                                });
                                            });
                                        });

                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("Host Summary").Icon(TablerIconType.Table));
                                            card.Body(body =>
                                            {
                                                var rows = summaries.Select(s => new
                                                {
                                                    Host = s.Key,
                                                    Listed = $"{s.Listed}/{s.Total}",
                                                    Blacklists = s.Blacklists != null && s.Blacklists.Count > 0 ? string.Join(", ", s.Blacklists) : "-"
                                                }).ToList();
                                                var t = (TablerTable)body.Table(rows, TableType.Tabler);
                                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                            });
                                        });
                                    }

                                    if (listed.Count > 0)
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("Listed Records").Icon(TablerIconType.AlertTriangle));
                                            card.Body(body =>
                                            {
                                                var rows = listed.Select(r2 => new { Host = r2.SourceHost ?? r2.IpAddress, Blacklist = r2.BlackList, Reason = r2.ReplyMeaning }).ToList();
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

}
