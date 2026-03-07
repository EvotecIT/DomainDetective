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
    private static void RenderClassificationSection(TablerAccordion acc, DomainBucket b)
    {
        var cls = b.Classification;
        if (cls == null)
        {
            return;
        }
        var narrative = cls.Raw != null ? MailClassificationNarrative.Build(cls.Raw) : null;
        acc.AddItem("Classification", item => {
            item.Icon(TablerIconType.Tags);
            item.HeaderRight(c => {
                c.Badge(cls.ErrorCount > 0 ? $"{cls.ErrorCount} Error" + (cls.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(cls.WarningCount > 0 ? $"{cls.WarningCount} Warning" + (cls.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(cls.Status ?? "Unknown", ColorForStatus(cls.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        var help = b.Mx?.ProviderHelp ?? b.Spf?.ProviderHelp;
                        var findingsCount = cls.WarningCount + cls.ErrorCount;
                        var findingsBadgeColor = cls.ErrorCount > 0
                            ? TablerBadgeColor.Danger
                            : (cls.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);
                        var positives = (cls.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
                            .Select(p => p?.Title ?? p?.Code)
                            .Where(t => !string.IsNullOrWhiteSpace(t))
                            .Select(t => t!.Trim())
                            .ToList();
                        var refs = MergeReferences(cls.References, narrative?.References);

                        bool useNewLayout = true;
                        if (useNewLayout)
                        {
                            RenderExecutionSnapshotCard(c2, g =>
                            {
                                g.AddItem("Status", cls.Status ?? "-").AsPanel(PanelColorForStatus(cls.Status), light: true);
                                g.AddItem("Warnings", cls.WarningCount.ToString()).AsPanel(cls.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                                g.AddItem("Errors", cls.ErrorCount.ToString()).AsPanel(cls.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);

                                g.AddItem("Classification", cls.Classification ?? "-").AsPanel();
                                g.AddItem("Confidence", cls.Confidence ?? "-").AsPanel();
                                g.AddItem("Score", cls.Score.ToString("0.##")).AsPanel();
                                g.AddItem("Primary Provider", cls.ProviderPrimary ?? "-").AsPanel();
                                g.AddItem("Gateways", cls.ProviderGateways != null && cls.ProviderGateways.Count > 0 ? string.Join(", ", cls.ProviderGateways) : "-").AsPanel();
                                g.AddItem("Outbound", cls.ProviderOutbound != null && cls.ProviderOutbound.Count > 0 ? string.Join(", ", cls.ProviderOutbound) : "-").AsPanel();
                            });

                            RenderGuidanceWizardCard(c2, narrative, help, new[] { "Deliverability" }, refs);

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
                                        RenderFindingsFromAssessments(col, cls.Assessments);
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

                                        if (cls.ScoreBreakdown != null && cls.ScoreBreakdown.Count > 0)
                                        {
                                            hasEvidence = true;
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Score Breakdown").Icon(TablerIconType.ChartBar));
                                                card.Body(body =>
                                                {
                                                    var rows = cls.ScoreBreakdown.Select(kv => new { Metric = kv.Key, Value = kv.Value.ToString("0.##") }).ToList();
                                                    var t = (TablerTable)body.Table(rows, TableType.Tabler);
                                                    t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                                });
                                            });
                                        }

                                        if (cls.ReceivingSignals != null && cls.ReceivingSignals.Count > 0)
                                        {
                                            hasEvidence = true;
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Receiving Signals").Icon(TablerIconType.InfoCircle));
                                                card.Body(body =>
                                                {
                                                    var ul = body.TablerList();
                                                    foreach (var s in cls.ReceivingSignals)
                                                    {
                                                        if (!string.IsNullOrWhiteSpace(s))
                                                        {
                                                            ul.AddItem(s, TablerIconType.InfoCircle);
                                                        }
                                                    }
                                                });
                                            });
                                        }

                                        if (cls.SendingSignals != null && cls.SendingSignals.Count > 0)
                                        {
                                            hasEvidence = true;
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Sending Signals").Icon(TablerIconType.InfoCircle));
                                                card.Body(body =>
                                                {
                                                    var ul = body.TablerList();
                                                    foreach (var s in cls.SendingSignals)
                                                    {
                                                        if (!string.IsNullOrWhiteSpace(s))
                                                        {
                                                            ul.AddItem(s, TablerIconType.InfoCircle);
                                                        }
                                                    }
                                                });
                                            });
                                        }

                                        var raw = cls.Raw;
                                        if (raw != null)
                                        {
                                            if (!string.IsNullOrWhiteSpace(raw.ClassificationReason))
                                            {
                                                hasEvidence = true;
                                                col.Card(card =>
                                                {
                                                    card.Header(h => h.Title("Reason").Icon(TablerIconType.FileText));
                                                    card.Body(body => body.Text(raw.ClassificationReason));
                                                });
                                            }
                                            if (raw.SPFIncludesResolved != null && raw.SPFIncludesResolved.Count > 0)
                                            {
                                                hasEvidence = true;
                                                col.Card(card =>
                                                {
                                                    card.Header(h => h.Title("SPF Includes").Icon(TablerIconType.FileText));
                                                    card.Body(body =>
                                                    {
                                                        var ul = body.TablerList();
                                                        foreach (var include in raw.SPFIncludesResolved)
                                                        {
                                                            if (!string.IsNullOrWhiteSpace(include))
                                                            {
                                                                ul.AddItem(include, TablerIconType.FileText);
                                                            }
                                                        }
                                                    });
                                                });
                                            }
                                            if (raw.DKIMSelectorsFound != null && raw.DKIMSelectorsFound.Count > 0)
                                            {
                                                hasEvidence = true;
                                                col.Card(card =>
                                                {
                                                    card.Header(h => h.Title("DKIM Selectors").Icon(TablerIconType.Key));
                                                    card.Body(body =>
                                                    {
                                                        var ul = body.TablerList();
                                                        foreach (var sel in raw.DKIMSelectorsFound)
                                                        {
                                                            if (!string.IsNullOrWhiteSpace(sel))
                                                            {
                                                                ul.AddItem(sel, TablerIconType.Key);
                                                            }
                                                        }
                                                    });
                                                });
                                            }
                                            if (raw.BimiEligible.HasValue || !string.IsNullOrWhiteSpace(raw.BimiEligibilityReason) || (raw.BimiNotes?.Count ?? 0) > 0)
                                            {
                                                hasEvidence = true;
                                                col.Card(card =>
                                                {
                                                    card.Header(h => h.Title("BIMI Eligibility").Icon(TablerIconType.Photo));
                                                    card.Body(body =>
                                                    {
                                                        if (raw.BimiEligible.HasValue)
                                                        {
                                                            body.Text(raw.BimiEligible.Value ? "Eligible" : "Not eligible");
                                                        }
                                                        if (!string.IsNullOrWhiteSpace(raw.BimiEligibilityReason))
                                                        {
                                                            body.Text(raw.BimiEligibilityReason ?? string.Empty).Style(TablerTextStyle.Muted);
                                                        }
                                                        if (raw.BimiNotes != null && raw.BimiNotes.Count > 0)
                                                        {
                                                            var ul = body.TablerList();
                                                            foreach (var note in raw.BimiNotes)
                                                            {
                                                                if (!string.IsNullOrWhiteSpace(note))
                                                                {
                                                                    ul.AddItem(note, TablerIconType.InfoCircle);
                                                                }
                                                            }
                                                        }
                                                    });
                                                });
                                            }
                                            if (!string.IsNullOrWhiteSpace(raw.IdpTenantId)
                                                || !string.IsNullOrWhiteSpace(raw.IdpNameSpaceType)
                                                || !string.IsNullOrWhiteSpace(raw.IdpFederatedAuthUrl))
                                            {
                                                hasEvidence = true;
                                                col.Card(card =>
                                                {
                                                    card.Header(h => h.Title("Identity Hints").Icon(TablerIconType.InfoCircle));
                                                    card.Body(body =>
                                                    {
                                                        if (!string.IsNullOrWhiteSpace(raw.IdpTenantId))
                                                        {
                                                            body.Text($"Tenant: {raw.IdpTenantId}");
                                                        }
                                                        if (!string.IsNullOrWhiteSpace(raw.IdpNameSpaceType))
                                                        {
                                                            body.Text($"Namespace: {raw.IdpNameSpaceType}");
                                                        }
                                                        if (!string.IsNullOrWhiteSpace(raw.IdpFederatedAuthUrl))
                                                        {
                                                            body.Text($"Federation URL: {raw.IdpFederatedAuthUrl}");
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
                        c2.DataGrid(g => {
                            g.AsCompact();
                            g.AddItem("Classification", cls.Classification ?? "-");
                            g.AddItem("Confidence", cls.Confidence ?? "-");
                            g.AddItem("Score", cls.Score.ToString("0.##"));
                            g.AddItem("Primary Provider", cls.ProviderPrimary ?? "-");
                            g.AddItem("Gateways", cls.ProviderGateways != null && cls.ProviderGateways.Count > 0 ? string.Join(", ", cls.ProviderGateways) : "-");
                            g.AddItem("Outbound", cls.ProviderOutbound != null && cls.ProviderOutbound.Count > 0 ? string.Join(", ", cls.ProviderOutbound) : "-");
                        });
                        if (cls.ScoreBreakdown != null && cls.ScoreBreakdown.Count > 0)
                        {
                            c2.Card(card =>
                            {
                                card.Header(h => h.Title("Score Breakdown").Icon(TablerIconType.ChartBar));
                                card.Body(body =>
                                {
                                    var rows = cls.ScoreBreakdown.Select(kv => new { Metric = kv.Key, Value = kv.Value.ToString("0.##") }).ToList();
                                    var t = (TablerTable)body.Table(rows, TableType.Tabler);
                                    t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                });
                            });
                        }
                        if (cls.ReceivingSignals != null && cls.ReceivingSignals.Count > 0)
                        {
                            c2.Card(card =>
                            {
                                card.Header(h => h.Title("Receiving Signals").Icon(TablerIconType.InfoCircle));
                                card.Body(body =>
                                {
                                    var ul = body.TablerList();
                                    foreach (var s in cls.ReceivingSignals)
                                    {
                                        if (!string.IsNullOrWhiteSpace(s))
                                        {
                                            ul.AddItem(s, TablerIconType.InfoCircle);
                                        }
                                    }
                                });
                            });
                        }
                        if (cls.SendingSignals != null && cls.SendingSignals.Count > 0)
                        {
                            c2.Card(card =>
                            {
                                card.Header(h => h.Title("Sending Signals").Icon(TablerIconType.InfoCircle));
                                card.Body(body =>
                                {
                                    var ul = body.TablerList();
                                    foreach (var s in cls.SendingSignals)
                                    {
                                        if (!string.IsNullOrWhiteSpace(s))
                                        {
                                            ul.AddItem(s, TablerIconType.InfoCircle);
                                        }
                                    }
                                });
                            });
                        }
                        RenderPositives(c2, cls.Positives?
                            .Select(p => p?.Title ?? p?.Code)
                            .Where(t => !string.IsNullOrWhiteSpace(t))    
                            .Select(t => t!));
                        RenderFindingsFromAssessments(c2, cls.Assessments);
                        RenderNarrative(c2, narrative);
                        var raw = cls.Raw;
                        if (raw != null)
                        {
                            if (!string.IsNullOrWhiteSpace(raw.ClassificationReason))
                            {
                                c2.Card(card =>
                                {
                                    card.Header(h => h.Title("Reason").Icon(TablerIconType.FileText));
                                    card.Body(body => body.Text(raw.ClassificationReason));
                                });
                            }
                            if (raw.SPFIncludesResolved != null && raw.SPFIncludesResolved.Count > 0)
                            {
                                c2.Card(card =>
                                {
                                    card.Header(h => h.Title("SPF Includes").Icon(TablerIconType.FileText));
                                    card.Body(body =>
                                    {
                                        var ul = body.TablerList();
                                        foreach (var include in raw.SPFIncludesResolved)
                                        {
                                            if (!string.IsNullOrWhiteSpace(include))
                                            {
                                                ul.AddItem(include, TablerIconType.FileText);
                                            }
                                        }
                                    });
                                });
                            }
                            if (raw.DKIMSelectorsFound != null && raw.DKIMSelectorsFound.Count > 0)
                            {
                                c2.Card(card =>
                                {
                                    card.Header(h => h.Title("DKIM Selectors").Icon(TablerIconType.Key));
                                    card.Body(body =>
                                    {
                                        var ul = body.TablerList();
                                        foreach (var sel in raw.DKIMSelectorsFound)
                                        {
                                            if (!string.IsNullOrWhiteSpace(sel))
                                            {
                                                ul.AddItem(sel, TablerIconType.Key);
                                            }
                                        }
                                    });
                                });
                            }
                            if (raw.BimiEligible.HasValue || !string.IsNullOrWhiteSpace(raw.BimiEligibilityReason) || (raw.BimiNotes?.Count ?? 0) > 0)
                            {
                                c2.Card(card =>
                                {
                                    card.Header(h => h.Title("BIMI Eligibility").Icon(TablerIconType.Photo));
                                    card.Body(body =>
                                    {
                                        if (raw.BimiEligible.HasValue)
                                        {
                                            body.Text(raw.BimiEligible.Value ? "Eligible" : "Not eligible");
                                        }
                                        if (!string.IsNullOrWhiteSpace(raw.BimiEligibilityReason))
                                        {
                                            body.Text(raw.BimiEligibilityReason ?? string.Empty).Style(TablerTextStyle.Muted);
                                        }
                                        if (raw.BimiNotes != null && raw.BimiNotes.Count > 0)
                                        {
                                            var ul = body.TablerList();
                                            foreach (var note in raw.BimiNotes)
                                            {
                                                if (!string.IsNullOrWhiteSpace(note))
                                                {
                                                    ul.AddItem(note, TablerIconType.InfoCircle);
                                                }
                                            }
                                        }
                                    });
                                });
                            }
                            if (!string.IsNullOrWhiteSpace(raw.IdpTenantId)
                                || !string.IsNullOrWhiteSpace(raw.IdpNameSpaceType)
                                || !string.IsNullOrWhiteSpace(raw.IdpFederatedAuthUrl))
                            {
                                c2.Card(card =>
                                {
                                    card.Header(h => h.Title("Identity Hints").Icon(TablerIconType.InfoCircle));
                                    card.Body(body =>
                                    {
                                        if (!string.IsNullOrWhiteSpace(raw.IdpTenantId))
                                        {
                                            body.Text($"Tenant: {raw.IdpTenantId}");
                                        }
                                        if (!string.IsNullOrWhiteSpace(raw.IdpNameSpaceType))
                                        {
                                            body.Text($"Namespace: {raw.IdpNameSpaceType}");
                                        }
                                        if (!string.IsNullOrWhiteSpace(raw.IdpFederatedAuthUrl))
                                        {
                                            body.Text($"Federation URL: {raw.IdpFederatedAuthUrl}");
                                        }
                                    });
                                });
                            }
                        }
                        RenderReferences(c2, MergeReferences(cls.References, narrative?.References));
                        }
                    });
                });
            });
        });
    }

    private static void RenderMtastsSection(TablerAccordion acc, DomainBucket b)
    {
        var mtasts = b.Mtasts;
        if (mtasts == null)
        {
            return;
        }
        var sec = SectionProjectors.BuildMtasts(mtasts);
        var narrative = MtaStsNarrative.Build(mtasts.Raw, mtasts.Assessments);
        acc.AddItem("MTA-STS", item => {
            item.Icon(TablerIconType.Lock);
            item.HeaderRight(c => {
                c.Badge(mtasts.ErrorCount > 0 ? $"{mtasts.ErrorCount} Error" + (mtasts.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(mtasts.WarningCount > 0 ? $"{mtasts.WarningCount} Warning" + (mtasts.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(mtasts.Status ?? "Unknown", ColorForStatus(mtasts.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        var help = b.Mx?.ProviderHelp ?? b.Spf?.ProviderHelp;
                        var findingsCount = mtasts.WarningCount + mtasts.ErrorCount;
                        var findingsBadgeColor = mtasts.ErrorCount > 0
                            ? TablerBadgeColor.Danger
                            : (mtasts.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);
                        var refs = MergeReferences(sec?.References, narrative?.References);

                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                            AddGridPanelUnique(g, seen, "Status", mtasts.Status ?? "-", PanelColorForStatus(mtasts.Status), light: true);
                            AddGridPanelUnique(g, seen, "Warnings", mtasts.WarningCount.ToString(), mtasts.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            AddGridPanelUnique(g, seen, "Errors", mtasts.ErrorCount.ToString(), mtasts.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                            if (sec != null)
                            {
                                AddGridSummaryPanelsUnique(g, seen, sec.Summary);
                            }
                        });

                        RenderGuidanceWizardCard(c2, narrative, help, new[] { "MTA-STS" }, refs);

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
                                    var raw = mtasts.Raw;
                                    if (raw == null)
                                    {
                                        col.Text("No evidence captured for this section.").Style(TablerTextStyle.Muted);
                                        return;
                                    }

                                    if (!string.IsNullOrWhiteSpace(raw.PolicyId))
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("DNS Record (TXT)").Icon(TablerIconType.FileText));
                                            card.Body(body => body.Text($"v=STSv1; id={raw.PolicyId}").Style(TablerTextStyle.Monospace));
                                        });
                                    }

                                    if (!string.IsNullOrWhiteSpace(raw.Policy))
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("Policy (mta-sts.txt)").Icon(TablerIconType.FileText));
                                            card.Body(body =>
                                            {
                                                foreach (var line in raw.Policy.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
                                                {
                                                    if (!string.IsNullOrWhiteSpace(line))
                                                    {
                                                        body.Text(line).Style(TablerTextStyle.Monospace);
                                                    }
                                                }
                                            });
                                        });
                                    }

                                    if (raw.Mx != null && raw.Mx.Count > 0)
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("Policy MX Patterns").Icon(TablerIconType.Mail));
                                            card.Body(body =>
                                            {
                                                var ul = body.TablerList();
                                                foreach (var mx2 in raw.Mx)
                                                {
                                                    if (!string.IsNullOrWhiteSpace(mx2))
                                                    {
                                                        ul.AddItem(mx2, TablerIconType.Mail);
                                                    }
                                                }
                                            });
                                        });
                                    }

                                    if (raw.MissingMxFromPolicy != null && raw.MissingMxFromPolicy.Count > 0)
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("Missing MX in Policy").Icon(TablerIconType.AlertTriangle));
                                            card.Body(body =>
                                            {
                                                var ul = body.TablerList();
                                                foreach (var mx2 in raw.MissingMxFromPolicy)
                                                {
                                                    if (!string.IsNullOrWhiteSpace(mx2))
                                                    {
                                                        ul.AddItem(mx2, TablerIconType.AlertTriangle);
                                                    }
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

    private static void RenderTlsRptSection(TablerAccordion acc, DomainBucket b)
    {
        var tls = b.TlsRpt;
        if (tls == null)
        {
            return;
        }
        var sec = SectionProjectors.BuildTlsRpt(tls);
        var narrative = tls.Raw != null ? TlsRptNarrative.Build(tls.Raw) : null;
        acc.AddItem("TLS-RPT", item => {
            item.Icon(TablerIconType.FileAnalytics);
            item.HeaderRight(c => {
                c.Badge(tls.ErrorCount > 0 ? $"{tls.ErrorCount} Error" + (tls.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(tls.WarningCount > 0 ? $"{tls.WarningCount} Warning" + (tls.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(tls.Status ?? "Unknown", ColorForStatus(tls.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        var help = b.Mx?.ProviderHelp ?? b.Spf?.ProviderHelp;
                        var findingsCount = tls.WarningCount + tls.ErrorCount;
                        var findingsBadgeColor = tls.ErrorCount > 0
                            ? TablerBadgeColor.Danger
                            : (tls.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);
                        var refs = MergeReferences(sec?.References, narrative?.References);

                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                            AddGridPanelUnique(g, seen, "Status", tls.Status ?? "-", PanelColorForStatus(tls.Status), light: true);
                            AddGridPanelUnique(g, seen, "Warnings", tls.WarningCount.ToString(), tls.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            AddGridPanelUnique(g, seen, "Errors", tls.ErrorCount.ToString(), tls.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                            if (sec != null)
                            {
                                AddGridSummaryPanelsUnique(g, seen, sec.Summary);
                            }
                        });

                        RenderGuidanceWizardCard(c2, narrative, help, new[] { "TLS-RPT" }, refs);

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

                                    if (!string.IsNullOrWhiteSpace(tls.TlsRptRecord))
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("TLS-RPT Record").Icon(TablerIconType.FileText));
                                            card.Body(body => body.Text(tls.TlsRptRecord!).Style(TablerTextStyle.Monospace));
                                        });
                                    }

                                    if ((tls.MailtoRua?.Count ?? 0) + (tls.HttpRua?.Count ?? 0) > 0)
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("Reporting URIs").Icon(TablerIconType.Link));
                                            card.Body(body =>
                                            {
                                                var rows = (tls.MailtoRua ?? Array.Empty<string>())
                                                    .Select(x => new { Scheme = "mailto", Uri = x })
                                                    .Concat((tls.HttpRua ?? Array.Empty<string>())
                                                        .Select(x => new { Scheme = "https", Uri = x }))
                                                    .ToList();
                                                var t = (TablerTable)body.Table(rows, TableType.Tabler);
                                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                            });
                                        });
                                    }

                                    if (tls.InvalidRua != null && tls.InvalidRua.Count > 0)
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("Invalid rua").Icon(TablerIconType.AlertTriangle));
                                            card.Body(body =>
                                            {
                                                var ul = body.TablerList();
                                                foreach (var u in tls.InvalidRua)
                                                {
                                                    if (!string.IsNullOrWhiteSpace(u))
                                                    {
                                                        ul.AddItem(u, TablerIconType.AlertTriangle);
                                                    }
                                                }
                                            });
                                        });
                                    }

                                    if (tls.UnknownTags != null && tls.UnknownTags.Count > 0)
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("Unknown tags").Icon(TablerIconType.InfoCircle));
                                            card.Body(body =>
                                            {
                                                var ul = body.TablerList();
                                                foreach (var t in tls.UnknownTags)
                                                {
                                                    if (!string.IsNullOrWhiteSpace(t))
                                                    {
                                                        ul.AddItem(t, TablerIconType.InfoCircle);
                                                    }
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

}
