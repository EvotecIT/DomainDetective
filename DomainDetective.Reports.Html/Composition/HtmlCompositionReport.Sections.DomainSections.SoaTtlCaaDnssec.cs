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
    private static void RenderSoaSection(TablerAccordion acc, DomainBucket b)   
    {
        var soa = b.Soa;
        if (soa == null)
        {
            return;
        }
        var sec = SectionProjectors.BuildSoa(soa);
        var narrative = soa.Raw != null ? SoaNarrative.Build(soa.Raw) : null;
        acc.AddItem("SOA", item => {
            item.Icon(TablerIconType.FileInfo);
            item.HeaderRight(c => {
                c.Badge(soa.ErrorCount > 0 ? $"{soa.ErrorCount} Error" + (soa.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(soa.WarningCount > 0 ? $"{soa.WarningCount} Warning" + (soa.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(soa.Status ?? "Unknown", ColorForStatus(soa.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        var findingsCount = soa.WarningCount + soa.ErrorCount;
                        var findingsBadgeColor = soa.ErrorCount > 0
                            ? TablerBadgeColor.Danger
                            : (soa.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);
                        var refs = MergeReferences(sec?.References, narrative?.References);

                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                            AddGridPanelUnique(g, seen, "Status", soa.Status ?? "-", PanelColorForStatus(soa.Status), light: true);
                            AddGridPanelUnique(g, seen, "Warnings", soa.WarningCount.ToString(), soa.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            AddGridPanelUnique(g, seen, "Errors", soa.ErrorCount.ToString(), soa.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
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
                                    var raw = soa.Raw;
                                    if (raw != null && raw.RecordExists)
                                    {
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("SOA Record").Icon(TablerIconType.FileInfo));
                                            card.Body(body =>
                                            {
                                                body.DataGrid(g =>
                                                {
                                                    g.AsCompact();
                                                    g.AddItem("Primary NS", raw.PrimaryNameServer ?? "-");
                                                    g.AddItem("Responsible", raw.ResponsibleMailbox ?? "-");
                                                    g.AddItem("Serial", raw.SerialNumber.ToString());
                                                    g.AddItem("Serial format", raw.SerialFormatValid ? "Valid" : "Check");
                                                    g.AddItem("Refresh", raw.Refresh.ToString());
                                                    g.AddItem("Retry", raw.Retry.ToString());
                                                    g.AddItem("Expire", raw.Expire.ToString());
                                                    g.AddItem("Minimum", raw.Minimum.ToString());
                                                    g.AddItem("Negative cache TTL", raw.NegativeCacheTtl.ToString());
                                                });
                                            });
                                        });
                                        return;
                                    }

                                    col.Text("No evidence captured for this section.").Style(TablerTextStyle.Muted);
                                }));
                            }).WithIcon(TablerIconType.FileText);
                        });
                    });
                });
            });
        });
    }

    private static void RenderTtlSection(TablerAccordion acc, DomainBucket b)
    {
        var ttl = b.Ttl;
        if (ttl == null)
        {
            return;
        }
        var narrative = ttl.Raw != null ? TtlNarrative.Build(ttl.Raw, ttl.Assessments) : null;
        acc.AddItem("TTL", item =>
        {
            item.Icon(TablerIconType.Clock);
            item.HeaderRight(c =>
            {
                c.Badge(ttl.ErrorCount > 0 ? $"{ttl.ErrorCount} Error" + (ttl.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(ttl.WarningCount > 0 ? $"{ttl.WarningCount} Warning" + (ttl.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(ttl.Status ?? "Unknown", ColorForStatus(ttl.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content =>
            {
                content.Row(r =>
                {
                    r.Column(TablerColumnNumber.Twelve, c2 =>
                    {
                        var findingsCount = ttl.WarningCount + ttl.ErrorCount;
                        var findingsBadgeColor = ttl.ErrorCount > 0
                            ? TablerBadgeColor.Danger
                            : (ttl.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);

                        var positives = (ttl.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
                            .Select(p => p?.Title ?? p?.Code)
                            .Where(t => !string.IsNullOrWhiteSpace(t))
                            .Select(t => t!.Trim())
                            .ToList();

                        var refs = MergeReferences(ttl.References, narrative?.References);

                        static string MinMax(IReadOnlyList<int>? values)
                        {
                            if (values == null || values.Count == 0)
                            {
                                return "-";
                            }
                            var nonZero = values.Where(v => v > 0).ToList();
                            if (nonZero.Count == 0)
                            {
                                return "0";
                            }
                            if (nonZero.Count == 1)
                            {
                                return nonZero[0].ToString();
                            }
                            return $"{nonZero.Min()}/{nonZero.Max()}";
                        }

                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            g.AddItem("Status", ttl.Status ?? "-").AsPanel(PanelColorForStatus(ttl.Status), light: true);
                            g.AddItem("Warnings", ttl.WarningCount.ToString()).AsPanel(ttl.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            g.AddItem("Errors", ttl.ErrorCount.ToString()).AsPanel(ttl.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);

                            g.AddItem("DNSSEC signed", ttl.DnssecSigned ? "Yes" : "No").AsPanel();
                            g.AddItem("SOA TTL (s)", ttl.SoaTtl.ToString()).AsPanel();
                            g.AddItem("A TTL (min/max)", MinMax(ttl.ATtls)).AsPanel();
                            g.AddItem("AAAA TTL (min/max)", MinMax(ttl.AaaaTtls)).AsPanel();
                            g.AddItem("MX TTL (min/max)", MinMax(ttl.MxTtls)).AsPanel();
                            g.AddItem("NS TTL (min/max)", MinMax(ttl.NsTtls)).AsPanel();
                        });

                        RenderGuidanceWizardCard(c2, narrative, providerHelp: null, providerHelpTopics: null, references: refs);

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
                                    RenderFindingsFromAssessments(col, ttl.Assessments);
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
                                    var evidenceRows = new List<object>();

                                    static string Sample(IReadOnlyList<int>? values, int max = 10)
                                    {
                                        if (values == null || values.Count == 0) return "-";
                                        var unique = values.Where(v => v > 0).Distinct().OrderBy(v => v).ToList();
                                        if (unique.Count == 0) return "0";
                                        var take = unique.Take(max).ToList();
                                        var suffix = unique.Count > take.Count ? $" (+{unique.Count - take.Count} more)" : string.Empty;
                                        return string.Join(", ", take) + suffix;
                                    }

                                    void AddRow(string record, IReadOnlyList<int>? values)
                                    {
                                        if (values == null || values.Count == 0)
                                        {
                                            return;
                                        }
                                        var nonZero = values.Where(v => v > 0).ToList();
                                        evidenceRows.Add(new
                                        {
                                            Record = record,
                                            Min = nonZero.Count > 0 ? nonZero.Min().ToString() : "0",
                                            Max = nonZero.Count > 0 ? nonZero.Max().ToString() : "0",
                                            Count = nonZero.Count.ToString(),
                                            Values = Sample(values)
                                        });
                                    }

                                    AddRow("A", ttl.ATtls);
                                    AddRow("AAAA", ttl.AaaaTtls);
                                    AddRow("MX", ttl.MxTtls);
                                    AddRow("NS", ttl.NsTtls);
                                    AddRow("TXT (SPF)", ttl.SpfTxtTtls);
                                    AddRow("TXT (_dmarc)", ttl.DmarcTxtTtls);
                                    AddRow("TXT (_mta-sts)", ttl.MtastsTxtTtls);
                                    AddRow("TXT (_smtp._tls)", ttl.TlsRptTxtTtls);

                                    bool hasEvidence = false;

                                    if (ttl.SoaTtl > 0)
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("SOA TTL").Icon(TablerIconType.Clock));
                                            card.Body(b => b.Text($"{ttl.SoaTtl} seconds").Style(TablerTextStyle.Muted));
                                        });
                                    }

                                    if (evidenceRows.Count > 0)
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("Observed TTLs").Icon(TablerIconType.Table));
                                            card.Body(body =>
                                            {
                                                var t = (TablerTable)body.Table(evidenceRows, TableType.Tabler);
                                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                            });
                                        });
                                    }

                                    if (ttl.DkimTxtTtls != null && ttl.DkimTxtTtls.Count > 0)
                                    {
                                        hasEvidence = true;
                                        col.Card(card =>
                                        {
                                            card.Header(h => h.Title("DKIM Selector TTLs").Icon(TablerIconType.Key));
                                            card.Body(body =>
                                            {
                                                var rows = ttl.DkimTxtTtls
                                                    .OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                                                    .Select(kv =>
                                                    {
                                                        var values = kv.Value ?? Array.Empty<int>();
                                                        var nonZero = values.Where(v => v > 0).ToList();
                                                        return new
                                                        {
                                                            Selector = kv.Key,
                                                            Min = nonZero.Count > 0 ? nonZero.Min().ToString() : "0",
                                                            Max = nonZero.Count > 0 ? nonZero.Max().ToString() : "0",
                                                            Count = nonZero.Count.ToString(),
                                                            Values = Sample(values)
                                                        };
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

    private static void RenderCaaSection(TablerAccordion acc, DomainBucket b)   
    {
        var caa = b.Caa;
        if (caa == null)
        {
            return;
        }
        var sec = SectionProjectors.BuildCaa(caa);
        var narrative = caa.Raw != null ? CaaNarrative.Build(caa.Raw) : null;
        acc.AddItem("CAA", item => {
            item.Icon(TablerIconType.Certificate);
            item.HeaderRight(c => {
                c.Badge(caa.ErrorCount > 0 ? $"{caa.ErrorCount} Error" + (caa.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(caa.WarningCount > 0 ? $"{caa.WarningCount} Warning" + (caa.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(caa.Status ?? "Unknown", ColorForStatus(caa.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        bool useNewLayout = true;
                        if (useNewLayout)
                        {
                            var findingsCount = caa.WarningCount + caa.ErrorCount;
                            var findingsBadgeColor = caa.ErrorCount > 0
                                ? TablerBadgeColor.Danger
                                : (caa.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);
                            var refs = MergeReferences(sec?.References, narrative?.References);

                            RenderExecutionSnapshotCard(c2, g =>
                            {
                                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                                AddGridPanelUnique(g, seen, "Status", caa.Status ?? "-", PanelColorForStatus(caa.Status), light: true);
                                AddGridPanelUnique(g, seen, "Warnings", caa.WarningCount.ToString(), caa.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                                AddGridPanelUnique(g, seen, "Errors", caa.ErrorCount.ToString(), caa.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
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
                                        var raw = caa.Raw;
                                        if (raw != null && raw.AnalysisResults != null && raw.AnalysisResults.Count > 0)
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Analysis Results").Icon(TablerIconType.Table));
                                                card.Body(body =>
                                                {
                                                    var rows = raw.AnalysisResults.Select(r => new
                                                    {
                                                        Record = r.CAARecord,
                                                        Flag = r.Flag,
                                                        Tag = r.Tag.ToString(),
                                                        Value = r.Value,
                                                        Issuer = string.IsNullOrWhiteSpace(r.Issuer) ? "-" : r.Issuer,
                                                        Critical = r.Critical ? "Yes" : "No",
                                                        Invalid = r.Invalid ? "Yes" : "No"
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
                        var raw = caa.Raw;
                        if (raw != null && raw.AnalysisResults != null && raw.AnalysisResults.Count > 0)
                        {
                            c2.Card(card =>
                            {
                                card.Header(h => h.Title("Analysis Results").Icon(TablerIconType.Table));
                                card.Body(body =>
                                {
                                    var rows = raw.AnalysisResults.Select(r => new
                                    {
                                        Record = r.CAARecord,
                                        Flag = r.Flag,
                                        Tag = r.Tag.ToString(),
                                        Value = r.Value,
                                        Issuer = string.IsNullOrWhiteSpace(r.Issuer) ? "-" : r.Issuer,
                                        Critical = r.Critical ? "Yes" : "No",
                                        Invalid = r.Invalid ? "Yes" : "No"
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

    private static void RenderDnssecSection(TablerAccordion acc, DomainBucket b)
    {
        var dnssec = b.Dnssec;
        if (dnssec == null)
        {
            return;
        }
        var sec = SectionProjectors.BuildDnssec(dnssec);
        var narrative = DnssecNarrative.Build(dnssec.Raw, dnssec.Assessments);
        acc.AddItem("DNSSEC", item => {
            item.Icon(TablerIconType.ShieldBolt);
            item.HeaderRight(c => {
                c.Badge(dnssec.ErrorCount > 0 ? $"{dnssec.ErrorCount} Error" + (dnssec.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(dnssec.WarningCount > 0 ? $"{dnssec.WarningCount} Warning" + (dnssec.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(dnssec.Status ?? "Unknown", ColorForStatus(dnssec.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        bool useNewLayout = true;
                        if (useNewLayout)
                        {
                            var findingsCount = dnssec.WarningCount + dnssec.ErrorCount;
                            var findingsBadgeColor = dnssec.ErrorCount > 0
                                ? TablerBadgeColor.Danger
                                : (dnssec.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);
                            var refs = MergeReferences(sec?.References, narrative?.References);

                            RenderExecutionSnapshotCard(c2, g =>
                            {
                                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                                AddGridPanelUnique(g, seen, "Status", dnssec.Status ?? "-", PanelColorForStatus(dnssec.Status), light: true);
                                AddGridPanelUnique(g, seen, "Warnings", dnssec.WarningCount.ToString(), dnssec.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                                AddGridPanelUnique(g, seen, "Errors", dnssec.ErrorCount.ToString(), dnssec.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
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
                                        var raw = dnssec.Raw;
                                        if (raw != null)
                                        {
                                            if (raw.DsRecords != null && raw.DsRecords.Count > 0)
                                            {
                                                hasEvidence = true;
                                                col.Card(card =>
                                                {
                                                    card.Header(h => h.Title("DS Records").Icon(TablerIconType.FileText));
                                                    card.Body(body =>
                                                    {
                                                        foreach (var ds in raw.DsRecords)
                                                        {
                                                            if (!string.IsNullOrWhiteSpace(ds))
                                                            {
                                                                body.Text(ds).Style(TablerTextStyle.Monospace);
                                                            }
                                                        }
                                                    });
                                                });
                                            }
                                            if (raw.DnsKeys != null && raw.DnsKeys.Count > 0)
                                            {
                                                hasEvidence = true;
                                                col.Card(card =>
                                                {
                                                    card.Header(h => h.Title("DNSKEY Records").Icon(TablerIconType.Key));
                                                    card.Body(body =>
                                                    {
                                                        foreach (var key in raw.DnsKeys)
                                                        {
                                                            if (!string.IsNullOrWhiteSpace(key))
                                                            {
                                                                body.Text(key).Style(TablerTextStyle.Monospace);
                                                            }
                                                        }
                                                    });
                                                });
                                            }
                                            if (raw.Rrsigs != null && raw.Rrsigs.Count > 0)
                                            {
                                                hasEvidence = true;
                                                col.Card(card =>
                                                {
                                                    card.Header(h => h.Title("RRSIG Summary").Icon(TablerIconType.Table));
                                                    card.Body(body =>
                                                    {
                                                        var rows = raw.Rrsigs.Select(r => new
                                                        {
                                                            Algorithm = r.Algorithm,
                                                            KeyTag = r.KeyTag.ToString(),
                                                            Inception = r.Inception == DateTimeOffset.MinValue ? "-" : r.Inception.UtcDateTime.ToString("yyyy-MM-dd"),
                                                            Expiration = r.Expiration == DateTimeOffset.MinValue ? "-" : r.Expiration.UtcDateTime.ToString("yyyy-MM-dd")
                                                        }).ToList();
                                                        var t = (TablerTable)body.Table(rows, TableType.Tabler);
                                                        t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                                    });
                                                });
                                            }
                                            if (raw.RootAnchorExpiration.HasValue)
                                            {
                                                hasEvidence = true;
                                                col.Card(card =>
                                                {
                                                    card.Header(h => h.Title("Root trust anchor").Icon(TablerIconType.Clock));
                                                    card.Body(body => body.Text(raw.RootAnchorExpiration.Value.UtcDateTime.ToString("yyyy-MM-dd")));
                                                });
                                            }
                                            if (raw.MismatchSummary != null && raw.MismatchSummary.Count > 0)
                                            {
                                                hasEvidence = true;
                                                col.Card(card =>
                                                {
                                                    card.Header(h => h.Title("Mismatches").Icon(TablerIconType.AlertTriangle));
                                                    card.Body(body =>
                                                    {
                                                        var ul = body.TablerList();
                                                        foreach (var m in raw.MismatchSummary)
                                                        {
                                                            if (!string.IsNullOrWhiteSpace(m))
                                                            {
                                                                ul.AddItem(m, TablerIconType.AlertTriangle);
                                                            }
                                                        }
                                                    });
                                                });
                                            }
                                            if (raw.Warnings != null && raw.Warnings.Count > 0)
                                            {
                                                hasEvidence = true;
                                                col.Card(card =>
                                                {
                                                    card.Header(h => h.Title("Warnings").Icon(TablerIconType.AlertTriangle));
                                                    card.Body(body =>
                                                    {
                                                        var ul = body.TablerList();
                                                        foreach (var w in raw.Warnings)
                                                        {
                                                            if (!string.IsNullOrWhiteSpace(w))
                                                            {
                                                                ul.AddItem(w, TablerIconType.AlertTriangle);
                                                            }
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
                        RenderPositives(c2, sec?.Positives);
                        RenderFindings(c2, sec?.Findings);
                        RenderNarrative(c2, narrative);
                        var raw = dnssec.Raw;
                        if (raw != null)
                        {
                            if (raw.DsRecords != null && raw.DsRecords.Count > 0)
                            {
                                c2.Card(card =>
                                {
                                    card.Header(h => h.Title("DS Records").Icon(TablerIconType.FileText));
                                    card.Body(body =>
                                    {
                                        foreach (var ds in raw.DsRecords)
                                        {
                                            if (!string.IsNullOrWhiteSpace(ds))
                                            {
                                                body.Text(ds).Style(TablerTextStyle.Monospace);
                                            }
                                        }
                                    });
                                });
                            }
                            if (raw.DnsKeys != null && raw.DnsKeys.Count > 0)
                            {
                                c2.Card(card =>
                                {
                                    card.Header(h => h.Title("DNSKEY Records").Icon(TablerIconType.Key));
                                    card.Body(body =>
                                    {
                                        foreach (var key in raw.DnsKeys)
                                        {
                                            if (!string.IsNullOrWhiteSpace(key))
                                            {
                                                body.Text(key).Style(TablerTextStyle.Monospace);
                                            }
                                        }
                                    });
                                });
                            }
                            if (raw.Rrsigs != null && raw.Rrsigs.Count > 0)
                            {
                                c2.Card(card =>
                                {
                                    card.Header(h => h.Title("RRSIG Summary").Icon(TablerIconType.Table));
                                    card.Body(body =>
                                    {
                                        var rows = raw.Rrsigs.Select(r => new
                                        {
                                            Algorithm = r.Algorithm,
                                            KeyTag = r.KeyTag.ToString(),
                                            Inception = r.Inception == DateTimeOffset.MinValue ? "-" : r.Inception.UtcDateTime.ToString("yyyy-MM-dd"),
                                            Expiration = r.Expiration == DateTimeOffset.MinValue ? "-" : r.Expiration.UtcDateTime.ToString("yyyy-MM-dd")
                                        }).ToList();
                                        var t = (TablerTable)body.Table(rows, TableType.Tabler);
                                        t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                    });
                                });
                            }
                            if (raw.RootAnchorExpiration.HasValue)
                            {
                                c2.Card(card =>
                                {
                                    card.Header(h => h.Title("Root trust anchor").Icon(TablerIconType.Clock));
                                    card.Body(body => body.Text(raw.RootAnchorExpiration.Value.UtcDateTime.ToString("yyyy-MM-dd")));
                                });
                            }
                            if (raw.MismatchSummary != null && raw.MismatchSummary.Count > 0)
                            {
                                c2.Card(card =>
                                {
                                    card.Header(h => h.Title("Mismatch summary").Icon(TablerIconType.AlertTriangle));
                                    card.Body(body =>
                                    {
                                        var ul = body.TablerList();
                                        foreach (var m in raw.MismatchSummary)
                                        {
                                            if (!string.IsNullOrWhiteSpace(m))
                                            {
                                                ul.AddItem(m, TablerIconType.AlertTriangle);
                                            }
                                        }
                                    });
                                });
                            }
                            if (raw.Warnings != null && raw.Warnings.Count > 0)
                            {
                                c2.Card(card =>
                                {
                                    card.Header(h => h.Title("Warnings").Icon(TablerIconType.AlertTriangle));
                                    card.Body(body =>
                                    {
                                        var ul = body.TablerList();
                                        foreach (var w in raw.Warnings)
                                        {
                                            if (!string.IsNullOrWhiteSpace(w))
                                            {
                                                ul.AddItem(w, TablerIconType.AlertTriangle);
                                            }
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
