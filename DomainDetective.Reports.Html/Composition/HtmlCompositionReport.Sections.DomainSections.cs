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
    private static readonly string[] ProviderTopicOrder = new[] { "DMARC", "SPF", "DKIM", "ARC", "BIMI", "MTA-STS", "TLS-RPT", "DELIVERABILITY" };

    private static IReadOnlyList<string> GetPresentSections(DomainBucket b)
    {
        var list = new List<string>();
        if (b.Mx != null) list.Add("MX");
        if (b.Spf != null) list.Add("SPF");
        if (b.Dkim.Count > 0) list.Add("DKIM");
        if (b.Dmarc != null) list.Add("DMARC");
        if (b.Arc != null) list.Add("ARC");
        if (b.Bimi != null) list.Add("BIMI");
        if (b.Dnsbl != null) list.Add("DNSBL");
        if (b.Rpki != null) list.Add("RPKI");
        if (b.Ns != null) list.Add("NS");
        if (b.Soa != null) list.Add("SOA");
        if (b.ZoneTransfer != null) list.Add("ZoneTransfer");
        if (b.Wildcard != null) list.Add("Wildcard");
        if (b.Caa != null) list.Add("CAA");
        if (b.Classification != null) list.Add("Classification");
        if (b.Mtasts != null) list.Add("MTA-STS");
        if (b.TlsRpt != null) list.Add("TLS-RPT");
        if (b.SmtpTls != null || b.ImapTls != null || b.PopTls != null) list.Add("MAILTLS");
        if (b.Dnssec != null) list.Add("DNSSEC");
        if (b.Dane != null) list.Add("DANE");
        return list;
    }

    private static void RenderDomainSections(TablerAccordion acc, string domain, DomainBucket b, SectionOrderMode sectionOrderMode, string[] customOrder, Dictionary<string, List<string>> inputSectionOrder)
    {
        var present = GetPresentSections(b);
        List<string>? input = null;
        if (inputSectionOrder != null && inputSectionOrder.TryGetValue(domain, out var list))
        {
            input = list;
        }
        var order = SectionOrdering.ResolveOrder(sectionOrderMode, present, input, customOrder);
        foreach (var section in order)
        {
            switch (section)
            {
                case "MX":
                    RenderMxSection(acc, b);
                    break;
                case "SPF":
                    RenderSpfSection(acc, b);
                    break;
                case "DKIM":
                    RenderDkimSection(acc, b);
                    break;
                case "DMARC":
                    RenderDmarcSection(acc, b);
                    break;
                case "ARC":
                    RenderArcSection(acc, b);
                    break;
                case "BIMI":
                    RenderBimiSection(acc, b);
                    break;
                case "DNSBL":
                    RenderDnsblSection(acc, b);
                    break;
                case "Classification":
                    RenderClassificationSection(acc, b);
                    break;
                case "MTA-STS":
                    RenderMtastsSection(acc, b);
                    break;
                case "TLS-RPT":
                    RenderTlsRptSection(acc, b);
                    break;
                case "NS":
                    RenderNsSection(acc, b);
                    break;
                case "SOA":
                    RenderSoaSection(acc, b);
                    break;
                case "CAA":
                    RenderCaaSection(acc, b);
                    break;
                case "DNSSEC":
                    RenderDnssecSection(acc, b);
                    break;
                case "DANE":
                    RenderDaneSection(acc, b);
                    break;
                case "RPKI":
                    RenderRpkiSection(acc, b);
                    break;
                case "ZoneTransfer":
                    RenderZoneTransferSection(acc, b);
                    break;
                case "Wildcard":
                    RenderWildcardSection(acc, b);
                    break;
                case "MAILTLS":
                    RenderMailTlsSection(acc, b);
                    break;
            }
        }
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
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        var help = (spf.ProviderHelp != null && spf.ProviderHelp.Count > 0) ? spf.ProviderHelp : b.Mx?.ProviderHelp;

                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            g.AddItem("Status", spf.Status ?? "-").AsPanel(PanelColorForStatus(spf.Status), light: true);
                            g.AddItem("Warnings", spf.WarningCount.ToString()).AsPanel(spf.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            g.AddItem("Errors", spf.ErrorCount.ToString()).AsPanel(spf.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                            if (sec != null)
                            {
                                foreach (var kv in sec.Summary) g.AddItem(kv.Key, kv.Value).AsPanel();
                                if (sec.Mechanisms.Count > 0) g.AddItem("Mechanisms", sec.Mechanisms.Count.ToString()).AsPanel();
                            }
                        });

                        RenderGuidanceWizardCard(c2, spf.Narrative, help, new[] { "SPF" }, sec?.References);

                        c2.Divider("Results");
                        c2.Tabs(tabs =>
                        {
                            tabs.AddTab("Summary", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderHighlights(col, sec?.Highlights);
                                    RenderPositives(col, sec?.Positives);
                                }));
                            }).WithIcon(TablerIconType.Cards);

                            tabs.AddTab("Findings", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderFindings(col, sec?.Findings);
                                }));
                            }).WithIcon(TablerIconType.AlertTriangle)
                              .WithBadge((spf.WarningCount + spf.ErrorCount).ToString(), spf.ErrorCount > 0 ? TablerBadgeColor.Danger : (spf.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success));

                            tabs.AddTab("Evidence", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    var spfRecord = sec?.SpfRecord;
                                    if (!string.IsNullOrWhiteSpace(spfRecord))
                                    {
                                        col.Text("SPF Record:").Style(TablerTextStyle.Muted);
                                        col.Text(spfRecord!).Style(TablerTextStyle.Monospace);
                                    }

                                    if (sec != null && sec.Mechanisms.Count > 0)
                                    {
                                        col.Divider("Mechanisms");
                                        var rows = sec.Mechanisms.Select(m => new { m.Qualifier, m.Type, m.Value, m.Provider }).ToList();
                                        var t = (TablerTable)col.Table(rows, TableType.Tabler);
                                        t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                    }

                                    if (sec != null && (sec.FlattenedUniqueIpCount + sec.FlattenedDuplicateIpCount + sec.FlattenedTokenCount > 0))
                                    {
                                        col.Divider("Flattened IP Analysis");
                                        col.DataGrid(g =>
                                        {
                                            g.AsCompact();
                                            g.AddItem("Unique IPs", sec.FlattenedUniqueIpCount.ToString());
                                            g.AddItem("Duplicate IPs", sec.FlattenedDuplicateIpCount.ToString());
                                            g.AddItem("Tokens Resolved", sec.FlattenedTokenCount.ToString());
                                        });
                                    }

                                    if (string.IsNullOrWhiteSpace(spfRecord) && (sec?.Mechanisms.Count ?? 0) == 0 && (sec?.FlattenedTokenCount ?? 0) == 0)
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
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        var help = b.Mx?.ProviderHelp ?? b.Spf?.ProviderHelp;

                        RenderExecutionSnapshotCard(c2, g =>
                        {
                            g.AddItem("Status", dmarc.Status ?? "-").AsPanel(PanelColorForStatus(dmarc.Status), light: true);
                            g.AddItem("Warnings", dmarc.WarningCount.ToString()).AsPanel(dmarc.WarningCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                            g.AddItem("Errors", dmarc.ErrorCount.ToString()).AsPanel(dmarc.ErrorCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                            if (sec != null)
                            {
                                foreach (var kv in sec.Summary) g.AddItem(kv.Key, kv.Value).AsPanel();
                            }
                        });

                        RenderGuidanceWizardCard(c2, dmarc.Narrative, help, new[] { "DMARC" }, sec?.References);

                        c2.Divider("Results");
                        c2.Tabs(tabs =>
                        {
                            tabs.AddTab("Summary", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderHighlights(col, sec?.Highlights);
                                    RenderPositives(col, sec?.Positives);
                                }));
                            }).WithIcon(TablerIconType.Cards);

                            tabs.AddTab("Findings", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderFindings(col, sec?.Findings);
                                }));
                            }).WithIcon(TablerIconType.AlertTriangle)
                              .WithBadge((dmarc.WarningCount + dmarc.ErrorCount).ToString(), dmarc.ErrorCount > 0 ? TablerBadgeColor.Danger : (dmarc.WarningCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success));

                            tabs.AddTab("Evidence", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    var dmarcRecord = sec?.DmarcRecord;
                                    if (!string.IsNullOrWhiteSpace(dmarcRecord))
                                    {
                                        col.Text("DMARC Record:").Style(TablerTextStyle.Muted);
                                        col.Text(dmarcRecord!).Style(TablerTextStyle.Monospace);
                                    }

                                    if (sec != null && (sec.MailtoRua.Count + sec.HttpRua.Count + sec.MailtoRuf.Count + sec.HttpRuf.Count > 0))
                                    {
                                        col.Divider("Reporting URIs");
                                        if (sec.MailtoRua.Count + sec.HttpRua.Count > 0)
                                        {
                                            col.Text("Aggregate (RUA)").Style(TablerTextStyle.Muted);
                                            var rua = sec.MailtoRua.Select(x => new { Scheme = "mailto", Uri = x })
                                                .Concat(sec.HttpRua.Select(x => new { Scheme = "http", Uri = x })).ToList();
                                            var t = (TablerTable)col.Table(rua, TableType.Tabler);
                                            t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                        }
                                        if (sec.MailtoRuf.Count + sec.HttpRuf.Count > 0)
                                        {
                                            col.Text("Forensic (RUF)").Style(TablerTextStyle.Muted);
                                            var ruf = sec.MailtoRuf.Select(x => new { Scheme = "mailto", Uri = x })
                                                .Concat(sec.HttpRuf.Select(x => new { Scheme = "http", Uri = x })).ToList();
                                            var t2 = (TablerTable)col.Table(ruf, TableType.Tabler);
                                            t2.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                        }
                                    }

                                    if (string.IsNullOrWhiteSpace(dmarcRecord) && (sec == null || (sec.MailtoRua.Count + sec.HttpRua.Count + sec.MailtoRuf.Count + sec.HttpRuf.Count == 0)))
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

                        c2.Divider("Results");
                        c2.Tabs(tabs =>
                        {
                            tabs.AddTab("Summary", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderHighlights(col, sec?.Highlights);
                                    RenderPositives(col, sec?.Positives);
                                }));
                            }).WithIcon(TablerIconType.Cards);

                            tabs.AddTab("Findings", panel =>
                            {
                                panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                {
                                    RenderFindings(col, sec?.Findings);
                                }));
                            }).WithIcon(TablerIconType.AlertTriangle)
                              .WithBadge((warnCount + errCount).ToString(), errCount > 0 ? TablerBadgeColor.Danger : (warnCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success));

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
                                            TTL = k.TtlSeconds?.ToString() ?? "-"
                                        }).ToList();

                                        var table = (DataTablesTable)col.Table(rows, TableType.DataTables);
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
                                        col.Divider("Records");
                                        foreach (var r2 in sec.Rows.Where(r => !string.IsNullOrWhiteSpace(r.Record)))
                                        {
                                            col.Text($"Selector {r2.Selector}").Style(TablerTextStyle.Muted);
                                            col.Text(r2.Record).Style(TablerTextStyle.Monospace);
                                        }
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
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        RenderSummaryGrid(c2, sec?.Summary);
                        RenderProviderHelpBadges(c2, mx.ProviderHelp, new[] { "DMARC", "SPF", "DKIM", "MTA-STS", "TLS-RPT", "Deliverability" });
                        if (sec != null && sec.Records.Count > 0)
                        {
                            c2.Divider("MX Records");
                            var rows = sec.Records.Select(r2 => new { Host = r2 }).ToList();
                            var t = (TablerTable)c2.Table(rows, TableType.Tabler);
                            t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                        }
                        if (!string.IsNullOrWhiteSpace(sec?.MailTlsSmtp) || !string.IsNullOrWhiteSpace(sec?.MailTlsImap) || !string.IsNullOrWhiteSpace(sec?.MailTlsPop))
                        {
                            c2.Divider("MailTLS");
                            var rows = new List<object>
                            {
                                new { Service = "SMTP", Status = sec?.MailTlsSmtp ?? "-" },
                                new { Service = "IMAP", Status = sec?.MailTlsImap ?? "-" },
                                new { Service = "POP3", Status = sec?.MailTlsPop ?? "-" }
                            };
                            var t = (TablerTable)c2.Table(rows, TableType.Tabler);
                            t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                        }
                        RenderPositives(c2, sec?.Positives);
                        RenderFindings(c2, sec?.Findings);
                        RenderNarrative(c2, narrative);
                        var raw = mx.Raw;
                        bool hasEvidence = raw != null && ((raw.MxRecords?.Count ?? 0) > 0 || (raw.MxRecordTtls?.Count ?? 0) > 0);
                        if (hasEvidence && raw != null)
                        {
                            c2.Divider("Evidence");
                            if (raw.MxRecords != null && raw.MxRecords.Count > 0)
                            {
                                c2.Text("MX records").Style(TablerTextStyle.Muted);
                                foreach (var rr in raw.MxRecords)
                                {
                                    if (!string.IsNullOrWhiteSpace(rr))
                                    {
                                        c2.Text(rr).Style(TablerTextStyle.Monospace);
                                    }
                                }
                            }
                            if (raw.MxRecordTtls != null && raw.MxRecordTtls.Count > 0)
                            {
                                c2.Text("TTL (seconds)").Style(TablerTextStyle.Muted);
                                c2.Text(string.Join(", ", raw.MxRecordTtls)).Style(TablerTextStyle.Monospace);
                            }
                        }
                        RenderReferences(c2, MergeReferences(sec?.References, narrative?.References));
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
                c.Badge(arc.Status ?? "-", ColorForStatus(arc.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        c2.DataGrid(g => {
                            g.AsCompact();
                            g.AddItem("Headers Present", arc.ArcHeadersFound ? "Yes" : "No");
                            g.AddItem("ARC-Seal count", arc.SealCount.ToString());
                            g.AddItem("AAR count", arc.AarCount.ToString());
                            g.AddItem("Seals signed", arc.SealsIncludeSignatures ? "Yes" : "No");
                            g.AddItem("Chain state", arc.ChainState ?? "-");
                            g.AddItem("Status", arc.Status ?? "-");
                        });
                        var help = b.Mx?.ProviderHelp ?? b.Spf?.ProviderHelp;
                        RenderProviderHelpBadges(c2, help, new[] { "ARC" });
                        RenderHighlights(c2, arc.Highlights);
                        RenderPositives(c2, arc.Positives?
                            .Select(p => p?.Title ?? p?.Code)
                            .Where(t => !string.IsNullOrWhiteSpace(t))
                            .Select(t => t!));
                        RenderFindingsFromAssessments(c2, arc.Assessments);     
                        RenderNarrative(c2, arc.Narrative);
                        c2.Divider("Evidence");
                        c2.Text($"ARC-Seal headers: {arc.SealCount}");
                        c2.Text($"ARC-Authentication-Results headers: {arc.AarCount}");
                        c2.Text($"Chain: {arc.ChainState}");
                        var raw = arc.Raw;
                        if (raw != null)
                        {
                            const int maxHeaders = 5;
                            if (raw.ArcSealHeaders.Count > 0)
                            {
                                c2.Text("ARC-Seal values").Style(TablerTextStyle.Muted);
                                foreach (var header in raw.ArcSealHeaders.Take(maxHeaders))
                                {
                                    if (!string.IsNullOrWhiteSpace(header))
                                    {
                                        c2.Text(header).Style(TablerTextStyle.Monospace);
                                    }
                                }
                                if (raw.ArcSealHeaders.Count > maxHeaders)
                                {
                                    c2.Text($"+{raw.ArcSealHeaders.Count - maxHeaders} more").Style(TablerTextStyle.Muted);
                                }
                            }
                            if (raw.ArcAuthenticationResultsHeaders.Count > 0)
                            {
                                c2.Text("ARC-Authentication-Results values").Style(TablerTextStyle.Muted);
                                foreach (var header in raw.ArcAuthenticationResultsHeaders.Take(maxHeaders))
                                {
                                    if (!string.IsNullOrWhiteSpace(header))
                                    {
                                        c2.Text(header).Style(TablerTextStyle.Monospace);
                                    }
                                }
                                if (raw.ArcAuthenticationResultsHeaders.Count > maxHeaders)
                                {
                                    c2.Text($"+{raw.ArcAuthenticationResultsHeaders.Count - maxHeaders} more").Style(TablerTextStyle.Muted);
                                }
                            }
                        }
                        RenderReferences(c2, MergeReferences(arc.References, arc.Narrative?.References));
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
                c.Badge(bimi.Status ?? "-", ColorForStatus(bimi.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        c2.DataGrid(g => {
                            g.AsCompact();
                            g.AddItem("Record Present", bimi.BimiRecordExists ? "Yes" : "No");
                            g.AddItem("Location (l=)", string.IsNullOrWhiteSpace(bimi.Location) ? "-" : bimi.Location);
                            g.AddItem("Authority (a=)", string.IsNullOrWhiteSpace(bimi.Authority) ? "-" : bimi.Authority);
                            g.AddItem("SVG Valid", bimi.SvgValid ? "Yes" : "No");
                            g.AddItem("VMC Present", bimi.ValidVmc ? "Yes" : "No");
                            g.AddItem("VMC Trusted", bimi.ValidVmc ? (bimi.VmcSignedByKnownRoot ? "Yes" : "Untrusted") : "-");
                            g.AddItem("Declined (p=reject)", bimi.DeclinedToPublish ? "Yes" : "No");
                            g.AddItem("Status", bimi.Status ?? "-");
                        });
                        var help = b.Mx?.ProviderHelp ?? b.Spf?.ProviderHelp;
                        RenderProviderHelpBadges(c2, help, new[] { "BIMI" });
                        RenderPositives(c2, bimi.Positives?
                            .Select(p => p?.Title ?? p?.Code)
                            .Where(t => !string.IsNullOrWhiteSpace(t))
                            .Select(t => t!));
                        RenderFindingsFromAssessments(c2, bimi.Assessments);    
                        RenderNarrative(c2, narrative);
                        c2.Divider("Evidence");
                        c2.Text("BIMI Record:").Style(TablerTextStyle.Muted);
                        c2.Text(bimi.BimiRecord ?? string.Empty).Style(TablerTextStyle.Monospace);
                        if (!string.IsNullOrWhiteSpace(bimi.Location)) c2.Text($"Location: {bimi.Location}");
                        if (!string.IsNullOrWhiteSpace(bimi.Authority)) c2.Text($"Authority: {bimi.Authority}");
                        if (!bimi.SvgValid && !string.IsNullOrWhiteSpace(bimi.SvgInvalidReason)) c2.Text($"SVG invalid: {bimi.SvgInvalidReason}");
                        var raw = bimi.Raw;
                        if (raw != null && !string.IsNullOrWhiteSpace(raw.FailureReason))
                        {
                            c2.Text("Failure").Style(TablerTextStyle.Muted);
                            c2.Text(raw.FailureReason ?? string.Empty);
                        }
                        if (raw?.VmcCertificate != null)
                        {
                            var cert = raw.VmcCertificate;
                            c2.Text("VMC certificate").Style(TablerTextStyle.Muted);
                            c2.DataGrid(g => {
                                g.AsCompact();
                                g.AddItem("Subject", cert.Subject ?? "-");
                                g.AddItem("Issuer", cert.Issuer ?? "-");
                                g.AddItem("Valid from", cert.NotBefore.ToString("yyyy-MM-dd"));
                                g.AddItem("Valid to", cert.NotAfter.ToString("yyyy-MM-dd"));
                                g.AddItem("Serial", cert.SerialNumber ?? "-");
                            });
                        }
                        RenderReferences(c2, MergeReferences(bimi.References, narrative?.References));
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
            item.HeaderRight(c => c.Badge(dnsbl.Status ?? "-", ColorForStatus(dnsbl.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true));
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        RenderSummaryGrid(c2, sec?.Summary);
                        if (summaries.Count > 0)
                        {
                            c2.Divider("Provider Trust Grid");
                            c2.DataGrid(g => {
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
                        }
                        RenderPositives(c2, sec?.Positives);
                        RenderFindings(c2, sec?.Findings);
                        RenderNarrative(c2, narrative);
                        var listed = dnsbl.ListedRecords ?? Array.Empty<DNSBLRecord>();
                        bool hasEvidence = summaries.Count > 0 || listed.Count > 0;
                        if (hasEvidence)
                        {
                            c2.Divider("Evidence");
                            if (summaries.Count > 0)
                            {
                                c2.Text("Host summary").Style(TablerTextStyle.Muted);
                                var rows = summaries.Select(s => new {
                                    Host = s.Key,
                                    Listed = $"{s.Listed}/{s.Total}",
                                    Blacklists = s.Blacklists != null && s.Blacklists.Count > 0 ? string.Join(", ", s.Blacklists) : "-"
                                }).ToList();
                                var t = (TablerTable)c2.Table(rows, TableType.Tabler);
                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                            }
                            if (listed.Count > 0)
                            {
                                c2.Text("Listed records").Style(TablerTextStyle.Muted);
                                var rows = listed.Select(r2 => new { Host = r2.SourceHost ?? r2.IpAddress, Blacklist = r2.BlackList, Reason = r2.ReplyMeaning }).ToList();
                                var t = (TablerTable)c2.Table(rows, TableType.Tabler);
                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                            }
                        }
                        RenderReferences(c2, MergeReferences(sec?.References, narrative?.References));
                    });
                });
            });
        });
    }

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
            item.HeaderRight(c => c.Badge(cls.Status ?? "-", ColorForStatus(cls.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true));
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
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
                            c2.Divider("Score Breakdown");
                            var rows = cls.ScoreBreakdown.Select(kv => new { Metric = kv.Key, Value = kv.Value.ToString("0.##") }).ToList();
                            var t = (TablerTable)c2.Table(rows, TableType.Tabler);
                            t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                        }
                        if (cls.ReceivingSignals != null && cls.ReceivingSignals.Count > 0)
                        {
                            c2.Divider("Receiving Signals");
                            foreach (var s in cls.ReceivingSignals) c2.Text("- " + s);
                        }
                        if (cls.SendingSignals != null && cls.SendingSignals.Count > 0)
                        {
                            c2.Divider("Sending Signals");
                            foreach (var s in cls.SendingSignals) c2.Text("- " + s);
                        }
                        RenderPositives(c2, cls.Positives?
                            .Select(p => p?.Title ?? p?.Code)
                            .Where(t => !string.IsNullOrWhiteSpace(t))
                            .Select(t => t!));
                        RenderFindingsFromAssessments(c2, cls.Assessments);
                        RenderNarrative(c2, narrative);
                        var raw = cls.Raw;
                        bool hasEvidence = raw != null
                            && (!string.IsNullOrWhiteSpace(raw.ClassificationReason)
                                || (raw.SPFIncludesResolved?.Count ?? 0) > 0
                                || (raw.DKIMSelectorsFound?.Count ?? 0) > 0
                                || raw.BimiEligible.HasValue
                                || (raw.BimiNotes?.Count ?? 0) > 0
                                || !string.IsNullOrWhiteSpace(raw.IdpTenantId)
                                || !string.IsNullOrWhiteSpace(raw.IdpNameSpaceType)
                                || !string.IsNullOrWhiteSpace(raw.IdpFederatedAuthUrl));
                        if (hasEvidence && raw != null)
                        {
                            c2.Divider("Evidence");
                            if (!string.IsNullOrWhiteSpace(raw.ClassificationReason))
                            {
                                c2.Text("Reason").Style(TablerTextStyle.Muted);
                                c2.Text(raw.ClassificationReason);
                            }
                            if (raw.SPFIncludesResolved != null && raw.SPFIncludesResolved.Count > 0)
                            {
                                c2.Text("SPF includes").Style(TablerTextStyle.Muted);
                                foreach (var include in raw.SPFIncludesResolved)
                                {
                                    c2.Text("- " + include);
                                }
                            }
                            if (raw.DKIMSelectorsFound != null && raw.DKIMSelectorsFound.Count > 0)
                            {
                                c2.Text("DKIM selectors").Style(TablerTextStyle.Muted);
                                foreach (var sel in raw.DKIMSelectorsFound)
                                {
                                    c2.Text("- " + sel);
                                }
                            }
                            if (raw.BimiEligible.HasValue)
                            {
                                c2.Text("BIMI eligibility").Style(TablerTextStyle.Muted);
                                c2.Text(raw.BimiEligible.Value ? "Eligible" : "Not eligible");
                            }
                            if (!string.IsNullOrWhiteSpace(raw.BimiEligibilityReason))
                            {
                                c2.Text("BIMI note").Style(TablerTextStyle.Muted);
                                c2.Text(raw.BimiEligibilityReason ?? string.Empty);
                            }
                            if (raw.BimiNotes != null && raw.BimiNotes.Count > 0)
                            {
                                c2.Text("BIMI notes").Style(TablerTextStyle.Muted);
                                foreach (var note in raw.BimiNotes)
                                {
                                    c2.Text("- " + note);
                                }
                            }
                            if (!string.IsNullOrWhiteSpace(raw.IdpTenantId)
                                || !string.IsNullOrWhiteSpace(raw.IdpNameSpaceType)
                                || !string.IsNullOrWhiteSpace(raw.IdpFederatedAuthUrl))
                            {
                                c2.Text("Identity hints").Style(TablerTextStyle.Muted);
                                if (!string.IsNullOrWhiteSpace(raw.IdpTenantId))
                                {
                                    c2.Text($"Tenant: {raw.IdpTenantId}");
                                }
                                if (!string.IsNullOrWhiteSpace(raw.IdpNameSpaceType))
                                {
                                    c2.Text($"Namespace: {raw.IdpNameSpaceType}");
                                }
                                if (!string.IsNullOrWhiteSpace(raw.IdpFederatedAuthUrl))
                                {
                                    c2.Text($"Federation URL: {raw.IdpFederatedAuthUrl}");
                                }
                            }
                        }
                        RenderReferences(c2, MergeReferences(cls.References, narrative?.References));
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
            item.HeaderRight(c => c.Badge(mtasts.Status ?? "-", ColorForStatus(mtasts.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true));
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        RenderSummaryGrid(c2, sec?.Summary);
                        var help = b.Mx?.ProviderHelp ?? b.Spf?.ProviderHelp;
                        RenderProviderHelpBadges(c2, help, new[] { "MTA-STS" });
                        RenderPositives(c2, sec?.Positives);
                        RenderFindings(c2, sec?.Findings);
                        RenderNarrative(c2, narrative);
                        var raw = mtasts.Raw;
                        bool hasEvidence = raw != null
                            && (!string.IsNullOrWhiteSpace(raw.PolicyId)
                                || !string.IsNullOrWhiteSpace(raw.Policy)
                                || (raw.Mx != null && raw.Mx.Count > 0)
                                || (raw.MissingMxFromPolicy != null && raw.MissingMxFromPolicy.Count > 0));
                        if (hasEvidence && raw != null)
                        {
                            c2.Divider("Evidence");
                            if (!string.IsNullOrWhiteSpace(raw.PolicyId))
                            {
                                c2.Text("MTA-STS TXT:").Style(TablerTextStyle.Muted);
                                c2.Text($"v=STSv1; id={raw.PolicyId}").Style(TablerTextStyle.Monospace);
                            }
                            if (!string.IsNullOrWhiteSpace(raw.Policy))
                            {
                                c2.Text("Policy (mta-sts.txt):").Style(TablerTextStyle.Muted);
                                c2.Text(raw.Policy).Style(TablerTextStyle.Monospace);
                            }
                            if (raw.Mx != null && raw.Mx.Count > 0)
                            {
                                c2.Text("Policy MX Patterns:").Style(TablerTextStyle.Muted);
                                foreach (var mx in raw.Mx) c2.Text("- " + mx);
                            }
                            if (raw.MissingMxFromPolicy != null && raw.MissingMxFromPolicy.Count > 0)
                            {
                                c2.Text("Missing MX in policy:").Style(TablerTextStyle.Muted);
                                foreach (var mx in raw.MissingMxFromPolicy) c2.Text("- " + mx);
                            }
                        }
                        RenderReferences(c2, MergeReferences(sec?.References, narrative?.References));
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
            item.HeaderRight(c => c.Badge(tls.Status ?? "-", ColorForStatus(tls.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true));
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        RenderSummaryGrid(c2, sec?.Summary);
                        var help = b.Mx?.ProviderHelp ?? b.Spf?.ProviderHelp;
                        RenderProviderHelpBadges(c2, help, new[] { "TLS-RPT" });
                        RenderPositives(c2, sec?.Positives);
                        RenderFindings(c2, sec?.Findings);
                        RenderNarrative(c2, narrative);
                        bool hasEvidence = !string.IsNullOrWhiteSpace(tls.TlsRptRecord)
                            || (tls.MailtoRua != null && tls.MailtoRua.Count > 0)
                            || (tls.HttpRua != null && tls.HttpRua.Count > 0)
                            || (tls.InvalidRua != null && tls.InvalidRua.Count > 0)
                            || (tls.UnknownTags != null && tls.UnknownTags.Count > 0);
                        if (hasEvidence)
                        {
                            c2.Divider("Evidence");
                            if (!string.IsNullOrWhiteSpace(tls.TlsRptRecord))
                            {
                                c2.Text("TLS-RPT Record:").Style(TablerTextStyle.Muted);
                                c2.Text(tls.TlsRptRecord!).Style(TablerTextStyle.Monospace);
                            }
                            if ((tls.MailtoRua?.Count ?? 0) + (tls.HttpRua?.Count ?? 0) > 0)
                            {
                                c2.Text("Reporting URIs").Style(TablerTextStyle.Muted);
                                var rows = (tls.MailtoRua ?? Array.Empty<string>())
                                    .Select(x => new { Scheme = "mailto", Uri = x })
                                    .Concat((tls.HttpRua ?? Array.Empty<string>())
                                        .Select(x => new { Scheme = "https", Uri = x }))
                                    .ToList();
                                var t = (TablerTable)c2.Table(rows, TableType.Tabler);
                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                            }
                            if (tls.InvalidRua != null && tls.InvalidRua.Count > 0)
                            {
                                c2.Text("Invalid rua").Style(TablerTextStyle.Muted);
                                foreach (var u in tls.InvalidRua) c2.Text("- " + u);
                            }
                            if (tls.UnknownTags != null && tls.UnknownTags.Count > 0)
                            {
                                c2.Text("Unknown tags").Style(TablerTextStyle.Muted);
                                foreach (var t in tls.UnknownTags) c2.Text("- " + t);
                            }
                        }
                        RenderReferences(c2, MergeReferences(sec?.References, narrative?.References));
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
            item.HeaderRight(c => c.Badge(ns.Status ?? "-", ColorForStatus(ns.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true));
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        RenderSummaryGrid(c2, sec?.Summary);
                        RenderPositives(c2, sec?.Positives);
                        RenderFindings(c2, sec?.Findings);
                        RenderNarrative(c2, narrative);
                        var raw = ns.Raw;
                        bool hasEvidence = raw != null
                            && ((raw.NsRecords?.Count ?? 0) > 0
                                || (raw.ParentNsRecords?.Count ?? 0) > 0
                                || (raw.RootServerResponses?.Count ?? 0) > 0
                                || (raw.RecursionEnabled?.Count ?? 0) > 0);
                        if (hasEvidence && raw != null)
                        {
                            c2.Divider("Evidence");
                            if (raw.NsRecords != null && raw.NsRecords.Count > 0)
                            {
                                c2.Text("Child NS").Style(TablerTextStyle.Muted);
                                foreach (var name in raw.NsRecords)
                                {
                                    c2.Text("- " + name);
                                }
                            }
                            if (raw.ParentNsRecords != null && raw.ParentNsRecords.Count > 0)
                            {
                                c2.Text("Parent NS").Style(TablerTextStyle.Muted);
                                foreach (var name in raw.ParentNsRecords)
                                {
                                    c2.Text("- " + name);
                                }
                            }
                            if (raw.RootServerResponses != null && raw.RootServerResponses.Count > 0)
                            {
                                c2.Text("Root responses").Style(TablerTextStyle.Muted);
                                var rows = raw.RootServerResponses.Select(kv => new { Server = kv.Key, Responded = kv.Value ? "Yes" : "No" }).ToList();
                                var t = (TablerTable)c2.Table(rows, TableType.Tabler);
                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                            }
                            if (raw.RecursionEnabled != null && raw.RecursionEnabled.Count > 0)
                            {
                                c2.Text("Recursion status").Style(TablerTextStyle.Muted);
                                var rows = raw.RecursionEnabled.Select(kv => new { Server = kv.Key, Recursion = kv.Value ? "Yes" : "No" }).ToList();
                                var t = (TablerTable)c2.Table(rows, TableType.Tabler);
                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                            }
                        }
                        RenderReferences(c2, MergeReferences(sec?.References, narrative?.References));
                    });
                });
            });
        });
    }

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
            item.HeaderRight(c => c.Badge(soa.Status ?? "-", ColorForStatus(soa.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true));
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        RenderSummaryGrid(c2, sec?.Summary);
                        RenderFindings(c2, sec?.Findings);
                        RenderNarrative(c2, narrative);
                        var raw = soa.Raw;
                        bool hasEvidence = raw != null && raw.RecordExists;
                        if (hasEvidence && raw != null)
                        {
                            c2.Divider("Evidence");
                            c2.DataGrid(g => {
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
                        }
                        RenderReferences(c2, MergeReferences(sec?.References, narrative?.References));
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
            item.HeaderRight(c => c.Badge(caa.Status ?? "-", ColorForStatus(caa.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true));
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        RenderSummaryGrid(c2, sec?.Summary);
                        RenderPositives(c2, sec?.Positives);
                        RenderFindings(c2, sec?.Findings);
                        RenderNarrative(c2, narrative);
                        var raw = caa.Raw;
                        if (raw != null && raw.AnalysisResults != null && raw.AnalysisResults.Count > 0)
                        {
                            c2.Divider("Evidence");
                            var rows = raw.AnalysisResults.Select(r => new {
                                Record = r.CAARecord,
                                Flag = r.Flag,
                                Tag = r.Tag.ToString(),
                                Value = r.Value,
                                Issuer = string.IsNullOrWhiteSpace(r.Issuer) ? "-" : r.Issuer,
                                Critical = r.Critical ? "Yes" : "No",
                                Invalid = r.Invalid ? "Yes" : "No"
                            }).ToList();
                            var t = (TablerTable)c2.Table(rows, TableType.Tabler);
                            t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                        }
                        RenderReferences(c2, MergeReferences(sec?.References, narrative?.References));
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
            item.HeaderRight(c => c.Badge(dnssec.Status ?? "-", ColorForStatus(dnssec.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true));
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        RenderSummaryGrid(c2, sec?.Summary);
                        RenderPositives(c2, sec?.Positives);
                        RenderFindings(c2, sec?.Findings);
                        RenderNarrative(c2, narrative);
                        var raw = dnssec.Raw;
                        bool hasEvidence = raw != null
                            && ((raw.DsRecords?.Count ?? 0) > 0
                                || (raw.DnsKeys?.Count ?? 0) > 0
                                || (raw.Rrsigs?.Count ?? 0) > 0
                                || raw.RootAnchorExpiration.HasValue
                                || (raw.MismatchSummary?.Count ?? 0) > 0
                                || (raw.Warnings?.Count ?? 0) > 0);
                        if (hasEvidence && raw != null)
                        {
                            c2.Divider("Evidence");
                            if (raw.DsRecords != null && raw.DsRecords.Count > 0)
                            {
                                c2.Text("DS records").Style(TablerTextStyle.Muted);
                                foreach (var ds in raw.DsRecords)
                                {
                                    c2.Text(ds).Style(TablerTextStyle.Monospace);
                                }
                            }
                            if (raw.DnsKeys != null && raw.DnsKeys.Count > 0)
                            {
                                c2.Text("DNSKEY records").Style(TablerTextStyle.Muted);
                                foreach (var key in raw.DnsKeys)
                                {
                                    c2.Text(key).Style(TablerTextStyle.Monospace);
                                }
                            }
                            if (raw.Rrsigs != null && raw.Rrsigs.Count > 0)
                            {
                                c2.Text("RRSIG summary").Style(TablerTextStyle.Muted);
                                var rows = raw.Rrsigs.Select(r => new {
                                    Algorithm = r.Algorithm,
                                    KeyTag = r.KeyTag.ToString(),
                                    Inception = r.Inception == DateTimeOffset.MinValue ? "-" : r.Inception.UtcDateTime.ToString("yyyy-MM-dd"),
                                    Expiration = r.Expiration == DateTimeOffset.MinValue ? "-" : r.Expiration.UtcDateTime.ToString("yyyy-MM-dd")
                                }).ToList();
                                var t = (TablerTable)c2.Table(rows, TableType.Tabler);
                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                            }
                            if (raw.RootAnchorExpiration.HasValue)
                            {
                                c2.Text("Root trust anchor expires").Style(TablerTextStyle.Muted);
                                c2.Text(raw.RootAnchorExpiration.Value.UtcDateTime.ToString("yyyy-MM-dd"));
                            }
                            if (raw.MismatchSummary != null && raw.MismatchSummary.Count > 0)
                            {
                                c2.Text("Mismatch summary").Style(TablerTextStyle.Muted);
                                foreach (var m in raw.MismatchSummary)
                                {
                                    c2.Text("- " + m);
                                }
                            }
                            if (raw.Warnings != null && raw.Warnings.Count > 0)
                            {
                                c2.Text("Warnings").Style(TablerTextStyle.Muted);
                                foreach (var w in raw.Warnings)
                                {
                                    c2.Text("- " + w);
                                }
                            }
                        }
                        RenderReferences(c2, MergeReferences(sec?.References, narrative?.References));
                    });
                });
            });
        });
    }

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
            item.HeaderRight(c => c.Badge(dane.Status ?? "-", ColorForStatus(dane.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true));
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        RenderSummaryGrid(c2, sec?.Summary);
                        RenderPositives(c2, sec?.Positives);
                        RenderFindings(c2, sec?.Findings);
                        RenderNarrative(c2, narrative);
                        var raw = dane.Raw;
                        if (raw != null && raw.AnalysisResults != null && raw.AnalysisResults.Count > 0)
                        {
                            c2.Divider("Evidence");
                            var rows = raw.AnalysisResults.Select(r => new {
                                Host = r.DomainName,
                                Usage = r.CertificateUsage,
                                Selector = r.SelectorField,
                                Matching = r.MatchingTypeField,
                                Valid = r.ValidDANERecord ? "Yes" : "No"
                            }).ToList();
                            var t = (TablerTable)c2.Table(rows, TableType.Tabler);
                            t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                        }
                        RenderReferences(c2, MergeReferences(sec?.References, narrative?.References));
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
            item.HeaderRight(c => c.Badge(rpki.Status ?? "-", ColorForStatus(rpki.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true));
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        RenderSummaryGrid(c2, sec?.Summary);
                        RenderPositives(c2, sec?.Positives);
                        RenderFindings(c2, sec?.Findings);
                        RenderNarrative(c2, narrative);
                        if (rpki.Results != null && rpki.Results.Count > 0)
                        {
                            c2.Divider("Evidence");
                            c2.Text("Per-IP results").Style(TablerTextStyle.Muted);
                            var rows = rpki.Results.Select(r2 => new { r2.IpAddress, r2.Prefix, r2.Asn, Valid = r2.Valid ? "Yes" : "No" }).ToList();
                            var t = (DataTablesTable)c2.Table(rows, TableType.DataTables);
                            t.EnablePaging(10, new[] { 10, 25, 50 }).EnableSearching().EnableOrdering();
                        }
                        RenderReferences(c2, MergeReferences(sec?.References, narrative?.References));
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
            item.HeaderRight(c => c.Badge(zone.Status ?? "-", ColorForStatus(zone.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true));
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        RenderSummaryGrid(c2, sec?.Summary);
                        RenderFindings(c2, sec?.Findings);
                        RenderNarrative(c2, narrative);
                        if (zone.ServerResults != null && zone.ServerResults.Count > 0)
                        {
                            c2.Divider("Evidence");
                            c2.Text("Server results").Style(TablerTextStyle.Muted);
                            var rows = zone.ServerResults.Select(kv => new { Server = kv.Key, Open = kv.Value ? "Yes" : "No" }).ToList();
                            var t = (DataTablesTable)c2.Table(rows, TableType.DataTables);
                            t.EnablePaging(10, new[] { 10, 25, 50 }).EnableSearching().EnableOrdering();
                        }
                        RenderReferences(c2, MergeReferences(sec?.References, narrative?.References));
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
            item.HeaderRight(c => c.Badge(wildcard.Status ?? "-", ColorForStatus(wildcard.Status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true));
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        RenderSummaryGrid(c2, sec?.Summary);
                        RenderFindings(c2, sec?.Findings);
                        RenderNarrative(c2, narrative);
                        var raw = wildcard.Raw;
                        bool hasEvidence = raw != null
                            && ((raw.TestedNames?.Count ?? 0) > 0
                                || (raw.ResolvedNames?.Count ?? 0) > 0
                                || (raw.ResolvedAddresses?.Count ?? 0) > 0);
                        if (hasEvidence && raw != null)
                        {
                            const int maxItems = 10;
                            c2.Divider("Evidence");
                            if (raw.TestedNames != null && raw.TestedNames.Count > 0)
                            {
                                c2.Text("Tested names").Style(TablerTextStyle.Muted);
                                foreach (var name in raw.TestedNames.Take(maxItems))
                                {
                                    c2.Text("- " + name);
                                }
                                if (raw.TestedNames.Count > maxItems)
                                {
                                    c2.Text($"+{raw.TestedNames.Count - maxItems} more").Style(TablerTextStyle.Muted);
                                }
                            }
                            if (raw.ResolvedNames != null && raw.ResolvedNames.Count > 0)
                            {
                                c2.Text("Resolved names").Style(TablerTextStyle.Muted);
                                foreach (var name in raw.ResolvedNames.Take(maxItems))
                                {
                                    c2.Text("- " + name);
                                }
                                if (raw.ResolvedNames.Count > maxItems)
                                {
                                    c2.Text($"+{raw.ResolvedNames.Count - maxItems} more").Style(TablerTextStyle.Muted);
                                }
                            }
                            if (raw.ResolvedAddresses != null && raw.ResolvedAddresses.Count > 0)
                            {
                                c2.Text("Resolved addresses").Style(TablerTextStyle.Muted);
                                foreach (var addr in raw.ResolvedAddresses.Take(maxItems))
                                {
                                    c2.Text("- " + addr);
                                }
                                if (raw.ResolvedAddresses.Count > maxItems)
                                {
                                    c2.Text($"+{raw.ResolvedAddresses.Count - maxItems} more").Style(TablerTextStyle.Muted);
                                }
                            }
                        }
                        RenderReferences(c2, MergeReferences(sec?.References, narrative?.References));
                    });
                });
            });
        });
    }

    private static void RenderMailTlsSection(TablerAccordion acc, DomainBucket b)
    {
        if (b.SmtpTls == null && b.ImapTls == null && b.PopTls == null)
        {
            return;
        }
        var sec = SectionProjectors.BuildMailTls(b.SmtpTls, b.ImapTls, b.PopTls);
        var narrative = b.SmtpTls?.Raw != null
            ? MailTlsNarrative.Build(b.SmtpTls.Raw, DomainDetective.MailTlsAnalysis.MailProtocol.Smtp)
            : b.ImapTls?.Raw != null
                ? MailTlsNarrative.Build(b.ImapTls.Raw, DomainDetective.MailTlsAnalysis.MailProtocol.Imap)
                : b.PopTls?.Raw != null
                    ? MailTlsNarrative.Build(b.PopTls.Raw, DomainDetective.MailTlsAnalysis.MailProtocol.Pop3)
                    : null;
        acc.AddItem("Mail TLS", item => {
            item.Icon(TablerIconType.LockCheck);
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        if (sec != null && sec.Rows.Count > 0)
                        {
                            var rows = sec.Rows.Select(v => new { v.Service, v.Status, Protocol = string.IsNullOrWhiteSpace(v.Protocol) ? "-" : v.Protocol }).ToList();
                            var t = (TablerTable)c2.Table(rows, TableType.Tabler);
                            t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                        }
                        RenderPositives(c2, sec?.Positives);
                        RenderFindings(c2, sec?.Findings);
                        RenderNarrative(c2, narrative);
                        bool hasEvidence = (b.SmtpTls?.Servers?.Count ?? 0) > 0
                            || (b.ImapTls?.Servers?.Count ?? 0) > 0
                            || (b.PopTls?.Servers?.Count ?? 0) > 0;
                        if (hasEvidence)
                        {
                            c2.Divider("Evidence");
                        }
                        if (b.SmtpTls?.Servers != null && b.SmtpTls.Servers.Count > 0) RenderMailTlsServers(c2, "SMTP", b.SmtpTls);
                        if (b.ImapTls?.Servers != null && b.ImapTls.Servers.Count > 0) RenderMailTlsServers(c2, "IMAP", b.ImapTls);
                        if (b.PopTls?.Servers != null && b.PopTls.Servers.Count > 0) RenderMailTlsServers(c2, "POP3", b.PopTls);
                        RenderReferences(c2, MergeReferences(sec?.References, narrative?.References));
                    });
                });
            });
        });
    }

    private static void RenderSummaryGrid(TablerColumn c2, IEnumerable<(string Key, string Value)>? summary)
    {
        if (summary == null)
        {
            return;
        }
        var items = summary.ToList();
        if (items.Count == 0)
        {
            return;
        }
        c2.DataGrid(g => {
            g.AsCompact();
            foreach (var kv in items)
            {
                g.AddItem(kv.Key, kv.Value).AsPanel();
            }
        });
    }

    private static void RenderHighlights(TablerColumn c2, IEnumerable<string>? highlights)
    {
        if (highlights == null)
        {
            return;
        }
        var list = highlights.Where(t => !string.IsNullOrWhiteSpace(t)).ToList();
        if (list.Count == 0)
        {
            return;
        }
        c2.Divider("Highlights");
        var ul = c2.TablerList();
        foreach (var t in list)
        {
            ul.AddItem(t, TablerIconType.AlertTriangle);
        }
    }

    private static void RenderPositives(TablerColumn c2, IEnumerable<string>? positives)
    {
        if (positives == null)
        {
            return;
        }
        var list = positives.Where(t => !string.IsNullOrWhiteSpace(t)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (list.Count == 0)
        {
            return;
        }
        c2.Divider("Good Posture");
        var ul = c2.TablerList();
        foreach (var t in list)
        {
            ul.AddItem(t, TablerIconType.CircleCheck);
        }
    }

    private static void RenderFindings(TablerColumn c2, IEnumerable<SectionProjectors.SimpleFinding>? findings)
    {
        if (findings == null)
        {
            return;
        }
        var rows = findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList();
        if (rows.Count == 0)
        {
            return;
        }
        c2.Divider("Findings");
        var t = (DataTablesTable)c2.Table(rows, TableType.DataTables);
        t.EnablePaging(10, new[] { 10, 25, 50 }).EnableSearching().EnableOrdering();
    }

    private static void RenderFindingsFromAssessments(TablerColumn c2, IEnumerable<Assessment>? assessments)
    {
        if (assessments == null)
        {
            return;
        }
        var list = assessments.Where(a => a != null && a.Severity != AssessmentSeverity.Info)
            .Select(a => new SectionProjectors.SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty))
            .ToList();
        RenderFindings(c2, list);
    }

    private static void RenderNarrative(TablerColumn c2, NarrativeSections? narrative)
    {
        if (narrative == null)
        {
            return;
        }
        var intro = narrative.Introduction;
        var why = narrative.WhyItMatters;
        var details = narrative.Details?.Where(t => !string.IsNullOrWhiteSpace(t)).ToList() ?? new List<string>();
        var remediations = narrative.Remediations?.Where(t => !string.IsNullOrWhiteSpace(t)).ToList() ?? new List<string>();
        bool hasIntro = !string.IsNullOrWhiteSpace(intro);
        bool hasWhy = !string.IsNullOrWhiteSpace(why);
        if (!hasIntro && !hasWhy && details.Count == 0 && remediations.Count == 0)
        {
            return;
        }
        c2.Divider("Guidance");
        if (hasIntro)
        {
            c2.Text("Summary").Style(TablerTextStyle.Muted);
            c2.Text(intro!);
        }
        if (hasWhy)
        {
            c2.Text("Why it matters").Style(TablerTextStyle.Muted);
            c2.Text(why!);
        }
        if (details.Count > 0)
        {
            c2.Text("Details").Style(TablerTextStyle.Muted);
            foreach (var d in details)
            {
                c2.Text("- " + d);
            }
        }
        if (remediations.Count > 0)
        {
            c2.Text("How to fix").Style(TablerTextStyle.Muted);
            foreach (var r in remediations)
            {
                c2.Text("- " + r);
            }
        }
    }

    private static void RenderReferences(TablerColumn c2, IEnumerable<string>? references)
    {
        if (references == null)
        {
            return;
        }
        var list = references.Where(u => !string.IsNullOrWhiteSpace(u)).ToList();
        if (list.Count == 0)
        {
            return;
        }
        c2.Divider("References");
        c2.Row(rr => {
            rr.Gap(2);
            foreach (var u in list)
            {
                var f = LinkFormatter.Format(u);
                rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(f.Title, TablerBadgeColor.Blue, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true, href: f.Url));
            }
        });
    }

    private static IEnumerable<string>? MergeReferences(IEnumerable<string>? first, IEnumerable<string>? second)
    {
        if (first == null && second == null)
        {
            return null;
        }
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var list = new List<string>();
        void AddRange(IEnumerable<string>? src)
        {
            if (src == null)
            {
                return;
            }
            foreach (var s in src)
            {
                if (string.IsNullOrWhiteSpace(s))
                {
                    continue;
                }
                if (set.Add(s)) list.Add(s);
            }
        }
        AddRange(first);
        AddRange(second);
        return list;
    }

    private static void RenderMailTlsServers(TablerColumn c2, string title, MailTlsInfo info)
    {
        var servers = info?.Servers;
        if (servers == null || servers.Count == 0)
        {
            return;
        }
        c2.Divider(title + " Servers");
        var rows = servers.Select(s => new {
            Host = s.Key,
            Status = info?.Status ?? "-",
            StartTLS = s.StartTlsAdvertised ? "Yes" : "No",
            Grade = s.Grade.ToString(),
            Proto = s.Protocol,
            TLS13 = s.Tls13Used ? "Yes" : (s.SupportsTls13 ? "Supported" : "No"),
            Cert = s.CertificateValid ? "Valid" : "Invalid",
            Chain = s.ChainValid ? "Valid" : "Invalid",
            Expires = s.ValidTo.HasValue ? s.ValidTo.Value.ToString("yyyy-MM-dd") : "-",
            DaysToExpire = s.DaysToExpire,
            Cipher = string.IsNullOrWhiteSpace(s.CipherSuite) ? "-" : s.CipherSuite
        }).ToList();
        var tt = (TablerTable)c2.Table(rows, TableType.Tabler);
        tt.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
    }

    private static void RenderProviderHelpBadges(TablerColumn c2, IReadOnlyList<ProviderHelpLinks>? help, IEnumerable<string>? topicFilter)
    {
        if (help == null || help.Count == 0)
        {
            return;
        }
        var filter = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (topicFilter != null)
        {
            foreach (var t in topicFilter)
            {
                if (!string.IsNullOrWhiteSpace(t))
                {
                    filter.Add(t);
                }
            }
        }
        bool any = false;
        foreach (var ph in help)
        {
            var topics = NormalizeProviderTopics(ph);
            if (filter.Count > 0) topics = topics.Where(t => filter.Contains(t.Topic)).ToList();
            if (topics.Count > 0)
            {
                any = true;
                break;
            }
        }
        if (!any)
        {
            return;
        }

        c2.Divider("Provider Help");
        foreach (var ph in help)
        {
            if (ph == null)
            {
                continue;
            }
            var topics = NormalizeProviderTopics(ph);
            if (filter.Count > 0) topics = topics.Where(t => filter.Contains(t.Topic)).ToList();
            if (topics.Count == 0)
            {
                continue;
            }
            var ordered = topics.OrderBy(t => TopicOrderIndex(t.Topic)).ThenBy(t => t.Topic, StringComparer.OrdinalIgnoreCase).ToList();
            c2.Row(rr => {
                rr.Gap(2);
                if (!string.IsNullOrWhiteSpace(ph.ProviderName))
                {
                    rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(ph.ProviderName, TablerBadgeColor.Secondary, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true));
                }
                foreach (var t in ordered)
                {
                    var title = string.IsNullOrWhiteSpace(t.Title) ? t.Topic : t.Title;
                    rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(title ?? t.Topic, TablerBadgeColor.Blue, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true, href: t.Url));
                    if (!t.IsPublic)
                    {
                        rr.Column(TablerColumnNumber.Auto, cc => cc.Badge("Login", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true));
                    }
                    if (t.IsThirdParty)
                    {
                        rr.Column(TablerColumnNumber.Auto, cc => cc.Badge("Third-party", TablerBadgeColor.Secondary, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true));
                    }
                    if (t.LastVerified.HasValue && t.LastVerified.Value != DateTime.MinValue)
                    {
                        rr.Column(TablerColumnNumber.Auto, cc => cc.Badge($"Verified {t.LastVerified.Value:yyyy-MM-dd}", TablerBadgeColor.Info, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true));
                    }
                }
            });
        }
        c2.Text("Legend: Login = requires provider login; Third-party = non-vendor resource; Verified = last verified date.")
            .Style(TablerTextStyle.Muted);
    }

    private static List<ProviderHelpTopic> NormalizeProviderTopics(ProviderHelpLinks ph)
    {
        var list = new List<ProviderHelpTopic>();
        if (ph?.Topics != null && ph.Topics.Count > 0)
        {
            list.AddRange(ph.Topics.Where(t => t != null));
        }
        if (list.Count == 0 && ph != null)
        {
            if (!string.IsNullOrWhiteSpace(ph.Dmarc)) list.Add(new ProviderHelpTopic { Topic = "DMARC", Url = ph.Dmarc, Title = $"{ph.ProviderName} - DMARC" });
            if (!string.IsNullOrWhiteSpace(ph.Spf)) list.Add(new ProviderHelpTopic { Topic = "SPF", Url = ph.Spf, Title = $"{ph.ProviderName} - SPF" });
            if (!string.IsNullOrWhiteSpace(ph.Dkim)) list.Add(new ProviderHelpTopic { Topic = "DKIM", Url = ph.Dkim, Title = $"{ph.ProviderName} - DKIM" });
            if (!string.IsNullOrWhiteSpace(ph.MtaSts)) list.Add(new ProviderHelpTopic { Topic = "MTA-STS", Url = ph.MtaSts, Title = $"{ph.ProviderName} - MTA-STS" });
            if (!string.IsNullOrWhiteSpace(ph.TlsRpt)) list.Add(new ProviderHelpTopic { Topic = "TLS-RPT", Url = ph.TlsRpt, Title = $"{ph.ProviderName} - TLS-RPT" });
            if (!string.IsNullOrWhiteSpace(ph.Deliverability)) list.Add(new ProviderHelpTopic { Topic = "Deliverability", Url = ph.Deliverability, Title = $"{ph.ProviderName} - Deliverability" });
        }
        return list.Where(t => !string.IsNullOrWhiteSpace(t.Url)).ToList();
    }

    private static int TopicOrderIndex(string topic)
    {
        if (string.IsNullOrWhiteSpace(topic)) return int.MaxValue;
        var key = topic.Trim().ToUpperInvariant();
        var idx = Array.IndexOf(ProviderTopicOrder, key);
        return idx >= 0 ? idx : int.MaxValue;
    }
}
