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
        if (b.Mx != null || b.SmtpTls != null || b.ImapTls != null || b.PopTls != null || b.Mtasts != null || b.TlsRpt != null || b.TlsRptReports != null || b.Dane != null)
            list.Add("Mail Transport Posture");
        if (b.Spf != null) list.Add("SPF");
        if (b.Dkim.Count > 0) list.Add("DKIM");
	        if (b.Dmarc != null) list.Add("DMARC");
	        if (b.DmarcAggregate != null) list.Add("DMARC Aggregate");
	        if (b.Registration != null) list.Add("Registration");
	        if (b.Http != null) list.Add("HTTP");
	        if (b.CtTimeline != null) list.Add("CT Timeline");
        if (b.Subdomains != null) list.Add("Subdomains");
        if (b.DnsInventory != null) list.Add("DNS Inventory");
        if (b.DnsTrace != null) list.Add("DNS Trace");
        if (b.DnsPropagation != null && b.DnsPropagation.Count > 0) list.Add("DNS Propagation");
        if (b.DnsAmplification != null) list.Add("DNS Amplification");
        if (b.DnsOverTls != null) list.Add("DNS over TLS");
        if (b.IpEnrichment != null) list.Add("IP Enrichment");
        if (b.Arc != null) list.Add("ARC");
        if (b.Bimi != null) list.Add("BIMI");
        if (b.Dnsbl != null) list.Add("DNSBL");
        if (b.Rpki != null) list.Add("RPKI");
        if (b.Ns != null) list.Add("NS");
        if (b.Soa != null) list.Add("SOA");
        if (b.Ttl != null) list.Add("TTL");
        if (b.ZoneTransfer != null) list.Add("ZoneTransfer");
        if (b.Wildcard != null) list.Add("Wildcard");
        if (b.Caa != null) list.Add("CAA");
        if (b.Classification != null) list.Add("Classification");
        if (b.Mtasts != null) list.Add("MTA-STS");
        if (b.TlsRpt != null) list.Add("TLS-RPT");
        if (b.TlsRptReports != null) list.Add("TLS-RPT Reports");
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
                case "Mail Transport Posture":
                    RenderMailTransportPostureSection(acc, b);
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
                case "DMARC Aggregate":
                    RenderDmarcAggregateSection(acc, b);
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
                case "TLS-RPT Reports":
                    RenderTlsRptReportsSection(acc, b);
                    break;
	                case "Registration":
	                    RenderRegistrationSection(acc, b);
	                    break;
	                case "HTTP":
	                    RenderHttpSection(acc, b);
	                    break;
	                case "CT Timeline":
	                    RenderCtTimelineSection(acc, b);
	                    break;
                case "Subdomains":
                    RenderSubdomainsSection(acc, b);
                    break;
                case "DNS Inventory":
                    RenderDnsInventorySection(acc, b);
                    break;
                case "DNS Trace":
                    RenderDnsTraceSection(acc, b);
                    break;
                case "DNS Propagation":
                    RenderDnsPropagationSection(acc, b);
                    break;
                case "DNS Amplification":
                    RenderDnsAmplificationSection(acc, b);
                    break;
                case "DNS over TLS":
                    RenderDnsOverTlsSection(acc, b);
                    break;
                case "IP Enrichment":
                    RenderIpEnrichmentSection(acc, b);
                    break;
                case "NS":
                    RenderNsSection(acc, b);
                    break;
                case "SOA":
                    RenderSoaSection(acc, b);
                    break;
                case "TTL":
                    RenderTtlSection(acc, b);
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

    private static void RenderMailTlsSection(TablerAccordion acc, DomainBucket b)
    {
        if (b.SmtpTls == null && b.ImapTls == null && b.PopTls == null)
        {
            return;
        }
        var sec = SectionProjectors.BuildMailTls(b.SmtpTls, b.ImapTls, b.PopTls);
        int warnCount = (b.SmtpTls?.WarningCount ?? 0) + (b.ImapTls?.WarningCount ?? 0) + (b.PopTls?.WarningCount ?? 0);
        int errCount = (b.SmtpTls?.ErrorCount ?? 0) + (b.ImapTls?.ErrorCount ?? 0) + (b.PopTls?.ErrorCount ?? 0);
        var status = errCount > 0 ? "Error" : (warnCount > 0 ? "Warning" : "OK");
        var narrative = b.SmtpTls?.Raw != null
            ? MailTlsNarrative.Build(b.SmtpTls.Raw, DomainDetective.MailTlsAnalysis.MailProtocol.Smtp)
            : b.ImapTls?.Raw != null
                ? MailTlsNarrative.Build(b.ImapTls.Raw, DomainDetective.MailTlsAnalysis.MailProtocol.Imap)
                : b.PopTls?.Raw != null
                    ? MailTlsNarrative.Build(b.PopTls.Raw, DomainDetective.MailTlsAnalysis.MailProtocol.Pop3)
                    : null;
        acc.AddItem("Mail TLS", item => {
            item.Icon(TablerIconType.LockCheck);
            item.HeaderRight(c =>
            {
                c.Badge(errCount > 0 ? $"{errCount} Error" + (errCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(warnCount > 0 ? $"{warnCount} Warning" + (warnCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(status, ColorForStatus(status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        bool useNewLayout = true;
                        if (useNewLayout)
                        {
                            var findingsCount = warnCount + errCount;
                            var findingsBadgeColor = errCount > 0
                                ? TablerBadgeColor.Danger
                                : (warnCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);
                            var refs = MergeReferences(sec?.References, narrative?.References);

                            RenderExecutionSnapshotCard(c2, g =>
                            {
                                g.AddItem("Status", status).AsPanel(PanelColorForStatus(status), light: true);
                                g.AddItem("Warnings", warnCount.ToString()).AsPanel(warnCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                                g.AddItem("Errors", errCount.ToString()).AsPanel(errCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);

                                if (b.SmtpTls != null) g.AddItem("SMTP", b.SmtpTls.Status ?? "-").AsPanel(PanelColorForStatus(b.SmtpTls.Status), light: true);
                                if (b.ImapTls != null) g.AddItem("IMAP", b.ImapTls.Status ?? "-").AsPanel(PanelColorForStatus(b.ImapTls.Status), light: true);
                                if (b.PopTls != null) g.AddItem("POP3", b.PopTls.Status ?? "-").AsPanel(PanelColorForStatus(b.PopTls.Status), light: true);
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
                                        if (sec != null && sec.Rows.Count > 0)
                                        {
                                            hasEvidence = true;
                                            var rows = sec.Rows.Select(v => new
                                            {
                                                v.Service,
                                                v.Status,
                                                Protocol = string.IsNullOrWhiteSpace(v.Protocol) ? "-" : v.Protocol
                                            }).ToList();
                                            var t = (TablerTable)col.Table(rows, TableType.Tabler);
                                            t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                        }

                                        if (b.SmtpTls?.Servers != null && b.SmtpTls.Servers.Count > 0)
                                        {
                                            hasEvidence = true;
                                            RenderMailTlsServers(col, "SMTP", b.SmtpTls);
                                        }
                                        if (b.ImapTls?.Servers != null && b.ImapTls.Servers.Count > 0)
                                        {
                                            hasEvidence = true;
                                            RenderMailTlsServers(col, "IMAP", b.ImapTls);
                                        }
                                        if (b.PopTls?.Servers != null && b.PopTls.Servers.Count > 0)
                                        {
                                            hasEvidence = true;
                                            RenderMailTlsServers(col, "POP3", b.PopTls);
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
                            if (sec != null && sec.Rows.Count > 0)
                            {
                                var rows = sec.Rows.Select(v => new { v.Service, v.Status, Protocol = string.IsNullOrWhiteSpace(v.Protocol) ? "-" : v.Protocol }).ToList();
                                var t = (TablerTable)c2.Table(rows, TableType.Tabler);
                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                            }
                            RenderPositives(c2, sec?.Positives);
                            RenderFindings(c2, sec?.Findings);
                            RenderNarrative(c2, narrative);
                            if (b.SmtpTls?.Servers != null && b.SmtpTls.Servers.Count > 0) RenderMailTlsServers(c2, "SMTP", b.SmtpTls);
                            if (b.ImapTls?.Servers != null && b.ImapTls.Servers.Count > 0) RenderMailTlsServers(c2, "IMAP", b.ImapTls);
                            if (b.PopTls?.Servers != null && b.PopTls.Servers.Count > 0) RenderMailTlsServers(c2, "POP3", b.PopTls);
                            RenderReferences(c2, MergeReferences(sec?.References, narrative?.References));
                        }
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

    private static void RenderSignalsSummary(TablerColumn c2, IEnumerable<string>? highlights, IEnumerable<string>? positives)
    {
        var issues = (highlights ?? Array.Empty<string>())
            .Where(t => !string.IsNullOrWhiteSpace(t))
            .Select(t => t.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var good = (positives ?? Array.Empty<string>())
            .Where(t => !string.IsNullOrWhiteSpace(t))
            .Select(t => t.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (issues.Count == 0 && good.Count == 0)
        {
            c2.Text("No notable signals captured for this check.").Style(TablerTextStyle.Muted);
            return;
        }

        const int maxItems = 12;
        int issuesMore = Math.Max(0, issues.Count - maxItems);
        int goodMore = Math.Max(0, good.Count - maxItems);
        issues = issues.Take(maxItems).ToList();
        good = good.Take(maxItems).ToList();

        foreach (var t in issues)
        {
            c2.Alert(TrimForDisplay(t, 320), string.Empty, TablerColor.Orange)
                .Icon(TablerIconType.AlertTriangle)
                .Minor();
        }
        if (issuesMore > 0)
        {
            c2.Text($"+{issuesMore} more issue(s)…").Style(TablerTextStyle.Muted);
        }

        foreach (var t in good)
        {
            c2.Alert(TrimForDisplay(t, 320), string.Empty, TablerColor.Green)
                .Icon(TablerIconType.CircleCheck)
                .Minor();
        }
        if (goodMore > 0)
        {
            c2.Text($"+{goodMore} more positive signal(s)…").Style(TablerTextStyle.Muted);
        }
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
        c2.Card(card =>
        {
            card.Header(h => h.Title("Highlights").Icon(TablerIconType.AlertTriangle));
            card.Body(body =>
            {
                var ul = body.TablerList();
                foreach (var t in list)
                {
                    ul.AddItem(t, TablerIconType.AlertTriangle);
                }
            });
        });
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
        c2.Card(card =>
        {
            card.Header(h => h.Title("Good Posture").Icon(TablerIconType.CircleCheck));
            card.Body(body =>
            {
                var ul = body.TablerList();
                foreach (var t in list)
                {
                    ul.AddItem(t, TablerIconType.CircleCheck);
                }
            });
        });
    }

    private static void RenderFindings(TablerColumn c2, IEnumerable<SectionProjectors.SimpleFinding>? findings)
    {
        if (findings == null)
        {
            return;
        }
        var rows = findings
            .Select(a => new { a.Severity, a.Target, a.Message })
            .ToList();
        if (rows.Count == 0)
        {
            return;
        }
        var t = (DataTablesTable)c2.Table(rows, TableType.DataTables);
        ConfigureStandardDataTable(t, defaultMode: ToggleViewMode.ScrollX);
        t.EnablePaging(10, new[] { 10, 25, 50 })
            .EnableSearching()
            .EnableOrdering()
            .HighlightWhen(
                where: g => g.And(c => c.StringContains("Severity", "error", false)),
                then: tt => { tt.Column("Severity").Danger(); tt.HighlightParent(true); })
            .HighlightWhen(
                where: g => g.And(c => c.StringContains("Severity", "warn", false)),
                then: tt => { tt.Column("Severity").Warning(); tt.HighlightParent(true); });
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
        RenderGuidanceWizardCard(c2, narrative, providerHelp: null, providerHelpTopics: null, references: null);
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
        c2.Card(card =>
        {
            card.Header(h => h.Title("References").Icon(TablerIconType.Link));
            card.Body(body =>
            {
                body.Row(rr =>
                {
                    rr.Gap(2);
                    foreach (var u in list)
                    {
                        var f = LinkFormatter.Format(u);
                        rr.Column(
                            TablerColumnNumber.Auto,
                            cc => cc.Badge(
                                f.Title,
                                TablerBadgeColor.Blue,
                                TablerBadgeVisualStyle.Light,
                                TablerBadgeSize.Small,
                                pill: true,
                                href: f.Url));
                    }
                });
            });
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
        c2.Card(card =>
        {
            card.Header(h => h.Title($"{title} Servers").Icon(TablerIconType.LockCheck));
            card.Body(body =>
            {
                var rows = servers.Select(s => new
                {
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
                var tt = (DataTablesTable)body.Table(rows, TableType.DataTables);
                ConfigureStandardDataTable(tt, defaultMode: ToggleViewMode.ScrollX);
                tt.EnablePaging(10, new[] { 10, 25, 50 })
                  .EnableSearching()
                  .EnableOrdering();
            });
        });
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

        c2.Card(card =>
        {
            card.Header(h => h.Title("Provider Help").Icon(TablerIconType.Link));
            card.Body(body =>
            {
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
                    body.Row(rr =>
                    {
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
                body.Text("Legend: Login = requires provider login; Third-party = non-vendor resource; Verified = last verified date.").Style(TablerTextStyle.Muted);
            });
        });
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
