using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
// HtmlForgeX types (Tabler*, DataTables*, etc.)
using HtmlForgeX.Containers.Tabler;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HtmlCompositionReport partial: single-domain view (header + details tabs).
/// </summary>
public static partial class HtmlCompositionReport
{
    private static void RenderSingleDomain(HtmlForgeX.TablerPage page, string d, DomainBucket b)
    {
        page.Divider(d);
        page.Row(row => {
            row.Column(TablerColumnNumber.Twelve, col => {
                col.Card(card => {
                    // Ribbon severity
                    var sevColor = TablerColor.Blue;
                    var statusText = "OK";
                    var warnCount = (b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + b.Dkim.Sum(x => x.WarningCount);
                    var errCount = (b.Mx?.ErrorCount ?? 0) + (b.Spf?.ErrorCount ?? 0) + (b.Dmarc?.ErrorCount ?? 0) + (b.Mtasts?.ErrorCount ?? 0) + (b.TlsRpt?.ErrorCount ?? 0) + b.Dkim.Sum(x => x.ErrorCount);
                    if (errCount > 0) { sevColor = TablerColor.Danger; statusText = $"{errCount} Error" + (errCount > 1 ? "s" : ""); }
                    else if (warnCount > 0) { sevColor = TablerColor.Warning; statusText = $"{warnCount} Warning" + (warnCount > 1 ? "s" : ""); }
                    card.Ribbon(statusText, sevColor)
                        .Header(h => {
                            h.Title($"Mail & DNS — {d}")
                             .Subtitle($"{warnCount} warning(s), {errCount} error(s)")
                             .SubtitleStyle(TablerTextStyle.Muted)
                             .WithActions(a => {
                                 a.Badge(errCount > 0 ? $"{errCount} Error" + (errCount>1?"s":"") : "0 Error", TablerBadgeColor.Danger, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                 a.Badge(warnCount > 0 ? $"{warnCount} Warning" + (warnCount>1?"s":"") : "0 Warning", TablerBadgeColor.Warning, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                 a.Badge($"MX: {b.Mx?.Status ?? "-"}", ColorForStatus(b.Mx?.Status), HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                 a.Badge($"SPF: {b.Spf?.Status ?? "-"}", ColorForStatus(b.Spf?.Status), HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                 var dk = b.Dkim.Count > 0 ? (b.Dkim.Max(x => x.Status) ?? "-") : "-";
                                 a.Badge($"DKIM: {dk}", ColorForStatus(dk), HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                 a.Badge($"DMARC: {b.Dmarc?.Status ?? "-"}", ColorForStatus(b.Dmarc?.Status), HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                 a.Badge($"MTA-STS: {b.Mtasts?.Status ?? "-"}", ColorForStatus(b.Mtasts?.Status), HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                 a.Badge($"TLS-RPT: {b.TlsRpt?.Status ?? "-"}", ColorForStatus(b.TlsRpt?.Status), HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                             });
                        });
                    card.Body(body => {
                        var dkimStatus = b.Dkim.Count > 0 ? (b.Dkim.Max(x => x.Status) ?? "-") : "-";
                        body.Text($"SPF {b.Spf?.Status ?? "-"}, DMARC {b.Dmarc?.Status ?? "-"}, DKIM {dkimStatus}, MX {b.Mx?.Status ?? "-"}, MTA-STS {b.Mtasts?.Status ?? "-"}, TLS-RPT {b.TlsRpt?.Status ?? "-"}").Style(TablerTextStyle.Muted);
                    });
                });

                // Tabbed details per domain
                col.Card(card => {
                    card.Header(h => h.Title("Details").Subtitle("Overview and deep-dive sections"));
                    card.Body(body => {
                        body.SmartTab(tabs => {
                            tabs.WithTheme(SmartTabTheme.Pills)
                                .WithNavStyle(SmartTabNavStyle.Tabs)
                                .WithSelectedTab(0)
                                .Justified(true)
                                .AutoAdjustHeight(true)
                                .WithCardHeaderLook(true);

                            // Overview tab (row of chips, no DataGrid)
                            tabs.AddTab("Overview", TablerIconType.InfoCircle, panel => {
                                var dkimStatus = b.Dkim.Count > 0 ? (b.Dkim.Max(x => x.Status) ?? "-") : "-";
                                var w = (b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + b.Dkim.Sum(x => x.WarningCount);
                                var e = (b.Mx?.ErrorCount ?? 0) + (b.Spf?.ErrorCount ?? 0) + (b.Dmarc?.ErrorCount ?? 0) + (b.Mtasts?.ErrorCount ?? 0) + (b.TlsRpt?.ErrorCount ?? 0) + b.Dkim.Sum(x => x.ErrorCount);
                                panel.Row(r => {
                                    r.Gap(2);
                                    r.Column(TablerColumnNumber.Auto, cc => { cc.Text("Domain").Style(TablerTextStyle.Muted); cc.H4(d); });
                                    r.Column(TablerColumnNumber.Auto, cc => { cc.Text("Findings").Style(TablerTextStyle.Muted); cc.Text($"{w} warning(s), {e} error(s)"); });
                                    r.Column(TablerColumnNumber.Auto, cc => { cc.Text("MX").Style(TablerTextStyle.Muted); cc.Badge(b.Mx?.Status ?? "-", ColorForStatus(b.Mx?.Status), HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true); });
                                    r.Column(TablerColumnNumber.Auto, cc => { cc.Text("SPF").Style(TablerTextStyle.Muted); cc.Badge(b.Spf?.Status ?? "-", ColorForStatus(b.Spf?.Status), HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true); });
                                    r.Column(TablerColumnNumber.Auto, cc => { cc.Text("DKIM").Style(TablerTextStyle.Muted); cc.Badge(dkimStatus, ColorForStatus(dkimStatus), HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true); });
                                    r.Column(TablerColumnNumber.Auto, cc => { cc.Text("DMARC").Style(TablerTextStyle.Muted); cc.Badge(b.Dmarc?.Status ?? "-", ColorForStatus(b.Dmarc?.Status), HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true); });
                                    r.Column(TablerColumnNumber.Auto, cc => { cc.Text("MTA-STS").Style(TablerTextStyle.Muted); cc.Badge(b.Mtasts?.Status ?? "-", ColorForStatus(b.Mtasts?.Status), HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true); });
                                    r.Column(TablerColumnNumber.Auto, cc => { cc.Text("TLS-RPT").Style(TablerTextStyle.Muted); cc.Badge(b.TlsRpt?.Status ?? "-", ColorForStatus(b.TlsRpt?.Status), HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true); });
                                });
                            });

                            // Email Auth tab with accordion
                            tabs.AddTab("Email Auth", TablerIconType.ShieldLock, panel => {
                                panel.Accordion(a => {
                                    if (b.Spf != null) a.AddItem("SPF", it => it.Content(c => {
                                        c.DataGrid(g => { g.AsCompact(); g.AddItem("Status", b.Spf.Status ?? "-"); g.AddItem("DNS Lookups", b.Spf.DnsLookupsCount.ToString()); });
                                        if ((b.Spf.Positives?.Count ?? 0) > 0) { c.Divider("Good Posture"); foreach (var p in b.Spf.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()) { var t = p?.Title; if (!string.IsNullOrWhiteSpace(t)) c.Text("• " + t); } }
                                        var spfFindings = (b.Spf.Assessments ?? Array.Empty<DomainDetective.Assessment>()).Where(x => x != null && x.Severity != DomainDetective.AssessmentSeverity.Info).Select(x => new { Severity = x.Severity.ToString(), x.Code, x.Target, x.Message }).ToList();
                                        if (spfFindings.Count > 0) { c.Divider("Findings"); var t = (TablerTable)c.Table(spfFindings, TableType.Tabler); t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover); }
                                        var spfRefs = b.Spf.References?.Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
                                        if ((spfRefs?.Count ?? 0) > 0) { c.Divider("References"); foreach (var url in spfRefs!) c.Text("• " + url); }
                                    }));

                                    if (b.Dmarc != null) a.AddItem("DMARC", it => it.Content(c => {
                                        c.DataGrid(g => { g.AsCompact(); g.AddItem("Status", b.Dmarc.Status ?? "-"); g.AddItem("Policy", string.IsNullOrWhiteSpace(b.Dmarc.Policy) ? "-" : b.Dmarc.Policy); });
                                        if ((b.Dmarc.Positives?.Count ?? 0) > 0) { c.Divider("Good Posture"); foreach (var p in b.Dmarc.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()) { var t = p?.Title; if (!string.IsNullOrWhiteSpace(t)) c.Text("• " + t); } }
                                        var dmarcFindings = (b.Dmarc.Assessments ?? Array.Empty<DomainDetective.Assessment>()).Where(x => x != null && x.Severity != DomainDetective.AssessmentSeverity.Info).Select(x => new { Severity = x.Severity.ToString(), x.Code, x.Target, x.Message }).ToList();
                                        if (dmarcFindings.Count > 0) { c.Divider("Findings"); var t = (TablerTable)c.Table(dmarcFindings, TableType.Tabler); t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover); }
                                        var dmarcRefs = b.Dmarc.References?.Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
                                        if ((dmarcRefs?.Count ?? 0) > 0) { c.Divider("References"); foreach (var url in dmarcRefs!) c.Text("• " + url); }
                                    }));

                                    if (b.Dkim.Count > 0) a.AddItem("DKIM", it => it.Content(c => {
                                        c.DataGrid(g => { g.AsCompact(); g.AddItem("Selectors", b.Dkim.Count.ToString()); g.AddItem("Any Weak", b.Dkim.Any(x => x.WeakKey).ToString()); });
                                        var dkPos = b.Dkim.SelectMany(x => x.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()).Where(p => !string.IsNullOrWhiteSpace(p?.Title)).Select(p => p!.Title!).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                                        if (dkPos.Count > 0) { c.Divider("Good Posture"); foreach (var t in dkPos) c.Text("• " + t); }
                                        var dkFind = b.Dkim.SelectMany(x => x.Assessments ?? Array.Empty<DomainDetective.Assessment>()).Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info).Select(a => new { Severity = a.Severity.ToString(), a.Code, a.Target, a.Message }).ToList();
                                        if (dkFind.Count > 0) { c.Divider("Findings"); var t = (TablerTable)c.Table(dkFind, TableType.Tabler); t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover); }
                                        var dkRefs = b.Dkim.SelectMany(x => x.References ?? Array.Empty<string>()).Where(s => !string.IsNullOrWhiteSpace(s)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                                        if (dkRefs.Count > 0) { c.Divider("References"); foreach (var url in dkRefs) c.Text("• " + url); }
                                    }));
                                });
                            });

                            // Transport tab
                            tabs.AddTab("Transport", TablerIconType.TruckDelivery, panel => {
                                panel.DataGrid(g => { g.AsCompact(); g.AddItem("MTA-STS", b.Mtasts?.Status ?? "-"); g.AddItem("TLS-RPT", b.TlsRpt?.Status ?? "-"); });
                                if (b.Mtasts != null)
                                {
                                    var mtFind = (b.Mtasts.Assessments ?? Array.Empty<DomainDetective.Assessment>()).Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info).Select(a => new { Severity = a.Severity.ToString(), a.Code, a.Target, a.Message }).ToList();
                                    if (mtFind.Count > 0) { panel.Divider("MTA-STS Findings"); var t = (TablerTable)panel.Table(mtFind, TableType.Tabler); t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover); }
                                    var mtRefs = b.Mtasts.References?.Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
                                    if ((mtRefs?.Count ?? 0) > 0) { panel.Divider("MTA-STS References"); panel.Row(r => r.Column(TablerColumnNumber.Twelve, c2 => { foreach (var url in mtRefs!) c2.Text("• " + url); })); }
                                }
                                if (b.TlsRpt != null)
                                {
                                    var trFind = (b.TlsRpt.Assessments ?? Array.Empty<DomainDetective.Assessment>()).Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info).Select(a => new { Severity = a.Severity.ToString(), a.Code, a.Target, a.Message }).ToList();
                                    if (trFind.Count > 0) { panel.Divider("TLS-RPT Findings"); var t = (TablerTable)panel.Table(trFind, TableType.Tabler); t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover); }
                                    var trRefs = b.TlsRpt.References?.Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
                                    if ((trRefs?.Count ?? 0) > 0) { panel.Divider("TLS-RPT References"); panel.Row(r => r.Column(TablerColumnNumber.Twelve, c2 => { foreach (var url in trRefs!) c2.Text("• " + url); })); }
                                }
                            });

                            // Reputation tab (DNSBL)
                            if (b.Dnsbl != null)
                            {
                                tabs.AddTab("Reputation", TablerIconType.ShieldCheck, panel => {
                                    var db = b.Dnsbl;
                                    panel.DataGrid(g => { g.AsCompact(); g.AddItem("Providers Checked", db.ProvidersChecked.ToString()); g.AddItem("Hosts Checked", db.HostsChecked.ToString()); g.AddItem("Hosts Listed", db.HostsListed.ToString()); });
                                    var listed = db.ListedRecords?.Select(r => new { Host = r.SourceHost ?? r.IpAddress, Blacklist = r.BlackList, Reason = r.ReplyMeaning }).ToList();
                                    if (listed != null && listed.Count > 0) { panel.Divider("Listed Records"); var t = (TablerTable)panel.Table(listed, TableType.Tabler); t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover); }
                                });
                            }
                        });
                    });
                });
            });
        });
    }
}
