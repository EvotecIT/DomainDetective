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
                                        var sec = DomainDetective.Reports.SectionProjectors.BuildSpf(b.Spf);
                                        c.DataGrid(g => { g.AsCompact(); foreach (var kvp in sec!.Summary) g.AddItem(kvp.Key, kvp.Value); });
                                        if (sec!.Positives.Count > 0) { c.Divider("Good Posture"); foreach (var t in sec.Positives) c.Text("• " + t); }
                                        if (sec.Findings.Count > 0) { c.Divider("Findings"); var rows = sec.Findings.Select(x => new { x.Severity, x.Code, x.Target, x.Message }).ToList(); var tt = (TablerTable)c.Table(rows, TableType.Tabler); tt.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover); }
                                        if (sec.References.Count > 0) { c.Divider("References"); foreach (var url in sec.References) c.Text("• " + url); }
                                    }));

                                    if (b.Dmarc != null) a.AddItem("DMARC", it => it.Content(c => {
                                        var sec = DomainDetective.Reports.SectionProjectors.BuildDmarc(b.Dmarc);
                                        c.DataGrid(g => { g.AsCompact(); foreach (var kvp in sec!.Summary) g.AddItem(kvp.Key, kvp.Value); });
                                        if (sec!.Positives.Count > 0) { c.Divider("Good Posture"); foreach (var t in sec.Positives) c.Text("• " + t); }
                                        if (sec.Findings.Count > 0) { c.Divider("Findings"); var rows = sec.Findings.Select(x => new { x.Severity, x.Code, x.Target, x.Message }).ToList(); var tt = (TablerTable)c.Table(rows, TableType.Tabler); tt.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover); }
                                        if (sec.References.Count > 0) { c.Divider("References"); foreach (var url in sec.References) c.Text("• " + url); }
                                    }));

                                    if (b.Dkim.Count > 0) a.AddItem("DKIM", it => it.Content(c => {
                                        var sec = DomainDetective.Reports.SectionProjectors.BuildDkim(b.Dkim);
                                        c.DataGrid(g => { g.AsCompact(); g.AddItem("Selectors", b.Dkim.Count.ToString()); g.AddItem("Any Weak", b.Dkim.Any(x => x.WeakKey).ToString()); });
                                        if (sec!.Rows.Count > 0) { var rows = sec.Rows.Select(r => new { r.Selector, r.Status, KeyBits = r.KeyBits, Hash = r.Hash }).ToList(); var tt = (TablerTable)c.Table(rows, TableType.Tabler); tt.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover); }
                                        if (sec.Positives.Count > 0) { c.Divider("Good Posture"); foreach (var t in sec.Positives) c.Text("• " + t); }
                                        if (sec.Findings.Count > 0) { c.Divider("Findings"); var rows2 = sec.Findings.Select(x => new { x.Severity, x.Code, x.Target, x.Message }).ToList(); var tt2 = (TablerTable)c.Table(rows2, TableType.Tabler); tt2.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover); }
                                        if (sec.References.Count > 0) { c.Divider("References"); foreach (var url in sec.References) c.Text("• " + url); }
                                    }));
                                });
                            });

                            // Transport tab — via SectionProjectors
                            tabs.AddTab("Transport", TablerIconType.TruckDelivery, panel => {
                                var mt = b.Mtasts != null ? DomainDetective.Reports.SectionProjectors.BuildMtasts(b.Mtasts) : null;
                                var tr = b.TlsRpt != null ? DomainDetective.Reports.SectionProjectors.BuildTlsRpt(b.TlsRpt) : null;
                                panel.DataGrid(g => { g.AsCompact(); g.AddItem("MTA-STS", b.Mtasts?.Status ?? "-"); g.AddItem("TLS-RPT", b.TlsRpt?.Status ?? "-"); });
                                if (mt != null)
                                {
                                    if (mt.Summary.Count > 0) { panel.Divider("MTA-STS Summary"); panel.DataGrid(g => { g.AsCompact(); foreach (var kv2 in mt.Summary) g.AddItem(kv2.Key, kv2.Value); }); }
                                    if (mt.Findings.Count > 0) { panel.Divider("MTA-STS Findings"); var rows = mt.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList(); var t = (TablerTable)panel.Table(rows, TableType.Tabler); t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover); }
                                    if (mt.References.Count > 0) { panel.Divider("MTA-STS References"); foreach (var url in mt.References) panel.Text("• " + url); }
                                }
                                if (tr != null)
                                {
                                    if (tr.Summary.Count > 0) { panel.Divider("TLS-RPT Summary"); panel.DataGrid(g => { g.AsCompact(); foreach (var kv2 in tr.Summary) g.AddItem(kv2.Key, kv2.Value); }); }
                                    if (tr.Findings.Count > 0) { panel.Divider("TLS-RPT Findings"); var rows = tr.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList(); var t = (TablerTable)panel.Table(rows, TableType.Tabler); t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover); }
                                    if (tr.References.Count > 0) { panel.Divider("TLS-RPT References"); foreach (var url in tr.References) panel.Text("• " + url); }
                                }
                            });

                            // Reputation tab (DNSBL) — via SectionProjectors
                            if (b.Dnsbl != null)
                            {
                                tabs.AddTab("Reputation", TablerIconType.ShieldCheck, panel => {
                                    var sec = DomainDetective.Reports.SectionProjectors.BuildDnsbl(b.Dnsbl);
                                    if (sec != null && sec.Summary.Count > 0)
                                    {
                                        panel.DataGrid(g => { g.AsCompact(); foreach (var kv2 in sec.Summary) g.AddItem(kv2.Key, kv2.Value); });
                                    }
                                    if (sec != null && sec.Findings.Count > 0)
                                    {
                                        panel.Divider("Findings");
                                        var rows = sec.Findings.Select(x => new { x.Severity, x.Code, x.Target, x.Message }).ToList();
                                        var t = (TablerTable)panel.Table(rows, TableType.Tabler);
                                        t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                    }
                                    if (b.Dnsbl.ListedRecords != null && b.Dnsbl.ListedRecords.Count > 0)
                                    {
                                        panel.Divider("Listed Records");
                                        var listed = b.Dnsbl.ListedRecords.Select(r => new { Host = r.SourceHost ?? r.IpAddress, Blacklist = r.BlackList, Reason = r.ReplyMeaning }).ToList();
                                        var t = (TablerTable)panel.Table(listed, TableType.Tabler);
                                        t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                    }
                                    if (sec != null && sec.References.Count > 0)
                                    {
                                        panel.Divider("References");
                                        foreach (var url in sec.References) panel.Text("• " + url);
                                    }
                                });
                            }
                        });
                    });
                });
            });
        });
    }
}
