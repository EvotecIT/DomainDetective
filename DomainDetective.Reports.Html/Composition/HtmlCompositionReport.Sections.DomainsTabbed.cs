using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HtmlCompositionReport partial: multi-domain tabbed section with per-domain cards + accordions.
/// </summary>
public static partial class HtmlCompositionReport
{
    private static void RenderDomainsTabbed(TablerPage page, List<KeyValuePair<string, DomainBucket>> ordered)
    {
        page.Divider("Domains");
        page.Row(rr => rr.Column(TablerColumnNumber.Twelve, c => {
            c.Card(card => {
                card.Header(h => h.Title("Domains").Subtitle("Switch tabs to view each domain"));
                card.Body(body => {
                    body.SmartTab(tabs => {
                        tabs.WithTheme(SmartTabTheme.Pills)
                            .WithNavStyle(SmartTabNavStyle.Tabs)
                            .WithSelectedTab(0)
                            .Justified(true)
                            .AutoAdjustHeight(true)
                            .WithCardHeaderLook(true);

                        foreach (var kv in ordered)
                        {
                            var d = kv.Key; var b = kv.Value;
                            tabs.AddTab(d, TablerIconType.Globe, panel => {
                                // Make domain obvious + show quick stats
                                var warnCount = (b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + b.Dkim.Sum(x => x.WarningCount);
                                var errCount = (b.Mx?.ErrorCount ?? 0) + (b.Spf?.ErrorCount ?? 0) + (b.Dmarc?.ErrorCount ?? 0) + (b.Mtasts?.ErrorCount ?? 0) + (b.TlsRpt?.ErrorCount ?? 0) + b.Dkim.Sum(x => x.ErrorCount);

                                // Severity banner with compact header badges (no intermediate grid/row)
                                panel.Card(card => {
                                    var sevColor = TablerColor.Blue;
                                    var statusText = "OK";
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
                                    card.Body(bdy => {
                                        var dkimStatus = b.Dkim.Count > 0 ? (b.Dkim.Max(x => x.Status) ?? "-") : "-";
                                        var summary = $"SPF {b.Spf?.Status ?? "-"}, DMARC {b.Dmarc?.Status ?? "-"}, DKIM {dkimStatus}, MX {b.Mx?.Status ?? "-"}, MTA-STS {b.Mtasts?.Status ?? "-"}, TLS-RPT {b.TlsRpt?.Status ?? "-"}";
                                        bdy.Text(summary).Style(TablerTextStyle.Muted);
                                    });
                                });

                                // Detailed sections as accordion
                                panel.Accordion(acc => {
                                    // SPF
                                    if (b.Spf != null)
                                    {
                                        acc.AddItem("SPF (Sender Policy Framework)", item => {
                                            item.HeaderRight(c => {
                                                c.Badge(b.Spf.ErrorCount > 0 ? $"{b.Spf.ErrorCount} Error" + (b.Spf.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                                c.Badge(b.Spf.WarningCount > 0 ? $"{b.Spf.WarningCount} Warning" + (b.Spf.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                                c.Badge(b.Spf.Status ?? "Unknown", TablerBadgeColor.Blue, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                            });
                                            item.Content(content => {
                                                content.Row(r => {
                                                    r.Column(TablerColumnNumber.Twelve, c2 => {
                                                        c2.DataGrid(g => {
                                                            g.WithLayout(TablerDataGridLayout.Compact).WithSpacing(TablerDataGridSpacing.Small).WithNarrowTitles();
                                                            g.AddItem("Record Present", b.Spf.SpfRecordExists ? "Yes" : "No").AsPanel();
                                                            g.AddItem("Starts Correctly", b.Spf.StartsCorrectly ? "Yes" : "No").AsPanel();
                                                            g.AddItem("DNS Lookups", b.Spf.DnsLookupsCount.ToString()).AsPanel();
                                                            g.AddItem("Multiple 'all'", b.Spf.MultipleAllMechanisms ? "Yes" : "No").AsPanel();
                                                        });
                                                        // Provider help badges (if available on SPF)
                                                        try {
                                                            var links = b.Spf.ProviderHelp;
                                                            if (links != null && links.Count > 0) {
                                                                c2.Row(rr => {
                                                                    rr.Gap(2);
                                                                    foreach (var provider in links) {
                                                                        if (!string.IsNullOrWhiteSpace(provider?.Spf))
                                                                            rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(provider!.ProviderName, TablerBadgeColor.Secondary, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true, href: provider.Spf));
                                                                        foreach (var topic in (provider?.Topics ?? new System.Collections.Generic.List<DomainDetective.Views.ProviderHelpTopic>())) {
                                                                            if (!string.IsNullOrWhiteSpace(topic?.Url))
                                                                                rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(topic!.Title ?? topic.Topic, TablerBadgeColor.Blue, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true, href: topic.Url));
                                                                        }
                                                                    }
                                                                });
                                                            }
                                                        } catch { }

                                                        if ((b.Spf.Highlights?.Count ?? 0) > 0) { c2.Divider("Highlights"); foreach (var t in b.Spf.Highlights) c2.Text("• " + t); }
                                                        if ((b.Spf.Positives?.Count ?? 0) > 0) { c2.Divider("Good Posture"); foreach (var p in b.Spf.Positives) if (!string.IsNullOrWhiteSpace(p?.Title)) c2.Text("• " + p!.Title!); }
                                                    });
                                                });
                                            });
                                        });
                                    }
                                    // DMARC
                                    if (b.Dmarc != null)
                                    {
                                        acc.AddItem("DMARC (Domain-based Message Authentication)", item => {
                                            item.HeaderRight(c => { });
                                            item.Content(content => {
                                                content.Row(r => {
                                                    r.Column(TablerColumnNumber.Twelve, c2 => {
                                                        c2.DataGrid(g => {
                                                            g.WithLayout(TablerDataGridLayout.Compact).WithSpacing(TablerDataGridSpacing.Small).WithNarrowTitles();
                                                            g.AddItem("Record Present", b.Dmarc.RecordExists ? "Yes" : "No").AsPanel();
                                                            g.AddItem("Policy", string.IsNullOrWhiteSpace(b.Dmarc.Policy) ? "-" : b.Dmarc.Policy).AsPanel();
                                                            g.AddItem("Aggregate Mailboxes", (b.Dmarc.AggregateMailboxes?.Count ?? 0).ToString()).AsPanel();
                                                            g.AddItem("Forensic Mailboxes", (b.Dmarc.ForensicMailboxes?.Count ?? 0).ToString()).AsPanel();
                                                        });

                                                        // Provider help badges (if available on DMARC)
                                                        try {
                                                            var links = b.Dmarc.ProviderHelp;
                                                            if (links != null && links.Count > 0) {
                                                                c2.Row(rr => {
                                                                    rr.Gap(2);
                                                                    foreach (var provider in links) {
                                                                        if (!string.IsNullOrWhiteSpace(provider?.Dmarc))
                                                                            rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(provider!.ProviderName, TablerBadgeColor.Secondary, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true, href: provider.Dmarc));
                                                                        foreach (var topic in (provider?.Topics ?? new System.Collections.Generic.List<DomainDetective.Views.ProviderHelpTopic>())) {
                                                                            if (!string.IsNullOrWhiteSpace(topic?.Url))
                                                                                rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(topic!.Title ?? topic.Topic, TablerBadgeColor.Blue, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true, href: topic.Url));
                                                                        }
                                                                    }
                                                                });
                                                            }
                                                        } catch { }

                                                        if ((b.Dmarc.Highlights?.Count ?? 0) > 0) { c2.Divider("Highlights"); foreach (var t in b.Dmarc.Highlights) c2.Text("• " + t); }
                                                        if ((b.Dmarc.Positives?.Count ?? 0) > 0) { c2.Divider("Good Posture"); foreach (var p in b.Dmarc.Positives) if (!string.IsNullOrWhiteSpace(p?.Title)) c2.Text("• " + p!.Title!); }
                                                    });
                                                });
                                            });
                                        });
                                    }
                                    // DKIM (summarized table)
                                    if (b.Dkim.Count > 0)
                                    {
                                        acc.AddItem("DKIM (DomainKeys Identified Mail)", item => {
                                            item.HeaderRight(c => {
                                                var err = b.Dkim.Sum(x => x.ErrorCount); var warn = b.Dkim.Sum(x => x.WarningCount);
                                                c.Badge(err > 0 ? $"{err} Error" + (err > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                                c.Badge(warn > 0 ? $"{warn} Warning" + (warn > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                            });
                                            item.Content(content => {
                                                content.Row(r => {
                                                    r.Column(TablerColumnNumber.Twelve, c2 => {
                                                        var rows = b.Dkim.Select(k => new { Selector = k.Selector, Key = k.PublicKeyExists ? (k.KeyLength.ToString() + " bits") : "no key", Alg = k.HashAlgorithm ?? "?", Status = k.Status ?? "-" }).ToList();
                                                        var table = (DataTablesTable)c2.Table(rows, TableType.DataTables);
                                                        table.EnablePaging(10, new[] { 10, 25, 50 }).EnableSearching().EnableOrdering();
                                                        table.HighlightWhen(
                                                            where: g => g.Or(c => { c.StringContains("Status", "error", false); c.StringContains("Status", "fail", false); }),
                                                            then: t => t.Column("Status").Danger());
                                                        table.HighlightWhen(
                                                            where: g => g.Or(c => { c.StringContains("Status", "warn", false); }),
                                                            then: t => t.Column("Status").Warning());
                                                    });
                                                });
                                            });
                                        });
                                    }
                                    // MX quick notes
                                    if (b.Mx != null)
                                    {
                                        acc.AddItem("MX (Mail Exchangers)", item => {
                                            item.HeaderRight(c => c.Badge(b.Mx.Status ?? "-", TablerBadgeColor.Blue, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true));
                                            item.Content(content => {
                                                content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 => {
                                                    c2.DataGrid(g => {
                                                        g.WithLayout(TablerDataGridLayout.Compact).WithSpacing(TablerDataGridSpacing.Small).WithNarrowTitles();
                                                        g.AddItem("Has Backup Servers", b.Mx.HasBackupServers ? "Yes" : "No").AsPanel();
                                                        g.AddItem("IPv6 Supported", b.Mx.Ipv6Supported ? "Yes" : "No").AsPanel();
                                                        g.AddItem("Null MX", b.Mx.HasNullMx ? "Yes" : "No").AsPanel();
                                                    });
                                                }));
                                            });
                                        });
                                    }
                                });
                            });
                        }
                    });
                });
            });
        }));
    }
}
