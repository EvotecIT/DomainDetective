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
    private static void RenderDomainsTabbed(HtmlForgeX.TablerPage page, List<KeyValuePair<string, DomainBucket>> ordered)
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
                                var warnCount = (b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + b.Dkim.Sum(x => x?.WarningCount ?? 0);
                                var errCount = (b.Mx?.ErrorCount ?? 0) + (b.Spf?.ErrorCount ?? 0) + (b.Dmarc?.ErrorCount ?? 0) + (b.Mtasts?.ErrorCount ?? 0) + (b.TlsRpt?.ErrorCount ?? 0) + b.Dkim.Sum(x => x?.ErrorCount ?? 0);

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
                                                 a.Badge(warnCount > 0 ? $"{warnCount} Warning" + (errCount>1?"s":"") : "0 Warning", TablerBadgeColor.Warning, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
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
                                                    var spfSec = DomainDetective.Reports.SectionProjectors.BuildSpf(b.Spf);
                                                    if ((spfSec?.Positives?.Count ?? 0) > 0) { c2.Divider("Good Posture"); foreach (var t in spfSec!.Positives) c2.Text("• " + t); }
                                                    if ((spfSec?.Findings?.Count ?? 0) > 0) { c2.Divider("Findings"); var rows = spfSec!.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList(); var t = (DataTablesTable)c2.Table(rows, TableType.DataTables); t.EnablePaging(10, new[]{10,25,50}).EnableSearching().EnableOrdering(); }
                                                    if ((spfSec?.References?.Count ?? 0) > 0) { c2.Divider("References"); c2.Row(rr => { rr.Gap(2); foreach (var u in spfSec!.References) { var f = DomainDetective.Reports.LinkFormatter.Format(u); rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(f.Title, TablerBadgeColor.Blue, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true, href: f.Url)); } }); }
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
                                                            g.AddItem("Record Present", b.Dmarc.DmarcRecordExists ? "Yes" : "No").AsPanel();
                                                            g.AddItem("Policy", string.IsNullOrWhiteSpace(b.Dmarc.Policy) ? "-" : b.Dmarc.Policy).AsPanel();
                                                            g.AddItem("mailto RUA", (b.Dmarc.MailtoRua?.Count ?? 0).ToString()).AsPanel();
                                                            g.AddItem("mailto RUF", (b.Dmarc.MailtoRuf?.Count ?? 0).ToString()).AsPanel();
                                                        });
                                                        if ((b.Dmarc.Highlights?.Count ?? 0) > 0) { c2.Divider("Highlights"); foreach (var t in b.Dmarc.Highlights) c2.Text("• " + t); }
                                                        var dmSec = DomainDetective.Reports.SectionProjectors.BuildDmarc(b.Dmarc);
                                                        if ((dmSec?.Positives?.Count ?? 0) > 0) { c2.Divider("Good Posture"); foreach (var t in dmSec!.Positives) c2.Text("• " + t); }
                                                        if ((dmSec?.Findings?.Count ?? 0) > 0) { c2.Divider("Findings"); var rows = dmSec!.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList(); var t = (DataTablesTable)c2.Table(rows, TableType.DataTables); t.EnablePaging(10, new[]{10,25,50}).EnableSearching().EnableOrdering(); }
                                                        if ((dmSec?.References?.Count ?? 0) > 0) { c2.Divider("References"); c2.Row(rr => { rr.Gap(2); foreach (var u in dmSec!.References) { var f = DomainDetective.Reports.LinkFormatter.Format(u); rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(f.Title, TablerBadgeColor.Blue, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true, href: f.Url)); } }); }
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
                                                var err = b.Dkim.Sum(x => x?.ErrorCount ?? 0); var warn = b.Dkim.Sum(x => x?.WarningCount ?? 0);
                                                c.Badge(err > 0 ? $"{err} Error" + (err > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                                c.Badge(warn > 0 ? $"{warn} Warning" + (warn > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                            });
                                            item.Content(content => {
                                                content.Row(r => {
                                                    r.Column(TablerColumnNumber.Twelve, c2 => {
                                                        var dkSec = DomainDetective.Reports.SectionProjectors.BuildDkim(b.Dkim);
                                                        var rows = dkSec!.Rows.Select(k => new { Selector = k.Selector, Key = string.IsNullOrEmpty(k.KeyBits) ? "-" : (k.KeyBits + " bits"), Alg = string.IsNullOrEmpty(k.Hash) ? "?" : k.Hash, Status = k.Status }).ToList();
                                                        var table = (DataTablesTable)c2.Table(rows, TableType.DataTables);
                                                        table.EnablePaging(10, new[] { 10, 25, 50 }).EnableSearching().EnableOrdering();
                                                        table.HighlightWhen(
                                                            where: g => g.Or(c => { c.StringContains("Status", "error", false); c.StringContains("Status", "fail", false); }),
                                                            then: t => t.Column("Status").Danger());
                                                        table.HighlightWhen(
                                                            where: g => g.Or(c => { c.StringContains("Status", "warn", false); }),
                                                            then: t => t.Column("Status").Warning());

                                                        // Positives / Findings / References
                                                        var dPos = dkSec!.Positives.Distinct(System.StringComparer.OrdinalIgnoreCase).ToList();
                                                        if (dPos.Count > 0) { c2.Divider("Good Posture"); foreach (var t in dPos) c2.Text("• " + t); }
                                                        var dFind = dkSec!.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList();
                                                        if (dFind.Count > 0) { c2.Divider("Findings"); var tf = (DataTablesTable)c2.Table(dFind, TableType.DataTables); tf.EnablePaging(10, new[]{10,25,50}).EnableSearching().EnableOrdering(); }
                                                        var dRefs = dkSec!.References;
                                                        if (dRefs.Count > 0) { c2.Divider("References"); c2.Row(rr => { rr.Gap(2); foreach (var u in dRefs) { var f = DomainDetective.Reports.LinkFormatter.Format(u); rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(f.Title, TablerBadgeColor.Blue, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true, href: f.Url)); } }); }
                                                    });
                                                });
                                            });
                                        });
                                    }
                                    // MX quick notes + records + MailTLS summary
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
                                                    // MX records
                                                    if ((b.Mx.MxRecords?.Count ?? 0) > 0)
                                                    {
                                                        c2.Divider("Records");
                                                        var mxRows = b.Mx.MxRecords.Select(x => new { Host = x }).ToList();
                                                        var tmx = (TablerTable)c2.Table(mxRows, TableType.Tabler); tmx.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                                    }
                                                    // MailTLS summary
                                                    if (b.SmtpTls != null || b.ImapTls != null || b.PopTls != null)
                                                    {
                                                        c2.Divider("MailTLS");
                                                        var tlsRows = new [] {
                                                            new { Service = "SMTP", Status = b.SmtpTls?.Status ?? "-", Summary = b.SmtpTls?.Summary ?? string.Empty },
                                                            new { Service = "IMAP", Status = b.ImapTls?.Status ?? "-", Summary = b.ImapTls?.Summary ?? string.Empty },
                                                            new { Service = "POP3", Status = b.PopTls?.Status ?? "-", Summary = b.PopTls?.Summary ?? string.Empty },
                                                        }.ToList();
                                                        var ttls = (TablerTable)c2.Table(tlsRows, TableType.Tabler); ttls.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                                    }
                                                    if ((b.Mx.Positives?.Count ?? 0) > 0) { c2.Divider("Good Posture"); foreach (var p in b.Mx.Positives) if (!string.IsNullOrWhiteSpace(p?.Title)) c2.Text("• " + p!.Title!); }
                                                    var mxFind = (b.Mx.Assessments ?? System.Array.Empty<DomainDetective.Assessment>()).Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info).Select(a => new { Severity = a.Severity.ToString(), a.Code, a.Target, a.Message }).ToList();
                                                    if (mxFind.Count > 0) { c2.Divider("Findings"); var t = (DataTablesTable)c2.Table(mxFind, TableType.DataTables); t.EnablePaging(10, new[]{10,25,50}).EnableSearching().EnableOrdering(); }
                                                    if ((b.Mx.References?.Count ?? 0) > 0) { c2.Divider("References"); var refs = b.Mx.References!.Where(s => !string.IsNullOrWhiteSpace(s)).ToList(); if (refs.Count > 0) { c2.Row(rr => { rr.Gap(2); foreach (var u in refs) { var f = DomainDetective.Reports.LinkFormatter.Format(u); rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(f.Title, TablerBadgeColor.Blue, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true, href: f.Url)); } }); } }
                                                }));
                                            });
                                        });
                                    }

                                    // NS (Authoritative Name Servers) — via SectionProjectors
                                    if (b.Ns != null)
                                    {
                                        acc.AddItem("NS (Authoritative)", item => {
                                            var sec = DomainDetective.Reports.SectionProjectors.BuildNs(b.Ns);
                                            item.HeaderRight(c => c.Badge(b.Ns.Status ?? "-", TablerBadgeColor.Blue, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true));
                                            item.Content(content => {
                                                content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 => {
                                                    // Summary
                                                    if (sec != null && sec.Summary.Count > 0)
                                                    {
                                                        c2.DataGrid(g => {
                                                            g.WithLayout(TablerDataGridLayout.Compact).WithSpacing(TablerDataGridSpacing.Small).WithNarrowTitles();
                                                            foreach (var kv2 in sec.Summary) g.AddItem(kv2.Key, kv2.Value).AsPanel();
                                                        });
                                                    }
                                                    // Positives
                                                    if (sec != null && sec.Positives.Count > 0) { c2.Divider("Good Posture"); foreach (var t in sec.Positives) c2.Text("• " + t); }
                                                    // Findings
                                                    if (sec != null && sec.Findings.Count > 0) { c2.Divider("Findings"); var rows = sec.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList(); var t = (DataTablesTable)c2.Table(rows, TableType.DataTables); t.EnablePaging(10, new[]{10,25,50}).EnableSearching().EnableOrdering(); }
                                                    // References
                                                    if (sec != null && sec.References.Count > 0) { c2.Divider("References"); c2.Row(rr => { rr.Gap(2); foreach (var u in sec.References) { var f = DomainDetective.Reports.LinkFormatter.Format(u); rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(f.Title, TablerBadgeColor.Blue, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true, href: f.Url)); } }); }
                                                }));
                                            });
                                        });
                                    }

                                    // SOA — via SectionProjectors
                                    if (b.Soa != null)
                                    {
                                        acc.AddItem("SOA", item => {
                                            var sec = DomainDetective.Reports.SectionProjectors.BuildSoa(b.Soa);
                                            item.HeaderRight(c => c.Badge(b.Soa.Status ?? "-", TablerBadgeColor.Blue, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true));
                                            item.Content(content => {
                                                content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 => {
                                                    if (sec != null && sec.Summary.Count > 0)
                                                    {
                                                        c2.DataGrid(g => { g.WithLayout(TablerDataGridLayout.Compact).WithSpacing(TablerDataGridSpacing.Small).WithNarrowTitles(); foreach (var kv2 in sec.Summary) g.AddItem(kv2.Key, kv2.Value).AsPanel(); });
                                                    }
                                                    if (sec != null && sec.Findings.Count > 0) { c2.Divider("Findings"); var rows = sec.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList(); var t = (DataTablesTable)c2.Table(rows, TableType.DataTables); t.EnablePaging(10, new[]{10,25,50}).EnableSearching().EnableOrdering(); }
                                                    if (sec != null && sec.References.Count > 0) { c2.Divider("References"); foreach (var url in sec.References) c2.Text("• " + url); }
                                                }));
                                            });
                                        });
                                    }

                                    // CAA — via SectionProjectors
                                    if (b.Caa != null)
                                    {
                                        acc.AddItem("CAA", item => {
                                            var sec = DomainDetective.Reports.SectionProjectors.BuildCaa(b.Caa);
                                            item.HeaderRight(c => c.Badge(b.Caa.Status ?? "-", TablerBadgeColor.Blue, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true));
                                            item.Content(content => {
                                                content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 => {
                                                    if (sec != null && sec.Summary.Count > 0)
                                                    {
                                                        c2.DataGrid(g => { g.WithLayout(TablerDataGridLayout.Compact).WithSpacing(TablerDataGridSpacing.Small).WithNarrowTitles(); foreach (var kv2 in sec.Summary) g.AddItem(kv2.Key, kv2.Value).AsPanel(); });
                                                    }
                                                    if (sec != null && sec.Findings.Count > 0) { c2.Divider("Findings"); var rows = sec.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList(); var t = (DataTablesTable)c2.Table(rows, TableType.DataTables); t.EnablePaging(10, new[]{10,25,50}).EnableSearching().EnableOrdering(); }
                                                    if (sec != null && sec.References.Count > 0) { c2.Divider("References"); foreach (var url in sec.References) c2.Text("• " + url); }
                                                }));
                                            });
                                        });
                                    }

                                    // DNSSEC — via SectionProjectors
                                    if (b.Dnssec != null)
                                    {
        acc.AddItem("DNSSEC", item => {
            var sec = DomainDetective.Reports.SectionProjectors.BuildDnssec(b.Dnssec);
            item.HeaderRight(c => c.Badge(b.Dnssec.Status ?? "-", ColorForStatus(b.Dnssec.Status), HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true));
            item.Content(content => {
                content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 => {
                    if (sec != null && sec.Summary.Count > 0)
                    {
                        c2.DataGrid(g => { g.WithLayout(TablerDataGridLayout.Compact).WithSpacing(TablerDataGridSpacing.Small).WithNarrowTitles(); foreach (var kv2 in sec.Summary) g.AddItem(kv2.Key, kv2.Value).AsPanel(); });
                    }
                    if (sec != null && sec.Positives.Count > 0) { c2.Divider("Good Posture"); foreach (var t in sec.Positives) c2.Text("• " + t); }
                    if (sec != null && sec.Findings.Count > 0) { c2.Divider("Findings"); var rows = sec.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList(); var t = (DataTablesTable)c2.Table(rows, TableType.DataTables); t.EnablePaging(10, new[]{10,25,50}).EnableSearching().EnableOrdering(); }
                    if (sec != null && sec.References.Count > 0) { c2.Divider("References"); foreach (var url in sec.References) c2.Text("• " + url); }
                }));
            });
        });
    }

                                    // DANE — via SectionProjectors
                                    if (b.Dane != null)
                                    {
                                        acc.AddItem("DANE", item => {
                                            var sec = DomainDetective.Reports.SectionProjectors.BuildDane(b.Dane);
                                            item.HeaderRight(c => c.Badge(b.Dane.Status ?? "-", ColorForStatus(b.Dane.Status), HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true));
                                            item.Content(content => {
                                                content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 => {
                                                    if (sec != null && sec.Summary.Count > 0) { c2.DataGrid(g => { g.WithLayout(TablerDataGridLayout.Compact).WithSpacing(TablerDataGridSpacing.Small).WithNarrowTitles(); foreach (var kv2 in sec.Summary) g.AddItem(kv2.Key, kv2.Value).AsPanel(); }); }
                                                    if (sec != null && sec.Findings.Count > 0) { c2.Divider("Findings"); var rows = sec.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList(); var t = (DataTablesTable)c2.Table(rows, TableType.DataTables); t.EnablePaging(10, new[]{10,25,50}).EnableSearching().EnableOrdering(); }
                                                    if (sec != null && sec.References.Count > 0) { c2.Divider("References"); foreach (var url in sec.References) c2.Text("• " + url); }
                                                }));
                                            });
                                        });
                                    }

                                    // Mail TLS
                                    if (b.SmtpTls != null || b.ImapTls != null || b.PopTls != null)
                                    {
                                        acc.AddItem("Mail TLS", item => {
                                            var sec = DomainDetective.Reports.SectionProjectors.BuildMailTls(b.SmtpTls, b.ImapTls, b.PopTls);
                                            item.Content(content => {
                                                content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 => {
                                                    if (sec != null && sec.Rows.Count > 0)
                                                    {
                                                        var rows = sec.Rows.Select(v => new { v.Service, v.Status, Protocol = string.IsNullOrWhiteSpace(v.Protocol) ? "-" : v.Protocol }).ToList();
                                                        var t = (TablerTable)c2.Table(rows, TableType.Tabler);
                                                        t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                                    }
                                                    if (sec != null && sec.Findings.Count > 0)
                                                    {
                                                        c2.Divider("Findings");
                                                        var fr = sec.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList();
                                                        var tf = (DataTablesTable)c2.Table(fr, TableType.DataTables);
                                                        tf.EnablePaging(10, new[]{10,25,50}).EnableSearching().EnableOrdering();
                                                    }
                                                    if (sec != null && sec.References.Count > 0)
                                                    { c2.Divider("References"); foreach (var url in sec.References) c2.Text("• " + url); }
                                                }));
                                            });
                                        });
                                    }

                                    // RPKI — via SectionProjectors
                                    if (b.Rpki != null)
                                    {
                                        acc.AddItem("RPKI", item => {
                                            var sec = DomainDetective.Reports.SectionProjectors.BuildRpki(b.Rpki);
                                            item.HeaderRight(c => c.Badge(b.Rpki.Status ?? "-", ColorForStatus(b.Rpki.Status), HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true));
                                            item.Content(content => {
                                                content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 => {
                                                    if (sec != null && sec.Summary.Count > 0)
                                                    { c2.DataGrid(g => { g.WithLayout(TablerDataGridLayout.Compact).WithSpacing(TablerDataGridSpacing.Small).WithNarrowTitles(); foreach (var kv2 in sec.Summary) g.AddItem(kv2.Key, kv2.Value).AsPanel(); }); }
                                                    if (sec != null && sec.Findings.Count > 0) { c2.Divider("Findings"); var rows = sec.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList(); var t = (DataTablesTable)c2.Table(rows, TableType.DataTables); t.EnablePaging(10, new[]{10,25,50}).EnableSearching().EnableOrdering(); }
                                                    if (b.Rpki.Results != null && b.Rpki.Results.Count > 0) { c2.Divider("Per-IP Results"); var rpRows = b.Rpki.Results.Select(rp => new { rp.IpAddress, rp.Prefix, rp.Asn, Valid = rp.Valid ? "Yes" : "No" }).ToList(); var tx = (DataTablesTable)c2.Table(rpRows, TableType.DataTables); tx.EnablePaging(10, new[]{10,25,50}).EnableSearching().EnableOrdering(); }
                                                    if (sec != null && sec.References.Count > 0) { c2.Divider("References"); foreach (var url in sec.References) c2.Text("• " + url); }
                                                }));
                                            });
                                        });
                                    }

                                    // Zone Transfer — via SectionProjectors
                                    if (b.ZoneTransfer != null)
                                    {
                                        acc.AddItem("Zone Transfer", item => {
                                            var sec = DomainDetective.Reports.SectionProjectors.BuildZoneTransfer(b.ZoneTransfer);
                                            item.Content(content => {
                                                content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 => {
                                                    if (sec != null && sec.Summary.Count > 0) { c2.DataGrid(g => { g.WithLayout(TablerDataGridLayout.Compact).WithSpacing(TablerDataGridSpacing.Small).WithNarrowTitles(); foreach (var kv2 in sec.Summary) g.AddItem(kv2.Key, kv2.Value).AsPanel(); }); }
                                                    var zRows = b.ZoneTransfer.ServerResults?.Select(kv2 => new { Server = kv2.Key, Open = kv2.Value ? "Yes" : "No" }).ToList();
                                                    if (zRows != null && zRows.Count > 0) { var t = (DataTablesTable)c2.Table(zRows, TableType.DataTables); t.EnablePaging(10, new[]{10,25,50}).EnableSearching().EnableOrdering(); }
                                                    if (sec != null && sec.Findings.Count > 0) { c2.Divider("Findings"); var rows = sec.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList(); var t2 = (DataTablesTable)c2.Table(rows, TableType.DataTables); t2.EnablePaging(10, new[]{10,25,50}).EnableSearching().EnableOrdering(); }
                                                }));
                                            });
                                        });
                                    }

                                    // Wildcard DNS — via SectionProjectors
                                    if (b.Wildcard != null)
                                    {
                                        acc.AddItem("Wildcard DNS", item => {
                                            var sec = DomainDetective.Reports.SectionProjectors.BuildWildcard(b.Wildcard);
                                            item.Content(content => {
                                                content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 => {
                                                    if (sec != null && sec.Summary.Count > 0) { c2.DataGrid(g => { g.WithLayout(TablerDataGridLayout.Compact).WithSpacing(TablerDataGridSpacing.Small).WithNarrowTitles(); foreach (var kv2 in sec.Summary) g.AddItem(kv2.Key, kv2.Value).AsPanel(); }); }
                                                    if (sec != null && sec.Findings.Count > 0) { c2.Divider("Findings"); var rows = sec.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList(); var t = (DataTablesTable)c2.Table(rows, TableType.DataTables); t.EnablePaging(10, new[]{10,25,50}).EnableSearching().EnableOrdering(); }
                                                    if (sec != null && sec.References.Count > 0) { c2.Divider("References"); foreach (var url in sec.References) c2.Text("• " + url); }
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
