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
                                                    if ((b.Spf.Positives?.Count ?? 0) > 0) { c2.Divider("Good Posture"); foreach (var p in b.Spf.Positives) if (!string.IsNullOrWhiteSpace(p?.Title)) c2.Text("• " + p!.Title!); }
                                                    var spfFind = (b.Spf.Assessments ?? Array.Empty<DomainDetective.Assessment>()).Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info).Select(a => new { Severity = a.Severity.ToString(), a.Code, a.Target, a.Message }).ToList();
                                                    if (spfFind.Count > 0) { c2.Divider("Findings"); var t = (DataTablesTable)c2.Table(spfFind, TableType.DataTables); t.EnablePaging(10, new[]{10,25,50}).EnableSearching().EnableOrdering(); }
                                                if ((b.Spf.References?.Count ?? 0) > 0) { c2.Divider("References"); var refs = b.Spf.References!.Where(s => !string.IsNullOrWhiteSpace(s)).ToList(); if (refs.Count > 0) { foreach (var url in refs) c2.Text("• " + url); } }
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
                                                        if ((b.Dmarc.Positives?.Count ?? 0) > 0) { c2.Divider("Good Posture"); foreach (var p in b.Dmarc.Positives) if (!string.IsNullOrWhiteSpace(p?.Title)) c2.Text("• " + p!.Title!); }
                                                        var dmFind = (b.Dmarc.Assessments ?? Array.Empty<DomainDetective.Assessment>()).Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info).Select(a => new { Severity = a.Severity.ToString(), a.Code, a.Target, a.Message }).ToList();
                                                        if (dmFind.Count > 0) { c2.Divider("Findings"); var t = (DataTablesTable)c2.Table(dmFind, TableType.DataTables); t.EnablePaging(10, new[]{10,25,50}).EnableSearching().EnableOrdering(); }
                                                        if ((b.Dmarc.References?.Count ?? 0) > 0) { c2.Divider("References"); var refs = b.Dmarc.References!.Where(s => !string.IsNullOrWhiteSpace(s)).ToList(); if (refs.Count > 0) { foreach (var url in refs) c2.Text("• " + url); } }
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

                                                        // Positives / Findings / References
                                                        var dPos = b.Dkim.SelectMany(x => x.Positives ?? System.Array.Empty<DomainDetective.RecommendationAdvice>())
                                                                         .Select(p => p?.Title)
                                                                         .Where(t => !string.IsNullOrWhiteSpace(t))
                                                                         .Select(t => t!)
                                                                         .Distinct(System.StringComparer.OrdinalIgnoreCase)
                                                                         .ToList();
                                                        if (dPos.Count > 0) { c2.Divider("Good Posture"); foreach (var t in dPos) c2.Text("• " + t); }
                                                        var dFind = b.Dkim.SelectMany(x => x.Assessments ?? System.Array.Empty<DomainDetective.Assessment>())
                                                                          .Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info)
                                                                          .Select(a => new { Severity = a.Severity.ToString(), a.Code, a.Target, a.Message }).ToList();
                                                        if (dFind.Count > 0) { c2.Divider("Findings"); var tf = (DataTablesTable)c2.Table(dFind, TableType.DataTables); tf.EnablePaging(10, new[]{10,25,50}).EnableSearching().EnableOrdering(); }
                                                        var dRefs = b.Dkim.SelectMany(x => x.References ?? System.Array.Empty<string>()).Where(u => !string.IsNullOrWhiteSpace(u)).Distinct(System.StringComparer.OrdinalIgnoreCase).ToList();
                                                        if (dRefs.Count > 0) { c2.Divider("References"); foreach (var url in dRefs) c2.Text("• " + url); }
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
                                                    if ((b.Mx.Positives?.Count ?? 0) > 0) { c2.Divider("Good Posture"); foreach (var p in b.Mx.Positives) if (!string.IsNullOrWhiteSpace(p?.Title)) c2.Text("• " + p!.Title!); }
                                                    var mxFind = (b.Mx.Assessments ?? System.Array.Empty<DomainDetective.Assessment>()).Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info).Select(a => new { Severity = a.Severity.ToString(), a.Code, a.Target, a.Message }).ToList();
                                                    if (mxFind.Count > 0) { c2.Divider("Findings"); var t = (DataTablesTable)c2.Table(mxFind, TableType.DataTables); t.EnablePaging(10, new[]{10,25,50}).EnableSearching().EnableOrdering(); }
                                                    if ((b.Mx.References?.Count ?? 0) > 0) { c2.Divider("References"); var refs = b.Mx.References!.Where(s => !string.IsNullOrWhiteSpace(s)).ToList(); if (refs.Count > 0) { foreach (var url in refs) c2.Text("• " + url); } }
                                                }));
                                            });
                                        });
                                    }

                                    // NS (Authoritative Name Servers)
                                    if (b.Ns != null)
                                    {
                                        acc.AddItem("NS (Authoritative)", item => {
                                            item.HeaderRight(c => c.Badge(b.Ns.Status ?? "-", TablerBadgeColor.Blue, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true));
                                            item.Content(content => {
                                                content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 => {
                                                    c2.DataGrid(g => {
                                                        g.WithLayout(TablerDataGridLayout.Compact).WithSpacing(TablerDataGridSpacing.Small).WithNarrowTitles();
                                                        g.AddItem("At Least Two", b.Ns.AtLeastTwoRecords ? "Yes" : "No").AsPanel();
                                                        g.AddItem("All Have A/AAAA", b.Ns.AllHaveAOrAaaa ? "Yes" : "No").AsPanel();
                                                        g.AddItem("Glue Complete", b.Ns.GlueRecordsComplete ? "Yes" : "No").AsPanel();
                                                        g.AddItem("Glue Consistent", b.Ns.GlueRecordsConsistent ? "Yes" : "No").AsPanel();
                                                        g.AddItem("Delegation Matches", b.Ns.DelegationMatches ? "Yes" : "No").AsPanel();
                                                        g.AddItem("Distinct ASNs", b.Ns.AsnDistinctCount.ToString()).AsPanel();
                                                    });
                                                    if ((b.Ns.Positives?.Count ?? 0) > 0) { c2.Divider("Good Posture"); foreach (var p in b.Ns.Positives ?? System.Array.Empty<DomainDetective.RecommendationAdvice>()) { var t = p?.Title; if (!string.IsNullOrWhiteSpace(t)) c2.Text("• " + t); } }
                                                    var nsFind = (b.Ns.Assessments ?? System.Array.Empty<DomainDetective.Assessment>()).Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info).Select(a => new { Severity = a.Severity.ToString(), a.Code, a.Target, a.Message }).ToList();
                                                    if (nsFind.Count > 0) { c2.Divider("Findings"); var t = (DataTablesTable)c2.Table(nsFind, TableType.DataTables); t.EnablePaging(10, new[]{10,25,50}).EnableSearching().EnableOrdering(); }
                                                }));
                                            });
                                        });
                                    }

                                    // SOA
                                    if (b.Soa != null)
                                    {
                                        acc.AddItem("SOA", item => {
                                            item.HeaderRight(c => c.Badge(b.Soa.Status ?? "-", TablerBadgeColor.Blue, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true));
                                            item.Content(content => {
                                                content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 => {
                                                    c2.DataGrid(g => {
                                                        g.WithLayout(TablerDataGridLayout.Compact).WithSpacing(TablerDataGridSpacing.Small).WithNarrowTitles();
                                                        g.AddItem("Primary NS", b.Soa.PrimaryNameServer ?? "").AsPanel();
                                                        g.AddItem("Responsible", b.Soa.ResponsibleMailbox ?? "").AsPanel();
                                                        g.AddItem("Serial", b.Soa.SerialNumber.ToString()).AsPanel();
                                                        g.AddItem("Serial Format", b.Soa.SerialFormatValid ? "Valid" : "Check").AsPanel();
                                                    });
                                                }));
                                            });
                                        });
                                    }

                                    // CAA
                                    if (b.Caa != null)
                                    {
                                        acc.AddItem("CAA", item => {
                                            item.HeaderRight(c => c.Badge(b.Caa.Status ?? "-", TablerBadgeColor.Blue, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true));
                                            item.Content(content => {
                                                content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 => {
                                                    c2.DataGrid(g => {
                                                        g.WithLayout(TablerDataGridLayout.Compact).WithSpacing(TablerDataGridSpacing.Small).WithNarrowTitles();
                                                        g.AddItem("Valid Records", b.Caa.ValidRecords.ToString()).AsPanel();
                                                        g.AddItem("Invalid Records", b.Caa.InvalidRecords.ToString()).AsPanel();
                                                        g.AddItem("Conflicting", b.Caa.Conflicting ? "Yes" : "No").AsPanel();
                                                    });
                                                }));
                                            });
                                        });
                                    }

                                    // DNSSEC
                                    if (b.Dnssec != null)
                                    {
                                        acc.AddItem("DNSSEC", item => {
                                            item.HeaderRight(c => c.Badge(b.Dnssec.Status ?? "-", ColorForStatus(b.Dnssec.Status), HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true));
                                            item.Content(content => {
                                                content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 => {
                                                    c2.DataGrid(g => { g.WithLayout(TablerDataGridLayout.Compact).WithSpacing(TablerDataGridSpacing.Small).WithNarrowTitles(); g.AddItem("Chain", b.Dnssec.ChainValid ? "Valid" : "Invalid").AsPanel(); g.AddItem("DS Match", b.Dnssec.DsMatch ? "Yes" : "Check").AsPanel(); });
                                                    var dsPos = (b.Dnssec.Positives ?? System.Array.Empty<DomainDetective.RecommendationAdvice>()).Select(p => p?.Title).Where(t => !string.IsNullOrWhiteSpace(t)).Select(t => t!).Distinct(System.StringComparer.OrdinalIgnoreCase).ToList();
                                                    if (dsPos.Count > 0) { c2.Divider("Good Posture"); foreach (var t in dsPos) c2.Text("• " + t); }
                                                    var dsFind = (b.Dnssec.Assessments ?? System.Array.Empty<DomainDetective.Assessment>()).Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info).Select(a => new { Severity = a.Severity.ToString(), a.Code, a.Target, a.Message }).ToList();
                                                    if (dsFind.Count > 0) { c2.Divider("Findings"); var t = (DataTablesTable)c2.Table(dsFind, TableType.DataTables); t.EnablePaging(10, new[]{10,25,50}).EnableSearching().EnableOrdering(); }
                                                    if ((b.Dnssec.References?.Count ?? 0) > 0) { c2.Divider("References"); var refs = b.Dnssec.References!.Where(s => !string.IsNullOrWhiteSpace(s)).ToList(); if (refs.Count > 0) { foreach (var url in refs) c2.Text("• " + url); } }
                                                }));
                                            });
                                        });
                                    }

                                    // DANE
                                    if (b.Dane != null)
                                    {
                                        acc.AddItem("DANE", item => {
                                            item.HeaderRight(c => c.Badge(b.Dane.Status ?? "-", ColorForStatus(b.Dane.Status), HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true));
                                            item.Content(content => {
                                                content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 => {
                                                    c2.DataGrid(g => { g.WithLayout(TablerDataGridLayout.Compact).WithSpacing(TablerDataGridSpacing.Small).WithNarrowTitles(); g.AddItem("Records", b.Dane.NumberOfRecords.ToString()).AsPanel(); g.AddItem("Invalid", b.Dane.HasInvalidRecords ? "Yes" : "No").AsPanel(); });
                                                }));
                                            });
                                        });
                                    }

                                    // Mail TLS
                                    if (b.SmtpTls != null || b.ImapTls != null || b.PopTls != null)
                                    {
                                        acc.AddItem("Mail TLS", item => {
                                            item.Content(content => {
                                                void RenderTls(string label, DomainDetective.Views.MailTlsInfo info)
                                                {
                                                    if (info == null) return;
                                                    content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 => {
                                                        c2.H4(label);
                                                        c2.DataGrid(g => { g.WithLayout(TablerDataGridLayout.Compact).WithSpacing(TablerDataGridSpacing.Small).WithNarrowTitles(); g.AddItem("Status", info.Status ?? "-").AsPanel(); g.AddItem("Servers", (info.Servers?.Count ?? 0).ToString()).AsPanel(); });
                                                        var tf = (info.Assessments ?? System.Array.Empty<DomainDetective.Assessment>()).Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info).Select(a => new { Severity = a.Severity.ToString(), a.Code, a.Target, a.Message }).ToList();
                                                        if (tf.Count > 0) { c2.Divider("Findings"); var t = (DataTablesTable)c2.Table(tf, TableType.DataTables); t.EnablePaging(10, new[]{10,25,50}).EnableSearching().EnableOrdering(); }
                                                    }));
                                                }
                                                if (b.SmtpTls != null) RenderTls("SMTP", b.SmtpTls);
                                                if (b.ImapTls != null) RenderTls("IMAP", b.ImapTls);
                                                if (b.PopTls != null) RenderTls("POP3", b.PopTls);
                                            });
                                        });
                                    }

                                    // RPKI
                                    if (b.Rpki != null)
                                    {
                                        acc.AddItem("RPKI", item => {
                                            item.HeaderRight(c => c.Badge(b.Rpki.Status ?? "-", ColorForStatus(b.Rpki.Status), HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true));
                                            item.Content(content => {
                                                content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 => {
                                                    c2.DataGrid(g => { g.WithLayout(TablerDataGridLayout.Compact).WithSpacing(TablerDataGridSpacing.Small).WithNarrowTitles(); g.AddItem("Valid", b.Rpki.ValidCount.ToString()).AsPanel(); g.AddItem("Total", b.Rpki.TotalChecked.ToString()).AsPanel(); });
                                                }));
                                            });
                                        });
                                    }

                                    // Zone Transfer
                                    if (b.ZoneTransfer != null)
                                    {
                                        acc.AddItem("Zone Transfer", item => {
                                            item.Content(content => {
                                                content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 => {
                                                    c2.DataGrid(g => { g.WithLayout(TablerDataGridLayout.Compact).WithSpacing(TablerDataGridSpacing.Small).WithNarrowTitles(); g.AddItem("Open", $"{b.ZoneTransfer.OpenCount}/{b.ZoneTransfer.TotalChecked}").AsPanel(); });
                                                    var zRows = b.ZoneTransfer.ServerResults?.Select(kv2 => new { Server = kv2.Key, Open = kv2.Value ? "Yes" : "No" }).ToList();
                                                    if (zRows != null && zRows.Count > 0) { var t = (DataTablesTable)c2.Table(zRows, TableType.DataTables); t.EnablePaging(10, new[]{10,25,50}).EnableSearching().EnableOrdering(); }
                                                }));
                                            });
                                        });
                                    }

                                    // Wildcard DNS
                                    if (b.Wildcard != null)
                                    {
                                        acc.AddItem("Wildcard DNS", item => {
                                            item.Content(content => {
                                                content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 => {
                                                    c2.DataGrid(g => { g.WithLayout(TablerDataGridLayout.Compact).WithSpacing(TablerDataGridSpacing.Small).WithNarrowTitles(); g.AddItem("Catch-All", b.Wildcard.CatchAll ? "Yes" : "No").AsPanel(); });
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
