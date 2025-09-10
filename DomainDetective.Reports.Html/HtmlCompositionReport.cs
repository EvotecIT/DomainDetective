using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Html;

/// <summary>
/// Aggregates mixed view objects (SPF/DKIM/DMARC) for one or more domains into a single HTML document using the IHtmlComposer adapter.
/// </summary>
/// <summary>
/// Builds a single HTML report from mixed view objects using the engine-agnostic composer.
/// </summary>
public static partial class HtmlCompositionReport {
    /// <summary>
    /// Generates the HTML report.
    /// </summary>
    /// <param name="path">Output file path.</param>
    /// <param name="items">View objects grouped by Subject.</param>
    /// <param name="scope">Detail level.</param>
    /// <param name="openInBrowser">Open the file after saving.</param>
    /// <param name="narrativePlacement">Where to render background narrative (global or per-domain).</param>
    /// <param name="titleOverride">Optional document title override.</param>
    /// <param name="authorOverride">Optional author override.</param>
    /// <param name="descriptionOverride">Optional description/summary override.</param>
    public static void Generate(string path, IReadOnlyList<object> items, Reports.ReportScope scope, bool openInBrowser = false, Reports.NarrativePlacement narrativePlacement = Reports.NarrativePlacement.Auto, string? titleOverride = null, string? authorOverride = null, string? descriptionOverride = null, DomainDetective.Reports.DomainOrder domainOrder = DomainDetective.Reports.DomainOrder.Alphabetical, DomainDetective.Reports.SectionOrderMode sectionOrderMode = DomainDetective.Reports.SectionOrderMode.Canonical, string[]? sectionOrder = null) {
        if (items == null || items.Count == 0) throw new ArgumentException("No items to compose.", nameof(items));

        var grouped = GroupBySubject(items);
        var ordered = (domainOrder == DomainDetective.Reports.DomainOrder.Input)
            ? OrderDomainsByInput(items, grouped)
            : grouped.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase).ToList();

        var title = BuildSubjectTitle(grouped.Keys.ToList());
        var theTitle = string.IsNullOrWhiteSpace(titleOverride) ? $"Domain Security Compliance Report — {title}" : titleOverride;
        var theAuthor = string.IsNullOrWhiteSpace(authorOverride) ? "DomainDetective" : authorOverride;
        var theDesc = string.IsNullOrWhiteSpace(descriptionOverride) ? "Security posture overview for domains" : descriptionOverride;

        using var document = new Document {
            Head = {
                Title = theTitle,
                Author = theAuthor,
                Description = theDesc,
                Revised = DateTime.Now
            },
            LibraryMode = LibraryMode.Online,
            ThemeMode = ThemeMode.Light
        };

        document.Body.Page(page => {
            page.Layout = TablerLayout.Combo;

            // Executive banner, KPIs, and summary table
            RenderExecutiveSummary(page, ordered);

            // Mail Providers — rendered via a dedicated partial to keep file small
            try { RenderProvidersSection(page, ordered); } catch { }

            // Optional global background/narrative placeholder (can be enhanced)
            var multiDomain = grouped.Count > 1;
            var placeGlobal = narrativePlacement == Reports.NarrativePlacement.Global || (narrativePlacement == Reports.NarrativePlacement.Auto && multiDomain);
            if (placeGlobal) {
                page.Divider("Background");
                page.Row(rr => rr.Column(TablerColumnNumber.Twelve, cc => {
                    cc.Card(cd => { cd.Body(b => b.Text("Background narrative omitted in this version.")); });
                }));
            }

            // Per-domain overview cards + accordion details (SPF/DMARC/DKIM/MX)
#if false /* legacy inline rendering kept temporarily for reference; can be removed */
            if (multiDomain) {
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

                                foreach (var kv in ordered) {
                                    var d = kv.Key; var b = kv.Value;
                                    tabs.AddTab(d, TablerIconType.Globe, panel => {
                                        // Make domain obvious + show quick stats
                                        var warnCount = (b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + b.Dkim.Sum(x => x.WarningCount);
                                        var errCount = (b.Mx?.ErrorCount ?? 0) + (b.Spf?.ErrorCount ?? 0) + (b.Dmarc?.ErrorCount ?? 0) + (b.Mtasts?.ErrorCount ?? 0) + (b.TlsRpt?.ErrorCount ?? 0) + b.Dkim.Sum(x => x.ErrorCount);

                                        // Severity banner with compact header badges (no intermediate grid/row)
                                        panel.Card(card => {
                                            var sevColor = TablerColor.Blue;
                                            var statusText = "OK";
                                            if (errCount > 0) { sevColor = TablerColor.Danger; statusText = $"{errCount} Error" + (errCount > 1 ? "s" : ""); } else if (warnCount > 0) { sevColor = TablerColor.Warning; statusText = $"{warnCount} Warning" + (warnCount > 1 ? "s" : ""); }
                                            card.Ribbon(statusText, sevColor)
                                                .Header(h => {
                                                    h.Title($"Mail & DNS — {d}")
                                                     .Subtitle($"{warnCount} warning(s), {errCount} error(s)")
                                                     .SubtitleStyle(TablerTextStyle.Muted)
                                                     .WithActions(a => {
                                                         // Findings counters first
                                                         a.Badge(errCount > 0 ? $"{errCount} Error" + (errCount>1?"s":"") : "0 Error", TablerBadgeColor.Danger, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                                         a.Badge(warnCount > 0 ? $"{warnCount} Warning" + (warnCount>1?"s":"") : "0 Warning", TablerBadgeColor.Warning, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                                         a.Badge($"MX: {b.Mx?.Status ?? "-"}", ColorForStatus(b.Mx?.Status));
                                                         a.Badge($"SPF: {b.Spf?.Status ?? "-"}", ColorForStatus(b.Spf?.Status));
                                                         var dk = b.Dkim.Count > 0 ? (b.Dkim.Max(x => x.Status) ?? "-") : "-";
                                                         a.Badge($"DKIM: {dk}", ColorForStatus(dk));
                                                         a.Badge($"DMARC: {b.Dmarc?.Status ?? "-"}", ColorForStatus(b.Dmarc?.Status));
                                                         a.Badge($"MTA-STS: {b.Mtasts?.Status ?? "-"}", ColorForStatus(b.Mtasts?.Status));
                                                         a.Badge($"TLS-RPT: {b.TlsRpt?.Status ?? "-"}", ColorForStatus(b.TlsRpt?.Status));
                                                     });
                                                });
                                            card.Body(bdy => {
                                                var dkimStatus = b.Dkim.Count > 0 ? (b.Dkim.Max(x => x.Status) ?? "-") : "-";
                                                var summary = $"SPF {b.Spf?.Status ?? "-"}, DMARC {b.Dmarc?.Status ?? "-"}, DKIM {dkimStatus}, MX {b.Mx?.Status ?? "-"}, MTA-STS {b.Mtasts?.Status ?? "-"}, TLS-RPT {b.TlsRpt?.Status ?? "-"}";
                                                bdy.Text(summary).Style(TablerTextStyle.Muted);
                                            });
                                        });

                                        // Detailed sections as accordion, same content as single-domain view
                                        panel.Accordion(acc => {
                                            //acc.AlwaysOpen(false);
                                            // SPF
                                            if (b.Spf != null) {
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
                                                                        c2.Row(rr2 => {
                                                                            rr2.Gap(2);
                                                                            foreach (var provider in links) {
                                                                                if (!string.IsNullOrWhiteSpace(provider?.Spf))
                                                                                    rr2.Column(TablerColumnNumber.Auto, cc => cc.Badge(provider!.ProviderName, TablerBadgeColor.Secondary, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true, href: provider.Spf));
                                                                                foreach (var topic in (provider?.Topics ?? new System.Collections.Generic.List<DomainDetective.Views.ProviderHelpTopic>())) {
                                                                                    if (!string.IsNullOrWhiteSpace(topic?.Url))
                                                                                        rr2.Column(TablerColumnNumber.Auto, cc => cc.Badge(topic!.Title ?? topic.Topic, TablerBadgeColor.Blue, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true, href: topic.Url));
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
                                            if (b.Dmarc != null) {
                                                acc.AddItem("DMARC (Domain-based Message Authentication)", item => {
                                                    item.HeaderRight(c => {
                                                        c.Badge(b.Dmarc.ErrorCount > 0 ? $"{b.Dmarc.ErrorCount} Error" + (b.Dmarc.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                                        c.Badge(b.Dmarc.WarningCount > 0 ? $"{b.Dmarc.WarningCount} Warning" + (b.Dmarc.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                                        c.Badge(b.Dmarc.Status ?? "Unknown", TablerBadgeColor.Blue, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                                    });
                                                    item.Content(content => {
                                                        content.Row(r => {
                                                            r.Column(TablerColumnNumber.Twelve, c2 => {
                                                                c2.DataGrid(g => {
                                                                    g.WithLayout(TablerDataGridLayout.Compact).WithSpacing(TablerDataGridSpacing.Small).WithNarrowTitles();
                                                                    g.AddItem("Policy", string.IsNullOrWhiteSpace(b.Dmarc.Policy) ? "-" : b.Dmarc.Policy).AsPanel();
                                                                    g.AddItem("Subdomain Policy", string.IsNullOrWhiteSpace(b.Dmarc.SubPolicy) ? "-" : b.Dmarc.SubPolicy).AsPanel();
                                                                    g.AddItem("Alignment", $"dkim={b.Dmarc.DkimAlignment ?? "?"}; spf={b.Dmarc.SpfAlignment ?? "?"}").AsPanel();
                                                                });
                                                                // Provider help for DMARC if surfaced under MX provider help
                                                                try {
                                                                    var links = b.Mx?.ProviderHelp;
                                                                    if (links != null) {
                                                                        c2.Row(rr2 => {
                                                                            rr2.Gap(2);
                                                                            foreach (var provider in links) {
                                                                                if (!string.IsNullOrWhiteSpace(provider?.Dmarc))
                                                                                    rr2.Column(TablerColumnNumber.Auto, cc => cc.Badge(provider!.ProviderName, TablerBadgeColor.Secondary, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true, href: provider.Dmarc));
                                                                            }
                                                                        });
                                                                    }
                                                                } catch { }

                                                                if ((b.Dmarc.Highlights?.Count ?? 0) > 0) { c2.Divider("Highlights"); foreach (var t in b.Dmarc.Highlights) c2.Text("• " + t); }
                                                                if ((b.Dmarc.Positives?.Count ?? 0) > 0) { c2.Divider("Good Posture"); foreach (var p in b.Dmarc.Positives) if (!string.IsNullOrWhiteSpace(p?.Title)) c2.Text("• " + p!.Title!); }

                                                                if (string.Equals(b.Dmarc.Policy, "quarantine", StringComparison.OrdinalIgnoreCase)) {
                                                                    c2.Alert("Recommendation", "After monitoring aggregate reports, consider upgrading DMARC policy to p=reject for maximum protection.", TablerColor.Blue).WithDescription();
                                                                }
                                                            });
                                                        });
                                                    });
                                                });
                                            }

                                            // DKIM (summarized)
                                            if (b.Dkim.Count > 0) {
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
                                                                    where: g => g.Or(cg => {
                                                                        cg.StringContains("Status", "error", false);
                                                                        cg.StringContains("Status", "fail", false);
                                                                    }),
                                                                    then: t => t.Column("Status").Danger());
                                                                table.HighlightWhen(
                                                                    where: g => g.Or(cg => {
                                                                        cg.StringContains("Status", "warn", false);
                                                                    }),
                                                                    then: t => t.Column("Status").Warning());
                                                            });
                                                        });
                                                    });
                                                });
                                            }

                                            // MX quick notes
                                            if (b.Mx != null) {
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
                                        }); // end accordion
                                    }); // end AddTab
                                } // end foreach
                            }); // end SmartTab
                        }); // end card.Body
                    }); // end card
                })); // end page.Row
            } else {
                foreach (var kv in ordered) {
                    var d = kv.Key; var b = kv.Value;
                    page.Divider(d);
                    page.Row(row => {
                        row.Column(TablerColumnNumber.Twelve, col => {
                            col.Card(card => {
                                // Ribbon severity
                                var sevColor = TablerColor.Blue;
                                var statusText = "OK";
                                var warnCount = (b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + b.Dkim.Sum(x => x.WarningCount);
                                var errCount = (b.Mx?.ErrorCount ?? 0) + (b.Spf?.ErrorCount ?? 0) + (b.Dmarc?.ErrorCount ?? 0) + (b.Mtasts?.ErrorCount ?? 0) + (b.TlsRpt?.ErrorCount ?? 0) + b.Dkim.Sum(x => x.ErrorCount);
                                if (errCount > 0) { sevColor = TablerColor.Danger; statusText = $"{errCount} Error" + (errCount > 1 ? "s" : ""); } else if (warnCount > 0) { sevColor = TablerColor.Warning; statusText = $"{warnCount} Warning" + (warnCount > 1 ? "s" : ""); }
                                card.Ribbon(statusText, sevColor)
                                    .Header(h => {
                                        h.Title($"Mail & DNS — {d}")
                                         .Subtitle($"{warnCount} warning(s), {errCount} error(s)")
                                         .SubtitleStyle(TablerTextStyle.Muted)
                                     .WithActions(a => {
                                         a.Badge(errCount > 0 ? $"{errCount} Error" + (errCount>1?"s":"") : "0 Error", TablerBadgeColor.Danger, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                         a.Badge(warnCount > 0 ? $"{warnCount} Warning" + (warnCount>1?"s":"") : "0 Warning", TablerBadgeColor.Warning, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                         a.Badge($"MX: {b.Mx?.Status ?? "-"}", ColorForStatus(b.Mx?.Status));
                                         a.Badge($"SPF: {b.Spf?.Status ?? "-"}", ColorForStatus(b.Spf?.Status));
                                             var dk = b.Dkim.Count > 0 ? (b.Dkim.Max(x => x.Status) ?? "-") : "-";
                                             a.Badge($"DKIM: {dk}", ColorForStatus(dk));
                                             a.Badge($"DMARC: {b.Dmarc?.Status ?? "-"}", ColorForStatus(b.Dmarc?.Status));
                                             a.Badge($"MTA-STS: {b.Mtasts?.Status ?? "-"}", ColorForStatus(b.Mtasts?.Status));
                                             a.Badge($"TLS-RPT: {b.TlsRpt?.Status ?? "-"}", ColorForStatus(b.TlsRpt?.Status));
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
                                                // The SPF/DMARC/DKIM accordions remain below (outside tabs) — we only add a compact overview here.
                                                if (b.Spf != null) a.AddItem("SPF", it => it.Content(c => c.DataGrid(g => { g.AsCompact(); g.AddItem("Status", b.Spf.Status ?? "-"); g.AddItem("DNS Lookups", b.Spf.DnsLookupsCount.ToString()); })));
                                                if (b.Dmarc != null) a.AddItem("DMARC", it => it.Content(c => c.DataGrid(g => { g.AsCompact(); g.AddItem("Status", b.Dmarc.Status ?? "-"); g.AddItem("Policy", string.IsNullOrWhiteSpace(b.Dmarc.Policy) ? "-" : b.Dmarc.Policy); })));
                                                if (b.Dkim.Count > 0) a.AddItem("DKIM", it => it.Content(c => c.DataGrid(g => { g.AsCompact(); g.AddItem("Selectors", b.Dkim.Count.ToString()); g.AddItem("Any Weak", b.Dkim.Any(x => x.WeakKey).ToString()); })));
                                            });
                                        });

                                        // Transport tab
                                        tabs.AddTab("Transport", TablerIconType.TruckDelivery, panel => {
                                            panel.DataGrid(g => { g.AsCompact(); g.AddItem("MTA-STS", b.Mtasts?.Status ?? "-"); g.AddItem("TLS-RPT", b.TlsRpt?.Status ?? "-"); });
                                        });

                                        // Reputation tab (DNSBL)
                                        if (b.Dnsbl != null) {
                                            tabs.AddTab("Reputation", TablerIconType.ShieldCheck, panel => {
                                                panel.Text("DNSBL summary available");
                                            });
                                        }
                                    });
                                });
                            });
                            col.Accordion(acc => {
                                //acc.AlwaysOpen(false);
                                // SPF
                                if (b.Spf != null) {
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
                                if (b.Dmarc != null) {
                                    acc.AddItem("DMARC (Domain-based Message Authentication)", item => {
                                        item.HeaderRight(c => {
                                            c.Badge(b.Dmarc.ErrorCount > 0 ? $"{b.Dmarc.ErrorCount} Error" + (b.Dmarc.ErrorCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                            c.Badge(b.Dmarc.WarningCount > 0 ? $"{b.Dmarc.WarningCount} Warning" + (b.Dmarc.WarningCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                            c.Badge(b.Dmarc.Status ?? "Unknown", TablerBadgeColor.Blue, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true);
                                        });
                                        item.Content(content => {
                                            content.Row(r => {
                                                r.Column(TablerColumnNumber.Twelve, c2 => {
                                                    c2.DataGrid(g => {
                                                        g.WithLayout(TablerDataGridLayout.Compact).WithSpacing(TablerDataGridSpacing.Small).WithNarrowTitles();
                                                        g.AddItem("Policy", string.IsNullOrWhiteSpace(b.Dmarc.Policy) ? "-" : b.Dmarc.Policy).AsPanel();
                                                        g.AddItem("Subdomain Policy", string.IsNullOrWhiteSpace(b.Dmarc.SubPolicy) ? "-" : b.Dmarc.SubPolicy).AsPanel();
                                                        g.AddItem("Alignment", $"dkim={b.Dmarc.DkimAlignment ?? "?"}; spf={b.Dmarc.SpfAlignment ?? "?"}").AsPanel();
                                                    });
                                                    // Provider help for DMARC if surfaced under MX provider help
                                                    try {
                                                        var links = b.Mx?.ProviderHelp;
                                                        if (links != null) {
                                                            c2.Row(rr => {
                                                                rr.Gap(2);
                                                                foreach (var provider in links) {
                                                                    if (!string.IsNullOrWhiteSpace(provider?.Dmarc))
                                                                        rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(provider!.ProviderName, TablerBadgeColor.Secondary, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true, href: provider.Dmarc));
                                                                }
                                                            });
                                                        }
                                                    } catch { }

                                                    if ((b.Dmarc.Highlights?.Count ?? 0) > 0) { c2.Divider("Highlights"); foreach (var t in b.Dmarc.Highlights) c2.Text("• " + t); }
                                                    if ((b.Dmarc.Positives?.Count ?? 0) > 0) { c2.Divider("Good Posture"); foreach (var p in b.Dmarc.Positives) if (!string.IsNullOrWhiteSpace(p?.Title)) c2.Text("• " + p!.Title!); }

                                                    if (string.Equals(b.Dmarc.Policy, "quarantine", StringComparison.OrdinalIgnoreCase)) {
                                                        c2.Alert("Recommendation", "After monitoring aggregate reports, consider upgrading DMARC policy to p=reject for maximum protection.", TablerColor.Blue).WithDescription();
                                                    }
                                                });
                                            });
                                        });
                                    });
                                }
                                // DKIM (summarized)
                                if (b.Dkim.Count > 0) {
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
                                                        where: g => g.Or(c => {
                                                            c.StringContains("Status", "error", false);
                                                            c.StringContains("Status", "fail", false);
                                                        }),
                                                        then: t => t.Column("Status").Danger());
                                                    table.HighlightWhen(
                                                        where: g => g.Or(c => {
                                                            c.StringContains("Status", "warn", false);
                                                        }),
                                                        then: t => t.Column("Status").Warning());
                                                });
                                            });
                                        });
                                    });
                                }
                                // MX quick notes
                                if (b.Mx != null) {
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
                    });
                }
                // Close 'else' block for single-domain rendering
            }
#endif
            if (multiDomain) { RenderDomainsTabbed(page, ordered); }
            else { foreach (var kv in ordered) RenderSingleDomain(page, kv.Key, kv.Value); }
            // Ensure page block closes cleanly
        });

        document.Save(path, openInBrowser);
    }

    }
