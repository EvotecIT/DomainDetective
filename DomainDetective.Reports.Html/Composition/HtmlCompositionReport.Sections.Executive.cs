using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HtmlCompositionReport partial: banner, KPIs, executive summary table.
/// </summary>
public static partial class HtmlCompositionReport
{
    private static void RenderExecutiveSummary(HtmlForgeX.TablerPage page, List<KeyValuePair<string, DomainBucket>> ordered, System.Collections.Generic.List<DomainDetective.Reports.ExecutiveSummaryBuilder.Row> rows, string overviewLine)
    {
        // Header banner card
        page.Row(r => {
            r.Column(TablerColumnNumber.Twelve, c => {
                c.Card(card => {
                    card.Background(TablerColor.Blue, isLight: true)
                        .Header(h => {
                            h.WithHeaderTitleLevel(HeaderLevelTag.H1).TitleDisplay(TablerTextSize.Display3);
                            h.Title("Domain Security Compliance Report");
                            h.Subtitle($"Generated on: {DateTime.Now:MMMM d, yyyy, h:mm tt zzz}").SubtitleAsHeader(HeaderLevelTag.H5);
                        });
                });
            });
        });

        var controlRollup = BuildControlRollup(rows);

        // Security rating hero
        var grade = ComputeOverallGrade(rows);
        var gradeColor = GradeColor(grade);
        page.Row(row => {
            row.WithBottomSpacing(TablerSpacing.Medium);
            row.Column(TablerColumnNumber.Twelve, col => {
                col.Card(card => {
                    card.Header(h => h.Title("Security Rating").Subtitle("Aggregate posture across domains"));
                    card.Body(b => {
                        b.DataGrid(g => {
                            g.Settings(s => s.Layout(TablerDataGridLayout.Compact).Spacing(TablerDataGridSpacing.Small).NarrowTitles());
                            g.AddItem("Overall Grade", grade).AsPanel(gradeColor, light: true);
                            g.AddItem("Domains", rows.Count.ToString()).AsPanel(TablerColor.Blue, light: true);
                            g.AddItem("Warnings", rows.Sum(r => r.Warnings).ToString()).AsPanel(TablerColor.Orange, light: true);
                            g.AddItem("Errors", rows.Sum(r => r.Errors).ToString()).AsPanel(TablerColor.Red, light: true);
                            var spfStatus = ControlStatusLabel(controlRollup["SPF"]);
                            var dkimStatus = ControlStatusLabel(controlRollup["DKIM"]);
                            var dmarcStatus = ControlStatusLabel(controlRollup["DMARC"]);
                            var mtastsStatus = ControlStatusLabel(controlRollup["MTA-STS"]);
                            var tlsRptStatus = ControlStatusLabel(controlRollup["TLS-RPT"]);
                            g.AddItem("SPF", spfStatus).AsPanel(PanelColorForStatus(spfStatus), light: true);
                            g.AddItem("DKIM", dkimStatus).AsPanel(PanelColorForStatus(dkimStatus), light: true);
                            g.AddItem("DMARC", dmarcStatus).AsPanel(PanelColorForStatus(dmarcStatus), light: true);
                            g.AddItem("MTA-STS", mtastsStatus).AsPanel(PanelColorForStatus(mtastsStatus), light: true);
                            g.AddItem("TLS-RPT", tlsRptStatus).AsPanel(PanelColorForStatus(tlsRptStatus), light: true);
                        });
                    });
                });
            });
        });

        // KPI cards: Domains / Warnings / Errors
        var totals = (warn: rows.Sum(r => r.Warnings), err: rows.Sum(r => r.Errors));
        page.Row(row => {
            row.WithBottomSpacing(TablerSpacing.Medium);

            row.Column(TablerColumnNumber.Four, col => {
                col.Card(card => {
                    card.Background(TablerColor.Success, isLight: true)
                        .Header(h => { h.Title("Domains").Subtitle("Analyzed"); h.Avatar(a => a.Icon(TablerIconType.Globe).BackgroundColor(TablerColor.Success).TextColor(TablerColor.White).Size(AvatarSize.MD)); })
                        .Body(b => { b.H2(rows.Count.ToString()); b.Text("Total").Style(TablerTextStyle.Muted); });
                });
            });
            row.Column(TablerColumnNumber.Four, col => {
                col.Card(card => {
                    card.Background(TablerColor.Warning, isLight: true)
                        .Header(h => { h.Title("Warnings").Subtitle("Attention"); h.Avatar(a => a.Icon(TablerIconType.AlertCircle).BackgroundColor(TablerColor.Orange).TextColor(TablerColor.White).Size(AvatarSize.MD)); })
                        .Body(b => { b.H2(totals.Item1.ToString()); b.Text("Across all domains").Style(TablerTextStyle.Muted); });
                });
            });
            row.Column(TablerColumnNumber.Four, col => {
                col.Card(card => {
                    card.Background(TablerColor.Danger, isLight: true)
                        .Header(h => { h.Title("Errors").Subtitle("Critical"); h.Avatar(a => a.Icon(TablerIconType.AlertTriangle).BackgroundColor(TablerColor.Danger).TextColor(TablerColor.White).Size(AvatarSize.MD)); })
                        .Body(b => { b.H2(totals.Item2.ToString()); b.Text("Across all domains").Style(TablerTextStyle.Muted); });
                });
            });
        });

        // Identical wording with Word: overview paragraph (single source)
        try {
            page.Row(r => r.Column(TablerColumnNumber.Twelve, c => {
                c.Card(card => card.Body(b => b.Text(overviewLine)));
            }));
        } catch { }

        // Top findings + control rollup
        try
        {
            var topFindings = BuildTopFindings(ordered.Select(kv => kv.Value), 6);
            if (topFindings.Count > 0 || controlRollup.Count > 0)
            {
                page.Row(r =>
                {
                    r.Column(TablerColumnNumber.Six, c =>
                    {
                        c.Card(card =>
                        {
                            card.Header(h => h.Title("Top Findings").Subtitle("Most frequent warnings/errors"));
                            card.Body(b =>
                            {
                                if (topFindings.Count == 0)
                                {
                                    b.Text("No warnings or errors detected.").Style(TablerTextStyle.Muted);
                                    return;
                                }
                                b.DataGrid(g =>
                                {
                                    g.Settings(s => s.Layout(TablerDataGridLayout.Compact).Spacing(TablerDataGridSpacing.Small).NarrowTitles());
                                    foreach (var f in topFindings)
                                    {
                                        var label = string.IsNullOrWhiteSpace(f.Code) ? f.Title : $"{f.Code}: {f.Title}";
                                        var title = TrimForDisplay(label, 120);
                                        var color = SeverityRank(f.Severity) == 0 ? TablerColor.Red : TablerColor.Orange;
                                        g.AddItem(title, $"x{f.Count}").AsPanel(color, light: true);
                                    }
                                });
                            });
                        });
                    });
                    r.Column(TablerColumnNumber.Six, c =>
                    {
                        c.Card(card =>
                        {
                            card.Header(h => h.Title("Control Risk Rollup").Subtitle("OK / Warning / Error / Unknown"));
                            card.Body(body =>
                            {
                                var rows2 = controlRollup.Select(kv => new {
                                    Control = kv.Key,
                                    OK = kv.Value.ok,
                                    Warning = kv.Value.warn,
                                    Error = kv.Value.err,
                                    Unknown = kv.Value.unknown
                                }).ToList();
                                var t = (TablerTable)body.Table(rows2, TableType.Tabler);
                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                            });
                        });
                    });
                });
            }
        } catch { }

        // Good Posture (aggregated top positives across domains)
        try {
            var positiveCounts = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
            void AddPos(IEnumerable<string> items) { foreach (var t in items ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(t)) positiveCounts[t] = (positiveCounts.TryGetValue(t, out var c)? c:0) + 1; }
            foreach (var kv in ordered) {
                var b = kv.Value;
                AddPos((b.Spf?.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()).Select(p => p?.Title ?? p?.Code).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s!));
                AddPos((b.Dmarc?.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()).Select(p => p?.Title ?? p?.Code).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s!));
                AddPos(b.Dkim.SelectMany(x => x.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()).Select(p => p?.Title ?? p?.Code).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s!));
                AddPos((b.Mx?.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()).Select(p => p?.Title ?? p?.Code).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s!));
                AddPos((b.Mtasts?.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()).Select(p => p?.Title ?? p?.Code).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s!));
                AddPos((b.TlsRpt?.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()).Select(p => p?.Title ?? p?.Code).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s!));
                AddPos((b.Ns?.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()).Select(p => p?.Title ?? p?.Code).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s!));
                AddPos((b.Dnssec?.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()).Select(p => p?.Title ?? p?.Code).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s!));
                AddPos((b.Caa?.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()).Select(p => p?.Title ?? p?.Code).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s!));
            }
            var top = positiveCounts.OrderByDescending(kv2 => kv2.Value).ThenBy(kv2 => kv2.Key, StringComparer.OrdinalIgnoreCase).Take(10).ToList();
            if (top.Count > 0) {
                page.Row(r => r.Column(TablerColumnNumber.Twelve, c => {
                    c.Card(card => {
                        card.Header(h => h.Title("Good Posture").Subtitle("Top positive signals across all domains"));
                        card.Body(b => {
                            b.Row(rr => {
                                rr.Gap(2);
                                foreach (var kv2 in top) rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(kv2.Key, TablerBadgeColor.Success, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true));
                            });
                        });
                    });
                }));
            }
        } catch { }

        // Legend (status meanings) — parity with Markdown
        try {
            page.Row(r => r.Column(TablerColumnNumber.Twelve, c => {
                c.Card(card => {
                    card.Header(h => h.Title("Legend").Subtitle("Status meanings"));
                    card.Body(b => {
                        var rows = new[] {
                            new { Status = "🟢 OK", Meaning = "All checks passed or acceptable" },
                            new { Status = "🟠 Warning", Meaning = "Requires attention; not blocking" },
                            new { Status = "🔴 Error", Meaning = "Blocking or invalid configuration" }
                        };
                        var t = (TablerTable)b.Table(rows, TableType.Tabler);
                        t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                    });
                });
            }));
        } catch { }

        // Executive summary table (DataTables) with highlighters
        page.Divider("Executive Summary");
        page.Row(r => r.Column(TablerColumnNumber.Twelve, c => {
            var tableRows = rows.Select(rw => new {
                Domain = rw.Domain,
                MX = rw.Mx,
                SPF = rw.Spf,
                DKIM = rw.Dkim,
                DMARC = rw.Dmarc,
                MTASTS = rw.Mtasts,
                TLSRPT = rw.TlsRpt,
                DNSSEC = rw.Dnssec,
                RPKI = rw.Rpki,
                Findings = $"{rw.Warnings} / {rw.Errors}"
            }).ToList();
            c.Card(card => {
                card.Header(h => h.Title("Domains"));
                card.Body(body => {
                    var table = (DataTablesTable)body.Table(tableRows, TableType.DataTables);
                    table.EnablePaging(10, new[] { 10, 25, 50 }).EnableSearching().EnableOrdering();
                    foreach (var col in new[] { "MX", "SPF", "DKIM", "DMARC", "MTASTS", "TLSRPT", "DNSSEC", "RPKI" })
                        table.HighlightWhen(g => g.And(x => x.StringContains(col, "error", false)).Or(x => x.StringContains(col, "fail", false)), t => t.Column(col).Danger());
                    foreach (var col in new[] { "MX", "SPF", "DKIM", "DMARC", "MTASTS", "TLSRPT", "DNSSEC", "RPKI" })
                        table.HighlightWhen(g => g.Or(x => x.StringContains(col, "warn", false)), t => t.Column(col).Warning());
                });
            });
        }));
    }
}

