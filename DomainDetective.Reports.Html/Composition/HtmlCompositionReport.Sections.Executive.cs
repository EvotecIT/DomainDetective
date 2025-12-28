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
    private static void RenderHeaderBanner(Element page, string title)
    {
        page.Row(r =>
        {
            r.Column(TablerColumnNumber.Twelve, c =>
            {
                c.Card(card =>
                {
                    card.Background(TablerColor.Blue, isLight: true)
                        .Header(h =>
                        {
                            h.WithHeaderTitleLevel(HeaderLevelTag.H1).TitleDisplay(TablerTextSize.Display3);
                            h.Title(title);
                            h.Subtitle($"Generated on: {DateTime.Now:MMMM d, yyyy, h:mm tt zzz}")
                             .SubtitleAsHeader(HeaderLevelTag.H5);
                        });
                });
            });
        });
    }

    private static void RenderExecutiveSummary(Element page, List<KeyValuePair<string, DomainBucket>> ordered, System.Collections.Generic.List<DomainDetective.Reports.ExecutiveSummaryBuilder.Row> rows, string overviewLine)
    {
        var controlRollup = BuildControlRollup(rows);

        // Aggregate stats used in the overview
        var grade = ComputeOverallGrade(rows);
        var gradeColor = GradeColor(grade);
        var totals = (warn: rows.Sum(r => r.Warnings), err: rows.Sum(r => r.Errors));
        var domainsCount = ordered.Count;
        bool hasMx = rows.Any(r => !IsEmptyStatus(r.Mx));
        bool hasSpf = rows.Any(r => !IsEmptyStatus(r.Spf));
        bool hasDkim = rows.Any(r => !IsEmptyStatus(r.Dkim));
        bool hasDmarc = rows.Any(r => !IsEmptyStatus(r.Dmarc));
        bool hasMtasts = rows.Any(r => !IsEmptyStatus(r.Mtasts));
        bool hasTlsRpt = rows.Any(r => !IsEmptyStatus(r.TlsRpt));
        bool hasDnssec = rows.Any(r => !IsEmptyStatus(r.Dnssec));
        bool hasRpki = rows.Any(r => !IsEmptyStatus(r.Rpki));
        bool hasClass = rows.Any(r => !IsEmptyStatus(r.Classification));
        bool IncludeControl(string key) => key switch
        {
            "MX" => hasMx,
            "SPF" => hasSpf,
            "DKIM" => hasDkim,
            "DMARC" => hasDmarc,
            "MTA-STS" => hasMtasts,
            "TLS-RPT" => hasTlsRpt,
            "DNSSEC" => hasDnssec,
            "RPKI" => hasRpki,
            _ => false
        };

        // Hero stats row with CardMini widgets (TestimoX-style AutoFit + Flex).
        page.Row(row => {
            row.Settings(s => s
                .AutoFit(TablerCardWidth.Large, maxColumns: 4, policy: TablerAutoFitPolicy.WideOneLine)
                .Engine(TablerAutoFitEngine.Flex)
                .EqualHeights());
            row.WithBottomSpacing(TablerSpacing.Small);
            row.Column(col => {
                col.CardMini()
                    .Avatar(TablerIconType.Award)
                    .BackgroundColor(gradeColor)
                    .TextColor(TablerColor.White)
                    .Title(grade)
                    .Subtitle("Overall Grade");
            });
            row.Column(col => {
                col.CardMini()
                    .Avatar(TablerIconType.World)
                    .BackgroundColor(domainsCount > 0 ? TablerColor.Blue : TablerColor.Gray500)
                    .TextColor(TablerColor.White)
                    .Title(domainsCount.ToString())
                    .Subtitle(domainsCount == 1 ? "Domain" : "Domains");
            });
            row.Column(col => {
                col.CardMini()
                    .Avatar(TablerIconType.AlertTriangle)
                    .BackgroundColor(totals.warn > 0 ? TablerColor.Orange : TablerColor.Green)
                    .TextColor(TablerColor.White)
                    .Title(totals.warn.ToString())
                    .Subtitle(totals.warn == 1 ? "Warning" : "Warnings");       
            });
            row.Column(col => {
                col.CardMini()
                    .Avatar(TablerIconType.AlertCircle)
                    .BackgroundColor(totals.err > 0 ? TablerColor.Red : TablerColor.Green)
                    .TextColor(TablerColor.White)
                    .Title(totals.err.ToString())
                    .Subtitle(totals.err == 1 ? "Error" : "Errors");
            });
        });

        // Calculate status totals for donut chart
        var statusTotals = (ok: 0, warn: 0, err: 0, unknown: 0);
        foreach (var kv in controlRollup)
        {
            if (IncludeControl(kv.Key))
            {
                statusTotals.ok += kv.Value.ok;
                statusTotals.warn += kv.Value.warn;
                statusTotals.err += kv.Value.err;
                statusTotals.unknown += kv.Value.unknown;
            }
        }

        // Control status: donut chart + grid
        page.Row(row => {
            row.WithBottomSpacing(TablerSpacing.Medium);
            // Donut chart
            row.Column(TablerColumnNumber.Four, col => {
                col.Card(card => {
                    card.Header(h => h.Title("Status Distribution").Icon(TablerIconType.ChartDonut));
                    card.Body(b => {
                        if (statusTotals.ok + statusTotals.warn + statusTotals.err + statusTotals.unknown == 0)
                        {
                            b.Text("No data").Style(TablerTextStyle.Muted);
                        }
                        else
                        {
                            b.ApexChart(ch => {
                                ch.AddDonut("OK", statusTotals.ok, "#2fb344");
                                ch.AddDonut("Warning", statusTotals.warn, "#f59e0b");
                                ch.AddDonut("Error", statusTotals.err, "#d63939");
                                ch.AddDonut("Unknown", statusTotals.unknown, "#6c757d");
                            });
                        }
                    });
                });
            });
            // Control grid
            row.Column(TablerColumnNumber.Eight, col => {
                col.Card(card => {
                    card.Header(h => h.Title("Control Status").Subtitle("OK / Warning / Error / Unknown").Icon(TablerIconType.ShieldCheck));
                    card.Body(b => {
                        b.DataGrid(g => {
                            g.Settings(s => s.Layout(TablerDataGridLayout.Compact).Spacing(TablerDataGridSpacing.Small).NarrowTitles().MobileResponsive());
                            if (hasMx) { var s = ControlStatusLabel(controlRollup["MX"]); g.AddItem("MX", s).AsPanel(PanelColorForStatus(s), light: true); }
                            if (hasSpf) { var s = ControlStatusLabel(controlRollup["SPF"]); g.AddItem("SPF", s).AsPanel(PanelColorForStatus(s), light: true); }
                            if (hasDkim) { var s = ControlStatusLabel(controlRollup["DKIM"]); g.AddItem("DKIM", s).AsPanel(PanelColorForStatus(s), light: true); }
                            if (hasDmarc) { var s = ControlStatusLabel(controlRollup["DMARC"]); g.AddItem("DMARC", s).AsPanel(PanelColorForStatus(s), light: true); }
                            if (hasMtasts) { var s = ControlStatusLabel(controlRollup["MTA-STS"]); g.AddItem("MTA-STS", s).AsPanel(PanelColorForStatus(s), light: true); }
                            if (hasTlsRpt) { var s = ControlStatusLabel(controlRollup["TLS-RPT"]); g.AddItem("TLS-RPT", s).AsPanel(PanelColorForStatus(s), light: true); }
                            if (hasDnssec) { var s = ControlStatusLabel(controlRollup["DNSSEC"]); g.AddItem("DNSSEC", s).AsPanel(PanelColorForStatus(s), light: true); }
                            if (hasRpki) { var s = ControlStatusLabel(controlRollup["RPKI"]); g.AddItem("RPKI", s).AsPanel(PanelColorForStatus(s), light: true); }
                            g.AsTiles("13rem");
                        });
                        if (!(hasMx || hasSpf || hasDkim || hasDmarc || hasMtasts || hasTlsRpt || hasDnssec || hasRpki))
                        {
                            b.Text("No control data available.").Style(TablerTextStyle.Muted);
                        }
                    });
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
                            card.Header(h => h.Title("Top Findings").Subtitle("Most frequent warnings/errors").Icon(TablerIconType.AlertTriangle));
                            card.Body(b =>
                            {
                                RenderTopFindingsList(b, topFindings, includeCode: false);
                            });
                        });
                    });
                    r.Column(TablerColumnNumber.Six, c =>
                    {
                        c.Card(card =>
                        {
                            card.Header(h => h.Title("Control Risk Rollup").Subtitle("OK / Warning / Error / Unknown").Icon(TablerIconType.ChartBar));
                            card.Body(body =>
                            {
                                var rows2 = controlRollup
                                    .Where(kv => IncludeControl(kv.Key))
                                    .Select(kv => new {
                                        Control = kv.Key,
                                        OK = kv.Value.ok,
                                        Warning = kv.Value.warn,
                                        Error = kv.Value.err,
                                        Unknown = kv.Value.unknown
                                    }).ToList();
                                if (rows2.Count == 0)
                                {
                                    body.Text("No control data available.").Style(TablerTextStyle.Muted);
                                    return;
                                }
                                var t = (TablerTable)body.Table(rows2, TableType.Tabler);
                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                            });
                        });
                    });
                });
            }
        } catch { }

        // Coverage summary with progress bars
        try
        {
            if (rows.Count > 0 && controlRollup.Count > 0)
            {
                page.Row(r =>
                {
                    r.Column(TablerColumnNumber.Twelve, c =>
                    {
                        c.Card(card =>
                        {
                            card.Header(h => h.Title("Control Coverage").Subtitle("Presence across domains").Icon(TablerIconType.ChartPie));
                            card.Body(body =>
                            {
                                var total = rows.Count;
                                var coverageData = controlRollup
                                    .Where(kv => IncludeControl(kv.Key))
                                    .Select(kv =>
                                    {
                                        var present = kv.Value.ok + kv.Value.warn + kv.Value.err;
                                        var pct = total > 0 ? (int)Math.Round(present * 100.0 / total) : 0;
                                        return (Control: kv.Key, Present: present, Total: total, Pct: pct, Ok: kv.Value.ok, Warn: kv.Value.warn, Err: kv.Value.err);
                                    }).ToList();
                                if (coverageData.Count == 0)
                                {
                                    body.Text("No control data available.").Style(TablerTextStyle.Muted);
                                    return;
                                }
                                // Render each control with a progress bar
                                foreach (var item in coverageData)
                                {
                                    body.Row(rr =>
                                    {
                                        rr.Column(TablerColumnNumber.Two, cc =>
                                        {
                                            cc.Text(item.Control).Style(TablerTextStyle.Primary);
                                        });
                                        rr.Column(TablerColumnNumber.Eight, cc =>
                                        {
                                            // Stacked progress bar: OK (green) + Warning (orange) + Error (red)
                                            var okPct = item.Total > 0 ? (int)Math.Round(item.Ok * 100.0 / item.Total) : 0;
                                            var warnPct = item.Total > 0 ? (int)Math.Round(item.Warn * 100.0 / item.Total) : 0;
                                            var errPct = item.Total > 0 ? (int)Math.Round(item.Err * 100.0 / item.Total) : 0;
                                            cc.Add(new TablerProgressBar()
                                                .Item(TablerColor.Success, okPct, "")
                                                .Item(TablerColor.Warning, warnPct, "")
                                                .Item(TablerColor.Danger, errPct, ""));
                                        });
                                        rr.Column(TablerColumnNumber.Two, cc =>
                                        {
                                            cc.Text($"{item.Present}/{item.Total} ({item.Pct}%)").Style(TablerTextStyle.Muted);
                                        });
                                    });
                                }
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
                        card.Header(h => h.Title("Good Posture").Subtitle("Top positive signals across all domains").Icon(TablerIconType.CircleCheck));
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
                    card.Header(h => h.Title("Legend").Subtitle("Status meanings").Icon(TablerIconType.InfoCircle));
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

        // Domain table intentionally removed from Summary; it lives in the Domains tab.
    }
}
