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

        // Aggregate stats used in the overview
        var grade = ComputeOverallGrade(rows);
        var gradeColor = GradeColor(grade);
        var totals = (warn: rows.Sum(r => r.Warnings), err: rows.Sum(r => r.Errors));
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

        // Executive overview: grade + control status rollup
        page.Row(row => {
            row.WithBottomSpacing(TablerSpacing.Medium);
            row.Column(TablerColumnNumber.Four, col => {
                col.Card(card => {
                    card.Background(gradeColor, isLight: true)
                        .Header(h => h.Title("Overall Grade").Subtitle("Aggregate posture"))
                        .Body(b => {
                            b.H1(grade);
                            b.Text($"{rows.Count} domain(s)").Style(TablerTextStyle.Muted);
                            b.Text($"{totals.warn} warning(s) / {totals.err} error(s)").Style(TablerTextStyle.Muted);
                        });
                });
            });
            row.Column(TablerColumnNumber.Eight, col => {
                col.Card(card => {
                    card.Header(h => h.Title("Control Status").Subtitle("OK / Warning / Error / Unknown"));
                    card.Body(b => {
                        b.DataGrid(g => {
                            g.Settings(s => s.Layout(TablerDataGridLayout.Compact).Spacing(TablerDataGridSpacing.Small).NarrowTitles());
                            if (hasMx) { var s = ControlStatusLabel(controlRollup["MX"]); g.AddItem("MX", s).AsPanel(PanelColorForStatus(s), light: true); }
                            if (hasSpf) { var s = ControlStatusLabel(controlRollup["SPF"]); g.AddItem("SPF", s).AsPanel(PanelColorForStatus(s), light: true); }
                            if (hasDkim) { var s = ControlStatusLabel(controlRollup["DKIM"]); g.AddItem("DKIM", s).AsPanel(PanelColorForStatus(s), light: true); }
                            if (hasDmarc) { var s = ControlStatusLabel(controlRollup["DMARC"]); g.AddItem("DMARC", s).AsPanel(PanelColorForStatus(s), light: true); }
                            if (hasMtasts) { var s = ControlStatusLabel(controlRollup["MTA-STS"]); g.AddItem("MTA-STS", s).AsPanel(PanelColorForStatus(s), light: true); }
                            if (hasTlsRpt) { var s = ControlStatusLabel(controlRollup["TLS-RPT"]); g.AddItem("TLS-RPT", s).AsPanel(PanelColorForStatus(s), light: true); }
                            if (hasDnssec) { var s = ControlStatusLabel(controlRollup["DNSSEC"]); g.AddItem("DNSSEC", s).AsPanel(PanelColorForStatus(s), light: true); }
                            if (hasRpki) { var s = ControlStatusLabel(controlRollup["RPKI"]); g.AddItem("RPKI", s).AsPanel(PanelColorForStatus(s), light: true); }
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
                            card.Header(h => h.Title("Top Findings").Subtitle("Most frequent warnings/errors"));
                            card.Body(b =>
                            {
                                if (topFindings.Count == 0)
                                {
                                    b.Text("No warnings or errors detected.").Style(TablerTextStyle.Muted);
                                    return;
                                }
                                var rows2 = topFindings.Select(f =>
                                {
                                    var label = string.IsNullOrWhiteSpace(f.Code) ? f.Title : $"{f.Code}: {f.Title}";
                                    var rank = SeverityRank(f.Severity);
                                    var sev = rank == 0 ? "Error" : (rank == 1 ? "Warning" : "Info");
                                    return new
                                    {
                                        Severity = sev,
                                        Finding = TrimForDisplay(label, 140),
                                        Count = f.Count
                                    };
                                }).ToList();
                                var t = (TablerTable)b.Table(rows2, TableType.Tabler);
                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
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

        // Coverage summary
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
                            card.Header(h => h.Title("Control Coverage").Subtitle("Presence across domains"));
                            card.Body(body =>
                            {
                                var total = rows.Count;
                                var rows2 = controlRollup
                                    .Where(kv => IncludeControl(kv.Key))
                                    .Select(kv =>
                                    {
                                        var present = kv.Value.ok + kv.Value.warn + kv.Value.err;
                                        var missing = kv.Value.unknown;
                                        var pct = total > 0 ? (present * 100.0 / total) : 0;
                                        return new { Control = kv.Key, Present = present, Missing = missing, Coverage = $"{pct:0}%"};
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
            var summaryColumns = new List<(string Header, Func<DomainDetective.Reports.ExecutiveSummaryBuilder.Row, string> Get)>();
            if (hasMx) summaryColumns.Add(("MX", r2 => r2.Mx));
            if (hasSpf) summaryColumns.Add(("SPF", r2 => r2.Spf));
            if (hasDkim) summaryColumns.Add(("DKIM", r2 => r2.Dkim));
            if (hasDmarc) summaryColumns.Add(("DMARC", r2 => r2.Dmarc));
            if (hasMtasts) summaryColumns.Add(("MTASTS", r2 => r2.Mtasts));
            if (hasTlsRpt) summaryColumns.Add(("TLSRPT", r2 => r2.TlsRpt));
            if (hasDnssec) summaryColumns.Add(("DNSSEC", r2 => r2.Dnssec));
            if (hasRpki) summaryColumns.Add(("RPKI", r2 => r2.Rpki));
            if (hasClass) summaryColumns.Add(("Classification", r2 => r2.Classification));
            var tableRows = rows.Select(rw => {
                var row = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Domain"] = rw.Domain
                };
                foreach (var col in summaryColumns)
                {
                    row[col.Header] = col.Get(rw);
                }
                row["Findings"] = $"{rw.Warnings} / {rw.Errors}";
                return (IDictionary<string, object>)row;
            }).ToList();
            c.Card(card => {
                card.Header(h => h.Title("Domains"));
                card.Body(body => {
                    var table = (DataTablesTable)body.Table(tableRows, TableType.DataTables);
                    table.EnablePaging(10, new[] { 10, 25, 50 }).EnableSearching().EnableOrdering();
                    var statusColumns = summaryColumns
                        .Where(s => !string.Equals(s.Header, "Classification", StringComparison.OrdinalIgnoreCase))
                        .Select(s => s.Header)
                        .ToList();
                    foreach (var col in statusColumns)
                        table.HighlightWhen(g => g.And(x => x.StringContains(col, "error", false)).Or(x => x.StringContains(col, "fail", false)), t => t.Column(col).Danger());
                    foreach (var col in statusColumns)
                        table.HighlightWhen(g => g.Or(x => x.StringContains(col, "warn", false)), t => t.Column(col).Warning());
                });
            });
        }));
    }
}

