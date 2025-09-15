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
                                foreach (var kv2 in top) rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(kv2.Key, TablerBadgeColor.Success, HtmlForgeX.Containers.Tabler.TablerBadgeStyle.Light, TablerBadgeSize.Small, pill: true));
                            });
                        });
                    });
                }));
            }
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
