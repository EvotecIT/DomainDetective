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
    private static void RenderExecutiveSummary(HtmlForgeX.TablerPage page, List<KeyValuePair<string, DomainBucket>> ordered)
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
        var totals = ordered.Select(kv => CountFindings(kv.Value)).Aggregate((0, 0), (acc, cur) => (acc.Item1 + cur.warn, acc.Item2 + cur.err));
        page.Row(row => {
            row.WithBottomSpacing(TablerSpacing.Medium);

            row.Column(TablerColumnNumber.Four, col => {
                col.Card(card => {
                    card.Background(TablerColor.Success, isLight: true)
                        .Header(h => { h.Title("Domains").Subtitle("Analyzed"); h.Avatar(a => a.Icon(TablerIconType.Globe).BackgroundColor(TablerColor.Success).TextColor(TablerColor.White).Size(AvatarSize.MD)); })
                        .Body(b => { b.H2(ordered.Count.ToString()); b.Text("Total").Style(TablerTextStyle.Muted); });
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

        // Executive summary table (DataTables) with highlighters
        page.Divider("Executive Summary");
        page.Row(r => r.Column(TablerColumnNumber.Twelve, c => {
            var rows = ordered.Select(kv => new {
                Domain = kv.Key,
                MX = kv.Value.Mx?.Status ?? "-",
                SPF = kv.Value.Spf?.Status ?? "-",
                DKIM = kv.Value.Dkim.Count > 0 ? (kv.Value.Dkim.Max(x => x.Status) ?? "-") : "-",
                DMARC = kv.Value.Dmarc?.Status ?? "-",
                MTASTS = kv.Value.Mtasts?.Status ?? "-",
                TLSRPT = kv.Value.TlsRpt?.Status ?? "-",
                Findings = $"{CountFindings(kv.Value).warn} / {CountFindings(kv.Value).err}"
            }).ToList();
            c.Card(card => {
                card.Header(h => h.Title("Domains"));
                card.Body(body => {
                    var table = (DataTablesTable)body.Table(rows, TableType.DataTables);
                    table.EnablePaging(10, new[] { 10, 25, 50 }).EnableSearching().EnableOrdering();
                    foreach (var col in new[] { "MX", "SPF", "DKIM", "DMARC", "MTASTS", "TLSRPT" })
                        table.HighlightWhen(g => g.And(x => x.StringContains(col, "error", false)).Or(x => x.StringContains(col, "fail", false)), t => t.Column(col).Danger());
                    foreach (var col in new[] { "MX", "SPF", "DKIM", "DMARC", "MTASTS", "TLSRPT" })
                        table.HighlightWhen(g => g.Or(x => x.StringContains(col, "warn", false)), t => t.Column(col).Warning());
                });
            });
        }));
    }
}
