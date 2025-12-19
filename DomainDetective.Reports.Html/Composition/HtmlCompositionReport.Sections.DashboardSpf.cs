using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HtmlCompositionReport partial: extra SPF details for Dashboard profile.
/// </summary>
public static partial class HtmlCompositionReport
{
    private static void RenderDashboardSpf(HtmlForgeX.TablerPage page, List<KeyValuePair<string, DomainBucket>> ordered)
    {
        // Collect SPF sections
        var data = new List<(string Domain, DomainDetective.Reports.SectionProjectors.SpfSection Sec)>();
        foreach (var kv in ordered)
        {
            if (kv.Value.Spf == null) continue;
            var sec = DomainDetective.Reports.SectionProjectors.BuildSpf(kv.Value.Spf);
            if (sec != null) data.Add((kv.Key, sec));
        }
        if (data.Count == 0) return;

        page.Divider("SPF Details");
        page.Row(r => r.Column(TablerColumnNumber.Twelve, c => {
            // Overview table per domain
            var overviewRows = data.Select(d => new {
                Domain = d.Domain,
                Status = d.Sec.Summary.FirstOrDefault(kv => string.Equals(kv.Key, "Status", StringComparison.OrdinalIgnoreCase)).Value ?? d.Sec.Status,
                Lookups = d.Sec.DnsLookupsCount,
                All = d.Sec.Summary.FirstOrDefault(kv => string.Equals(kv.Key, "All Mechanism", StringComparison.OrdinalIgnoreCase)).Value ?? "-",
                RecordLength = (d.Sec.SpfRecord ?? string.Empty).Length,
                Mechanisms = d.Sec.Mechanisms.Count
            }).ToList();
            c.Card(card => {
                card.Header(h => h.Title("SPF Overview (per domain)"));
                card.Body(b => {
                    var t = (DataTablesTable)b.Table(overviewRows, TableType.DataTables);
                    t.EnablePaging(10, new[] { 10, 25, 50 }).EnableSearching().EnableOrdering();
                    t.HighlightWhen(g => g.Or(x => x.StringContains("Status", "error", false)), a => a.Column("Status").Danger());
                    t.HighlightWhen(g => g.Or(x => x.StringContains("Status", "warn", false)), a => a.Column("Status").Warning());
                });
            });
        }));

        // Mechanisms (all domains)
        page.Row(r => r.Column(TablerColumnNumber.Twelve, c => {
            var mechRows = new List<object>();
            foreach (var d in data)
            {
                foreach (var m in d.Sec.Mechanisms)
                    mechRows.Add(new { Domain = d.Domain, Qualifier = m.Qualifier, Type = m.Type, Value = m.Value, Provider = m.Provider });
            }
            if (mechRows.Count > 0)
            {
                c.Card(card => {
                    card.Header(h => h.Title("SPF Mechanisms (all domains)"));
                    card.Body(b => {
                        var t = (DataTablesTable)b.Table(mechRows, TableType.DataTables);
                        t.EnablePaging(10, new[] { 10, 25, 50 }).EnableSearching().EnableOrdering();
                    });
                });
            }
        }));

        // Provider help (badges per domain)
        page.Row(r => r.Column(TablerColumnNumber.Twelve, c => {
            c.Card(card => {
                card.Header(h => h.Title("SPF Provider Help"));
                card.Body(b => {
                    foreach (var d in data)
                    {
                        b.Text(d.Domain).Style(TablerTextStyle.Muted);
                        b.Row(rr => {
                            rr.Gap(2);
                            foreach (var (title, url) in d.Sec.ProviderHelp.Take(6))
                                rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(title, TablerBadgeColor.Azure, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true, href: url));
                        });
                    }
                });
            });
        }));
    }
}


