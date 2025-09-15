using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;

namespace DomainDetective.Reports.Html;

public static partial class HtmlCompositionReport
{
    private static void RenderDashboardMailTls(HtmlForgeX.TablerPage page, List<KeyValuePair<string, DomainBucket>> ordered)
    {
        var rows = new List<object>();
        foreach (var kv in ordered)
        {
            void add(string service, DomainDetective.Views.MailTlsInfo? info)
            {
                if (info == null) return;
                foreach (var s in info.Servers ?? Array.Empty<DomainDetective.Views.MailTlsServerInfo>())
                {
                    rows.Add(new {
                        Domain = kv.Key,
                        Service = service,
                        Host = s.Key,
                        Status = info.Status ?? "-",
                        StartTLS = s.StartTlsAdvertised ? "Yes" : "No",
                        Grade = s.Grade.ToString(),
                        Proto = s.Protocol,
                        TLS13 = s.Tls13Used ? "Yes" : (s.SupportsTls13 ? "Supported" : "No"),
                        DaysToExpire = s.DaysToExpire,
                    });
                }
            }
            add("SMTP", kv.Value.SmtpTls);
            add("IMAP", kv.Value.ImapTls);
            add("POP3", kv.Value.PopTls);
        }
        if (rows.Count == 0) return;

        // Grade summary across all services
        var gradeCounts = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase) { {"A",0},{"B",0},{"C",0},{"D",0},{"F",0} };
        foreach (var kv in ordered)
        {
            void addGrades(DomainDetective.Views.MailTlsInfo? info)
            {
                if (info == null) return;
                foreach (var s in info.Servers ?? Array.Empty<DomainDetective.Views.MailTlsServerInfo>())
                {
                    var g = s.Grade.ToString();
                    if (gradeCounts.ContainsKey(g)) gradeCounts[g]++;
                }
            }
            addGrades(kv.Value.SmtpTls); addGrades(kv.Value.ImapTls); addGrades(kv.Value.PopTls);
        }

        page.Divider("MailTLS Servers");
        // Grades KPI
        page.Row(r => {
            r.WithBottomSpacing(TablerSpacing.Small);
            foreach (var label in new[]{"A","B","C","D","F"})
            {
                var count = gradeCounts[label];
                var color = label == "A" ? TablerColor.Success : (label == "B" ? TablerColor.Green : (label == "C" ? TablerColor.Orange : (label == "D" ? TablerColor.Yellow : TablerColor.Danger)));
                r.Column(TablerColumnNumber.Two, c => c.Card(card => {
                    card.Background(color, isLight: true)
                        .Header(h => { h.Title($"Grade {label}").Subtitle("Servers"); })
                        .Body(b => b.H3(count.ToString()));
                }));
            }
        });
        page.Row(r => r.Column(TablerColumnNumber.Twelve, c => {
            c.Card(card => {
                card.Header(h => h.Title("MailTLS Servers (all domains)"));
                card.Body(b => {
                    var t = (DataTablesTable)b.Table(rows, TableType.DataTables);
                    t.EnablePaging(10, new[] { 10, 25, 50 }).EnableSearching().EnableOrdering();
                    t.HighlightWhen(g => g.Or(x => x.StringContains("Status", "error", false)), a => a.Column("Status").Danger());
                    t.HighlightWhen(g => g.Or(x => x.StringContains("Status", "warn", false)), a => a.Column("Status").Warning());
                });
            });
        }));
    }
}
