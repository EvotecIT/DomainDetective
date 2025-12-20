using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HtmlCompositionReport partial: diagnostics (raw findings across all domains/sections).
/// </summary>
public static partial class HtmlCompositionReport
{
    private static void RenderDiagnosticsSection(Element page, List<KeyValuePair<string, DomainBucket>> ordered)
    {
        if (ordered == null || ordered.Count == 0)
        {
            return;
        }

        var all = new List<(string Domain, string Section, DomainDetective.AssessmentSeverity Severity, string Code, string Target, string Message)>();

        void Add(string domain, string section, IEnumerable<DomainDetective.Assessment>? assessments)
        {
            if (assessments == null)
            {
                return;
            }
            foreach (var a in assessments)
            {
                if (a == null)
                {
                    continue;
                }
                all.Add((
                    domain,
                    section,
                    a.Severity,
                    a.Code ?? string.Empty,
                    a.Target ?? string.Empty,
                    a.Message ?? string.Empty));
            }
        }

        foreach (var kv in ordered)
        {
            var domain = kv.Key;
            var b = kv.Value;
            if (b == null)
            {
                continue;
            }

            Add(domain, "MX", b.Mx?.Assessments);
            Add(domain, "SPF", b.Spf?.Assessments);
            Add(domain, "DMARC", b.Dmarc?.Assessments);
            Add(domain, "ARC", b.Arc?.Assessments);
            Add(domain, "BIMI", b.Bimi?.Assessments);
            Add(domain, "MTA-STS", b.Mtasts?.Assessments);
            Add(domain, "TLS-RPT", b.TlsRpt?.Assessments);
            Add(domain, "DNSBL", b.Dnsbl?.Assessments);
            Add(domain, "DNSSEC", b.Dnssec?.Assessments);
            Add(domain, "DANE", b.Dane?.Assessments);
            Add(domain, "RPKI", b.Rpki?.Assessments);
            Add(domain, "NS", b.Ns?.Assessments);
            Add(domain, "SOA", b.Soa?.Assessments);
            Add(domain, "CAA", b.Caa?.Assessments);
            Add(domain, "TTL", b.Ttl?.Assessments);
            Add(domain, "ZoneTransfer", b.ZoneTransfer?.Assessments);
            Add(domain, "Wildcard", b.Wildcard?.Assessments);
            Add(domain, "Classification", b.Classification?.Assessments);       
            Add(domain, "MailTLS (SMTP)", b.SmtpTls?.Assessments);
            Add(domain, "MailTLS (IMAP)", b.ImapTls?.Assessments);
            Add(domain, "MailTLS (POP3)", b.PopTls?.Assessments);

            foreach (var d in b.Dkim)
            {
                if (d == null)
                {
                    continue;
                }
                var selector = string.IsNullOrWhiteSpace(d.Selector) ? string.Empty : $" ({d.Selector})";
                Add(domain, "DKIM" + selector, d.Assessments);
            }
        }

        if (all.Count == 0)
        {
            page.Row(r => r.Column(TablerColumnNumber.Twelve, c =>        
            {
                c.Card(card =>
                {
                    card.Header(h => h.Title("Findings & Signals").Subtitle("No diagnostics data available."));
                    card.Body(b => b.Text("No assessments were produced by the selected checks.").Style(TablerTextStyle.Muted));
                });
            }));
            return;
        }

        var errCount = all.Count(x => x.Severity == DomainDetective.AssessmentSeverity.Error);
        var warnCount = all.Count(x => x.Severity == DomainDetective.AssessmentSeverity.Warning);
        var infoCount = all.Count(x => x.Severity == DomainDetective.AssessmentSeverity.Info);

        page.Row(row =>
        {
            row.Settings(s => s
                .AutoFit(TablerCardWidth.Large, maxColumns: 4, policy: TablerAutoFitPolicy.WideOneLine)
                .Engine(TablerAutoFitEngine.Flex)
                .EqualHeights());
            row.WithBottomSpacing(TablerSpacing.Small);

            row.Column(col =>
            {
                col.CardMini()
                   .Avatar(TablerIconType.AlertCircle)
                   .BackgroundColor(errCount > 0 ? TablerColor.Red : TablerColor.Green)
                   .TextColor(TablerColor.White)
                   .Title(errCount.ToString())
                   .Subtitle(errCount == 1 ? "Error" : "Errors");
            });
            row.Column(col =>
            {
                col.CardMini()
                   .Avatar(TablerIconType.AlertTriangle)
                   .BackgroundColor(warnCount > 0 ? TablerColor.Orange : TablerColor.Green)
                   .TextColor(TablerColor.White)
                   .Title(warnCount.ToString())
                   .Subtitle(warnCount == 1 ? "Warning" : "Warnings");
            });
            row.Column(col =>
            {
                col.CardMini()
                   .Avatar(TablerIconType.InfoCircle)
                   .BackgroundColor(infoCount > 0 ? TablerColor.Blue : TablerColor.Green)
                   .TextColor(TablerColor.White)
                   .Title(infoCount.ToString())
                   .Subtitle(infoCount == 1 ? "Info" : "Infos");
            });
        });

        page.Row(r => r.Column(TablerColumnNumber.Twelve, c =>
        {
            c.Card(card =>
            {
                card.Header(h => h.Title("Findings & Signals").Subtitle("All assessments across domains/sections").Icon(TablerIconType.Table));
                card.Body(b =>
                {
                    var rows = all
                        .OrderBy(x => SeverityRank(x.Severity.ToString()))
                        .ThenBy(x => x.Domain, StringComparer.OrdinalIgnoreCase)
                        .ThenBy(x => x.Section, StringComparer.OrdinalIgnoreCase)
                        .ThenBy(x => x.Code, StringComparer.OrdinalIgnoreCase)
                        .Select(x => new
                        {
                            x.Domain,
                            x.Section,
                            Severity = x.Severity.ToString(),
                            Code = NormalizeFindingCodeForDisplay(x.Code) ?? string.Empty,
                            x.Target,
                            x.Message
                        })
                        .ToList();

                    var t = (DataTablesTable)b.Table(rows, TableType.DataTables);
                    ConfigureStandardDataTable(t, defaultMode: ToggleViewMode.ScrollX);
                    t.EnablePaging(25, new[] { 10, 25, 50, 100 })
                     .EnableSearching()
                     .EnableOrdering();

                    // Severity highlighting
                    t.HighlightWhen(g => g.And(c2 => c2.StringContains("Severity", "Error", caseSensitive: false)), then: tt => tt.Column("Severity").Danger());
                    t.HighlightWhen(g => g.And(c2 => c2.StringContains("Severity", "Warning", caseSensitive: false)), then: tt => tt.Column("Severity").Warning());
                    t.HighlightWhen(g => g.And(c2 => c2.StringContains("Severity", "Info", caseSensitive: false)), then: tt => tt.Column("Severity").Info());
                });
            });
        }));
    }
}
