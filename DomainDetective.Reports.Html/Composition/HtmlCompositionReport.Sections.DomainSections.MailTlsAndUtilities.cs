using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;
using DomainDetective;
using DomainDetective.Reports;
using DomainDetective.Views;
using DomainDetective.Narratives;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HtmlCompositionReport partial: ordered per-domain sections.
/// </summary>
public static partial class HtmlCompositionReport
{
    private static void RenderMailTlsSection(TablerAccordion acc, DomainBucket b)
    {
        if (b.SmtpTls == null && b.ImapTls == null && b.PopTls == null)
        {
            return;
        }
        var sec = SectionProjectors.BuildMailTls(b.SmtpTls, b.ImapTls, b.PopTls);
        int warnCount = (b.SmtpTls?.WarningCount ?? 0) + (b.ImapTls?.WarningCount ?? 0) + (b.PopTls?.WarningCount ?? 0);
        int errCount = (b.SmtpTls?.ErrorCount ?? 0) + (b.ImapTls?.ErrorCount ?? 0) + (b.PopTls?.ErrorCount ?? 0);
        var status = errCount > 0 ? "Error" : (warnCount > 0 ? "Warning" : "OK");
        var narrative = b.SmtpTls?.Raw != null
            ? MailTlsNarrative.Build(b.SmtpTls.Raw, DomainDetective.MailTlsAnalysis.MailProtocol.Smtp)
            : b.ImapTls?.Raw != null
                ? MailTlsNarrative.Build(b.ImapTls.Raw, DomainDetective.MailTlsAnalysis.MailProtocol.Imap)
                : b.PopTls?.Raw != null
                    ? MailTlsNarrative.Build(b.PopTls.Raw, DomainDetective.MailTlsAnalysis.MailProtocol.Pop3)
                    : null;
        acc.AddItem("Mail TLS", item => {
            item.Icon(TablerIconType.LockCheck);
            item.HeaderRight(c =>
            {
                c.Badge(errCount > 0 ? $"{errCount} Error" + (errCount > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(warnCount > 0 ? $"{warnCount} Warning" + (warnCount > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(status, ColorForStatus(status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content => {
                content.Row(r => {
                    r.Column(TablerColumnNumber.Twelve, c2 => {
                        bool useNewLayout = true;
                        if (useNewLayout)
                        {
                            var findingsCount = warnCount + errCount;
                            var findingsBadgeColor = errCount > 0
                                ? TablerBadgeColor.Danger
                                : (warnCount > 0 ? TablerBadgeColor.Warning : TablerBadgeColor.Success);
                            var refs = MergeReferences(sec?.References, narrative?.References);

                            RenderExecutionSnapshotCard(c2, g =>
                            {
                                g.AddItem("Status", status).AsPanel(PanelColorForStatus(status), light: true);
                                g.AddItem("Warnings", warnCount.ToString()).AsPanel(warnCount > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                                g.AddItem("Errors", errCount.ToString()).AsPanel(errCount > 0 ? TablerColor.Red : TablerColor.Green, light: true);

                                if (b.SmtpTls != null) g.AddItem("SMTP", b.SmtpTls.Status ?? "-").AsPanel(PanelColorForStatus(b.SmtpTls.Status), light: true);
                                if (b.ImapTls != null) g.AddItem("IMAP", b.ImapTls.Status ?? "-").AsPanel(PanelColorForStatus(b.ImapTls.Status), light: true);
                                if (b.PopTls != null) g.AddItem("POP3", b.PopTls.Status ?? "-").AsPanel(PanelColorForStatus(b.PopTls.Status), light: true);
                            });

                            RenderGuidanceWizardCard(c2, narrative, providerHelp: null, providerHelpTopics: null, references: refs);

                            RenderResultsTabsCard(
                                c2,
                                tabs =>
                            {
                                tabs.AddTab("Summary", panel =>
                                {
                                    panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                    {
                                        RenderSignalsSummary(col, sec?.Findings.Select(f => f.Message), sec?.Positives);
                                    }));
                                }).WithIcon(TablerIconType.Cards);

                                var findingsTab = tabs.AddTab("Findings", panel =>
                                {
                                    panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                    {
                                        RenderFindings(col, sec?.Findings);
                                    }));
                                }).WithIcon(TablerIconType.AlertTriangle);
                                if (findingsCount > 0)
                                {
                                    findingsTab.WithBadge(findingsCount.ToString(), findingsBadgeColor);
                                }

                                tabs.AddTab("Evidence", panel =>
                                {
                                    panel.Row(rr => rr.Column(TablerColumnNumber.Twelve, col =>
                                    {
                                        bool hasEvidence = false;
                                        if (sec != null && sec.Rows.Count > 0)
                                        {
                                            hasEvidence = true;
                                            var rows = sec.Rows.Select(v => new
                                            {
                                                v.Service,
                                                v.Status,
                                                Protocol = string.IsNullOrWhiteSpace(v.Protocol) ? "-" : v.Protocol
                                            }).ToList();
                                            var t = (TablerTable)col.Table(rows, TableType.Tabler);
                                            t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                                        }

                                        if (b.SmtpTls?.Servers != null && b.SmtpTls.Servers.Count > 0)
                                        {
                                            hasEvidence = true;
                                            RenderMailTlsServers(col, "SMTP", b.SmtpTls);
                                        }
                                        if (b.ImapTls?.Servers != null && b.ImapTls.Servers.Count > 0)
                                        {
                                            hasEvidence = true;
                                            RenderMailTlsServers(col, "IMAP", b.ImapTls);
                                        }
                                        if (b.PopTls?.Servers != null && b.PopTls.Servers.Count > 0)
                                        {
                                            hasEvidence = true;
                                            RenderMailTlsServers(col, "POP3", b.PopTls);
                                        }

                                        if (!hasEvidence)
                                        {
                                            col.Text("No evidence captured for this section.").Style(TablerTextStyle.Muted);
                                        }
                                    }));
                                }).WithIcon(TablerIconType.FileText);
                            });
                        }
                        else
                        {
                            if (sec != null && sec.Rows.Count > 0)
                            {
                                var rows = sec.Rows.Select(v => new { v.Service, v.Status, Protocol = string.IsNullOrWhiteSpace(v.Protocol) ? "-" : v.Protocol }).ToList();
                                var t = (TablerTable)c2.Table(rows, TableType.Tabler);
                                t.Style(BootStrapTableStyle.Striped).Style(BootStrapTableStyle.Hover);
                            }
                            RenderPositives(c2, sec?.Positives);
                            RenderFindings(c2, sec?.Findings);
                            RenderNarrative(c2, narrative);
                            if (b.SmtpTls?.Servers != null && b.SmtpTls.Servers.Count > 0) RenderMailTlsServers(c2, "SMTP", b.SmtpTls);
                            if (b.ImapTls?.Servers != null && b.ImapTls.Servers.Count > 0) RenderMailTlsServers(c2, "IMAP", b.ImapTls);
                            if (b.PopTls?.Servers != null && b.PopTls.Servers.Count > 0) RenderMailTlsServers(c2, "POP3", b.PopTls);
                            RenderReferences(c2, MergeReferences(sec?.References, narrative?.References));
                        }
                    });
                });
            });
        });
    }

    private static void RenderSummaryGrid(TablerColumn c2, IEnumerable<(string Key, string Value)>? summary)
    {
        if (summary == null)
        {
            return;
        }
        var items = summary.ToList();
        if (items.Count == 0)
        {
            return;
        }
        c2.DataGrid(g => {
            g.AsCompact();
            foreach (var kv in items)
            {
                g.AddItem(kv.Key, kv.Value).AsPanel();
            }
        });
    }

    private static void RenderSignalsSummary(TablerColumn c2, IEnumerable<string>? highlights, IEnumerable<string>? positives)
    {
        var issues = (highlights ?? Array.Empty<string>())
            .Where(t => !string.IsNullOrWhiteSpace(t))
            .Select(t => t.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var good = (positives ?? Array.Empty<string>())
            .Where(t => !string.IsNullOrWhiteSpace(t))
            .Select(t => t.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (issues.Count == 0 && good.Count == 0)
        {
            c2.Text("No notable signals captured for this check.").Style(TablerTextStyle.Muted);
            return;
        }

        const int maxItems = 12;
        int issuesMore = Math.Max(0, issues.Count - maxItems);
        int goodMore = Math.Max(0, good.Count - maxItems);
        issues = issues.Take(maxItems).ToList();
        good = good.Take(maxItems).ToList();

        foreach (var t in issues)
        {
            c2.Alert(TrimForDisplay(t, 320), string.Empty, TablerColor.Orange)
                .Icon(TablerIconType.AlertTriangle)
                .Minor();
        }
        if (issuesMore > 0)
        {
            c2.Text($"+{issuesMore} more issue(s)…").Style(TablerTextStyle.Muted);
        }

        foreach (var t in good)
        {
            c2.Alert(TrimForDisplay(t, 320), string.Empty, TablerColor.Green)
                .Icon(TablerIconType.CircleCheck)
                .Minor();
        }
        if (goodMore > 0)
        {
            c2.Text($"+{goodMore} more positive signal(s)…").Style(TablerTextStyle.Muted);
        }
    }

    private static void RenderHighlights(TablerColumn c2, IEnumerable<string>? highlights)
    {
        if (highlights == null)
        {
            return;
        }
        var list = highlights.Where(t => !string.IsNullOrWhiteSpace(t)).ToList();
        if (list.Count == 0)
        {
            return;
        }
        c2.Card(card =>
        {
            card.Header(h => h.Title("Highlights").Icon(TablerIconType.AlertTriangle));
            card.Body(body =>
            {
                var ul = body.TablerList();
                foreach (var t in list)
                {
                    ul.AddItem(t, TablerIconType.AlertTriangle);
                }
            });
        });
    }

    private static void RenderPositives(TablerColumn c2, IEnumerable<string>? positives)
    {
        if (positives == null)
        {
            return;
        }
        var list = positives.Where(t => !string.IsNullOrWhiteSpace(t)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (list.Count == 0)
        {
            return;
        }
        c2.Card(card =>
        {
            card.Header(h => h.Title("Good Posture").Icon(TablerIconType.CircleCheck));
            card.Body(body =>
            {
                var ul = body.TablerList();
                foreach (var t in list)
                {
                    ul.AddItem(t, TablerIconType.CircleCheck);
                }
            });
        });
    }

    private static void RenderFindings(TablerColumn c2, IEnumerable<SectionProjectors.SimpleFinding>? findings)
    {
        if (findings == null)
        {
            return;
        }
        var rows = findings
            .Select(a => new { a.Severity, a.Target, a.Message })
            .ToList();
        if (rows.Count == 0)
        {
            return;
        }
        var t = (DataTablesTable)c2.Table(rows, TableType.DataTables);
        ConfigureStandardDataTable(t, defaultMode: ToggleViewMode.ScrollX);
        t.EnablePaging(10, new[] { 10, 25, 50 })
            .EnableSearching()
            .EnableOrdering()
            .HighlightWhen(
                where: g => g.And(c => c.StringContains("Severity", "error", false)),
                then: tt => { tt.Column("Severity").Danger(); tt.HighlightParent(true); })
            .HighlightWhen(
                where: g => g.And(c => c.StringContains("Severity", "warn", false)),
                then: tt => { tt.Column("Severity").Warning(); tt.HighlightParent(true); });
    }

    private static void RenderFindingsFromAssessments(TablerColumn c2, IEnumerable<Assessment>? assessments)
    {
        if (assessments == null)
        {
            return;
        }
        var list = assessments.Where(a => a != null && a.Severity != AssessmentSeverity.Info)
            .Select(a => new SectionProjectors.SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty))
            .ToList();
        RenderFindings(c2, list);
    }

    private static void RenderNarrative(TablerColumn c2, NarrativeSections? narrative)
    {
        RenderGuidanceWizardCard(c2, narrative, providerHelp: null, providerHelpTopics: null, references: null);
    }

    private static void RenderReferences(TablerColumn c2, IEnumerable<string>? references)
    {
        if (references == null)
        {
            return;
        }
        var list = references.Where(u => !string.IsNullOrWhiteSpace(u)).ToList();
        if (list.Count == 0)
        {
            return;
        }
        c2.Card(card =>
        {
            card.Header(h => h.Title("References").Icon(TablerIconType.Link));
            card.Body(body =>
            {
                body.Row(rr =>
                {
                    rr.Gap(2);
                    foreach (var u in list)
                    {
                        var f = LinkFormatter.Format(u);
                        rr.Column(
                            TablerColumnNumber.Auto,
                            cc => cc.Badge(
                                f.Title,
                                TablerBadgeColor.Blue,
                                TablerBadgeVisualStyle.Light,
                                TablerBadgeSize.Small,
                                pill: true,
                                href: f.Url));
                    }
                });
            });
        });
    }

    private static IEnumerable<string>? MergeReferences(IEnumerable<string>? first, IEnumerable<string>? second)
    {
        if (first == null && second == null)
        {
            return null;
        }
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var list = new List<string>();
        void AddRange(IEnumerable<string>? src)
        {
            if (src == null)
            {
                return;
            }
            foreach (var s in src)
            {
                if (string.IsNullOrWhiteSpace(s))
                {
                    continue;
                }
                if (set.Add(s)) list.Add(s);
            }
        }
        AddRange(first);
        AddRange(second);
        return list;
    }

    private static void RenderMailTlsServers(TablerColumn c2, string title, MailTlsInfo info)
    {
        var servers = info?.Servers;
        if (servers == null || servers.Count == 0)
        {
            return;
        }
        c2.Card(card =>
        {
            card.Header(h => h.Title($"{title} Servers").Icon(TablerIconType.LockCheck));
            card.Body(body =>
            {
                var rows = servers.Select(s => new
                {
                    Host = s.Key,
                    Status = info?.Status ?? "-",
                    StartTLS = s.StartTlsAdvertised ? "Yes" : "No",
                    Grade = s.Grade.ToString(),
                    Proto = s.Protocol,
                    TLS13 = s.Tls13Used ? "Yes" : (s.SupportsTls13 ? "Supported" : "No"),
                    Cert = s.CertificateValid ? "Valid" : "Invalid",
                    Chain = s.ChainValid ? "Valid" : "Invalid",
                    Expires = s.ValidTo.HasValue ? s.ValidTo.Value.ToString("yyyy-MM-dd") : "-",
                    DaysToExpire = s.DaysToExpire,
                    Cipher = string.IsNullOrWhiteSpace(s.CipherSuite) ? "-" : s.CipherSuite
                }).ToList();
                var tt = (DataTablesTable)body.Table(rows, TableType.DataTables);
                ConfigureStandardDataTable(tt, defaultMode: ToggleViewMode.ScrollX);
                tt.EnablePaging(10, new[] { 10, 25, 50 })
                  .EnableSearching()
                  .EnableOrdering();
            });
        });
    }

    private static void RenderProviderHelpBadges(TablerColumn c2, IReadOnlyList<ProviderHelpLinks>? help, IEnumerable<string>? topicFilter)
    {
        if (help == null || help.Count == 0)
        {
            return;
        }
        var filter = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (topicFilter != null)
        {
            foreach (var t in topicFilter)
            {
                if (!string.IsNullOrWhiteSpace(t))
                {
                    filter.Add(t);
                }
            }
        }
        bool any = false;
        foreach (var ph in help)
        {
            var topics = NormalizeProviderTopics(ph);
            if (filter.Count > 0) topics = topics.Where(t => filter.Contains(t.Topic)).ToList();
            if (topics.Count > 0)
            {
                any = true;
                break;
            }
        }
        if (!any)
        {
            return;
        }

        c2.Card(card =>
        {
            card.Header(h => h.Title("Provider Help").Icon(TablerIconType.Link));
            card.Body(body =>
            {
                foreach (var ph in help)
                {
                    if (ph == null)
                    {
                        continue;
                    }
                    var topics = NormalizeProviderTopics(ph);
                    if (filter.Count > 0) topics = topics.Where(t => filter.Contains(t.Topic)).ToList();
                    if (topics.Count == 0)
                    {
                        continue;
                    }
                    var ordered = topics.OrderBy(t => TopicOrderIndex(t.Topic)).ThenBy(t => t.Topic, StringComparer.OrdinalIgnoreCase).ToList();
                    body.Row(rr =>
                    {
                        rr.Gap(2);
                        if (!string.IsNullOrWhiteSpace(ph.ProviderName))
                        {
                            rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(ph.ProviderName, TablerBadgeColor.Secondary, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true));
                        }
                        foreach (var t in ordered)
                        {
                            var title = string.IsNullOrWhiteSpace(t.Title) ? t.Topic : t.Title;
                            rr.Column(TablerColumnNumber.Auto, cc => cc.Badge(title ?? t.Topic, TablerBadgeColor.Blue, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true, href: t.Url));
                            if (!t.IsPublic)
                            {
                                rr.Column(TablerColumnNumber.Auto, cc => cc.Badge("Login", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true));
                            }
                            if (t.IsThirdParty)
                            {
                                rr.Column(TablerColumnNumber.Auto, cc => cc.Badge("Third-party", TablerBadgeColor.Secondary, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true));
                            }
                            if (t.LastVerified.HasValue && t.LastVerified.Value != DateTime.MinValue)
                            {
                                rr.Column(TablerColumnNumber.Auto, cc => cc.Badge($"Verified {t.LastVerified.Value:yyyy-MM-dd}", TablerBadgeColor.Info, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true));
                            }
                        }
                    });
                }
                body.Text("Legend: Login = requires provider login; Third-party = non-vendor resource; Verified = last verified date.").Style(TablerTextStyle.Muted);
            });
        });
    }

    private static List<ProviderHelpTopic> NormalizeProviderTopics(ProviderHelpLinks ph)
    {
        var list = new List<ProviderHelpTopic>();
        if (ph?.Topics != null && ph.Topics.Count > 0)
        {
            list.AddRange(ph.Topics.Where(t => t != null));
        }
        if (list.Count == 0 && ph != null)
        {
            if (!string.IsNullOrWhiteSpace(ph.Dmarc)) list.Add(new ProviderHelpTopic { Topic = "DMARC", Url = ph.Dmarc, Title = $"{ph.ProviderName} - DMARC" });
            if (!string.IsNullOrWhiteSpace(ph.Spf)) list.Add(new ProviderHelpTopic { Topic = "SPF", Url = ph.Spf, Title = $"{ph.ProviderName} - SPF" });
            if (!string.IsNullOrWhiteSpace(ph.Dkim)) list.Add(new ProviderHelpTopic { Topic = "DKIM", Url = ph.Dkim, Title = $"{ph.ProviderName} - DKIM" });
            if (!string.IsNullOrWhiteSpace(ph.MtaSts)) list.Add(new ProviderHelpTopic { Topic = "MTA-STS", Url = ph.MtaSts, Title = $"{ph.ProviderName} - MTA-STS" });
            if (!string.IsNullOrWhiteSpace(ph.TlsRpt)) list.Add(new ProviderHelpTopic { Topic = "TLS-RPT", Url = ph.TlsRpt, Title = $"{ph.ProviderName} - TLS-RPT" });
            if (!string.IsNullOrWhiteSpace(ph.Deliverability)) list.Add(new ProviderHelpTopic { Topic = "Deliverability", Url = ph.Deliverability, Title = $"{ph.ProviderName} - Deliverability" });
        }
        return list.Where(t => !string.IsNullOrWhiteSpace(t.Url)).ToList();
    }

    private static int TopicOrderIndex(string topic)
    {
        if (string.IsNullOrWhiteSpace(topic)) return int.MaxValue;
        var key = topic.Trim().ToUpperInvariant();
        var idx = Array.IndexOf(ProviderTopicOrder, key);
        return idx >= 0 ? idx : int.MaxValue;
    }
}
