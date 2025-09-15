using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using OfficeIMO.Markdown;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Markdown;

/// <summary>
/// Markdown composition across mixed view items (SPF/DKIM/DMARC/MX/Classification...).
/// Mirrors Word layout at a high level and supports MarkdownHtml export.
/// </summary>
public static class MarkdownCompositionReport
{
    public static void Generate(
        string path,
        IReadOnlyList<object> items,
        ReportScope scope,
        OrderingOptions? ordering = null)
    {
        if (items == null || items.Count == 0) throw new ArgumentException("No items to compose.", nameof(items));

        var groups = CompositionBuilder.GroupBySubject(items);
        var domains = CompositionBuilder.OrderDomains(items, groups, ordering?.DomainOrder ?? DomainOrder.Alphabetical)
            .Select(kv => new KeyValuePair<string, DomainBucket>(kv.Key, Map(kv.Value)))
            .ToList();
        var title = CompositionBuilder.BuildSubjectTitle(domains.Select(x => x.Key).ToList());

        var rows = ExecutiveSummaryBuilder.Build(items, ordering?.DomainOrder ?? DomainOrder.Alphabetical);
        var overview = OverviewWording.ComposeFromItems(items);
        var md = BuildDoc(domains, title, rows, overview);
        var text = md.ToMarkdown();
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)) ?? ".");
        File.WriteAllText(path, text, Encoding.UTF8);
    }

    public static void GenerateMarkdownHtml(
        string htmlPath,
        IReadOnlyList<object> items,
        ReportScope scope,
        OrderingOptions? ordering = null)
    {
        if (items == null || items.Count == 0) throw new ArgumentException("No items to compose.", nameof(items));
        var groups = CompositionBuilder.GroupBySubject(items);
        var domains = CompositionBuilder.OrderDomains(items, groups, ordering?.DomainOrder ?? DomainOrder.Alphabetical)
            .Select(kv => new KeyValuePair<string, DomainBucket>(kv.Key, Map(kv.Value)))
            .ToList();
        var title = CompositionBuilder.BuildSubjectTitle(domains.Select(x => x.Key).ToList());

        var rows = ExecutiveSummaryBuilder.Build(items, ordering?.DomainOrder ?? DomainOrder.Alphabetical);
        var overview = OverviewWording.ComposeFromItems(items);
        var md = BuildDoc(domains, title, rows, overview);
        var mdPath = Path.ChangeExtension(htmlPath, ".md");
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(mdPath)) ?? ".");
        File.WriteAllText(mdPath, md.ToMarkdown(), Encoding.UTF8);

        var htmlOptions = new HtmlOptions {
            Kind = HtmlKind.Document,
            Style = HtmlStyle.GithubAuto,
            CssDelivery = CssDelivery.Inline,
            IncludeAnchorLinks = false,
            ShowAnchorIcons = true,
            AnchorIcon = "🔗",
            CopyHeadingLinkOnClick = true,
            BackToTopLinks = true,
            BackToTopMinLevel = 1,
            BackToTopText = "Back to top",
            ThemeToggle = true
        };
        md.SaveHtml(htmlPath, htmlOptions);
    }

    private static MarkdownDoc BuildDoc(List<KeyValuePair<string, DomainBucket>> domains, string title, List<ExecutiveSummaryBuilder.Row> rows, string overviewLine)
    {
        var md = MarkdownDoc.Create()
            .FrontMatter(new { title = $"Security Report — {title}", date = DateTimeOffset.Now.ToString("u") })
            .H1("Executive Summary")
            .Toc(opts => { opts.MinLevel = 1; opts.MaxLevel = 3; opts.IncludeTitle = false; opts.Collapsible = true; }, placeAtTop: true)
            .H2("Overview")
            .P(overviewLine)
            .H2("Legend")
            .Table(t => t.Headers("Status","Meaning")
                           .Row("🟢 OK","All checks passed or acceptable")
                           .Row("🟠 Warning","Requires attention; not blocking")
                           .Row("🔴 Error","Blocking or invalid configuration")
                           .AlignLeft(0,1))
            .H2("Domains");

        md.Table(t => t
            .Headers("Domain","MX","SPF","DKIM","DMARC","MTA-STS","TLS-RPT","DNSSEC","RPKI","Classification","Findings (W/E)")
            .Rows(rows.Select(r => (IReadOnlyList<string>)new []{ r.Domain, r.Mx, r.Spf, r.Dkim, r.Dmarc, r.Mtasts, r.TlsRpt, r.Dnssec, r.Rpki, r.Classification, $"{r.Warnings} / {r.Errors}" }))
            .AlignLeft(0).AlignCenter(1,2,3,4,5,6,7,8,9).AlignRight(10));

        // Provider chain + quick links (Word parity, condensed) — single source via ProviderChainBuilder
        md.H2("Mail Providers");
        foreach (var kv in domains)
        {
            var domain = kv.Key; var b = kv.Value;
            var chain = DomainDetective.Reports.ProviderChainBuilder.Build(b.Mx, b.Spf);
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(chain.Primary)) parts.Add($"Primary: {chain.Primary}");
            if (chain.Gateways.Count > 0) parts.Add($"Gateways: {string.Join(", ", chain.Gateways)}");
            if (chain.Outbound.Count > 0) parts.Add($"Outbound: {string.Join(", ", chain.Outbound)}");
            var line = parts.Count > 0 ? string.Join("; ", parts) : "(no provider detected)";

            // Append hints similar to Word (confidence, Single‑MX OK)
            try
            {
                var hints = DomainDetective.Reports.ProviderHintsBuilder.Build(b.Mx, chain.Primary);
                var hintParts = new List<string>();
                if (hints.ConfidencePercent > 0) hintParts.Add($"Confidence {hints.ConfidencePercent}%");
                if (hints.SingleMxOk) hintParts.Add("Single‑MX OK");
                var hintText = hintParts.Count > 0 ? $" — {string.Join(" · ", hintParts)}" : string.Empty;
                md.P(p => p.Bold(domain + ": ").Text(line + hintText));
            }
            catch { md.P(p => p.Bold(domain + ": ").Text(line)); }

            // Top provider links (DMARC/SPF/DKIM) for the primary provider if available
            try
            {
                var links = b.Mx?.ProviderHelp ?? b.Spf?.ProviderHelp;
                var primaryHelp = links?.FirstOrDefault(p => string.Equals(p?.ProviderName, chain.Primary, StringComparison.OrdinalIgnoreCase))
                                  ?? links?.FirstOrDefault();
                if (primaryHelp != null && (primaryHelp.Topics?.Count ?? 0) > 0)
                {
                    var top = primaryHelp.Topics.Where(t => !string.IsNullOrWhiteSpace(t?.Url)).Take(3).ToList();
                    if (top.Count > 0)
                    {
                        md.Ul(ul => {
                            foreach (var t in top)
                            {
                                var titleSafe = string.IsNullOrWhiteSpace(t?.Title) ? t!.Topic : t!.Title;
                                ul.ItemLink(titleSafe!, t!.Url!);
                            }
                        });
                    }
                }
            }
            catch { }
        }

        // Per-domain sections (compact, Word-like)
        foreach (var kv in domains)
        {
            var d = kv.Key; var b = kv.Value;
            md.H1(d).H2("Overview").Table(t => t.Headers("Key","Value")
                .Row("Domain", d)
                .Row("Classification", b.Classification?.Classification ?? "-")
                .Row("Confidence", b.Classification?.Confidence ?? "-")
                .Row("Status", ComputeStatus(b))
                .Row("Warnings", ((b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + b.Dkim.Sum(x => x.WarningCount)).ToString())
                .Row("Errors", ((b.Mx?.ErrorCount ?? 0) + (b.Spf?.ErrorCount ?? 0) + (b.Dmarc?.ErrorCount ?? 0) + (b.Mtasts?.ErrorCount ?? 0) + (b.TlsRpt?.ErrorCount ?? 0) + b.Dkim.Sum(x => x.ErrorCount)).ToString())
                .AlignLeft(0,1));

            if (b.Classification != null && b.Classification.ScoreBreakdown != null && b.Classification.ScoreBreakdown.Count > 0)
            {
                md.H2("Score Breakdown").Table(t => t.Headers("Metric","Value")
                    .Rows(b.Classification.ScoreBreakdown.Select(kv2 => (IReadOnlyList<string>)new[]{ kv2.Key, kv2.Value.ToString("0.##") }))
                    .AlignLeft(0).AlignRight(1));
            }

            if (b.Classification?.Recommendations?.Count > 0)
                md.H2("Recommendations").Ul(b.Classification.Recommendations.Select(r => r.Title ?? r.Code).ToArray());
            if (b.Classification?.Positives?.Count > 0)
                md.H2("Positives").Ul(b.Classification.Positives.Select(r => r.Title ?? r.Code).ToArray());
            if (b.Classification?.References?.Count > 0)
            {
                md.H2("References");
                md.Ul(ul => { foreach (var u in b.Classification.References) { var f = DomainDetective.Reports.LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } });
            }

            // Per‑section details (core parity with Word)
            // SPF (SectionProjectors)
            if (b.Spf != null)
            {
                var sec = DomainDetective.Reports.SectionProjectors.BuildSpf(b.Spf);
                md.H2("SPF");
                if (sec != null)
                {
                    md.Table(t => {
                        t.Headers("Key","Value");
                        foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value);
                        t.AlignLeft(0,1);
                    });
                    if (sec.Highlights.Count > 0) { md.H3("Highlights").Ul(sec.Highlights.ToArray()); }
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var spfFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (spfFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(spfFind).AlignLeft(0,1,2,3));
                    // Evidence
                    if (!string.IsNullOrWhiteSpace(sec.SpfRecord)) { md.H3("Evidence").P("SPF Record:"); md.Code("", sec.SpfRecord!); }
                    // Mechanisms
                    if (sec.Mechanisms.Count > 0) {
                        md.H3("Mechanisms");
                        var mechRows = sec.Mechanisms.Select(m => (IReadOnlyList<string>)new[]{ m.Qualifier, m.Type, m.Value, m.Provider }).ToList();
                        md.Table(t => t.Headers("Qualifier","Type","Value","Provider").Rows(mechRows).AlignLeft(0,1,2,3));
                    }
                    // Flattened IP Analysis
                    if (sec.FlattenedUniqueIpCount + sec.FlattenedDuplicateIpCount + sec.FlattenedTokenCount > 0) {
                        md.H3("Flattened IP Analysis");
                        md.Table(t => t.Headers("Metric","Value")
                            .Row("Unique IPs", sec.FlattenedUniqueIpCount.ToString())
                            .Row("Duplicate IPs", sec.FlattenedDuplicateIpCount.ToString())
                            .Row("Tokens Resolved", sec.FlattenedTokenCount.ToString())
                            .AlignLeft(0,1));
                    }
                    // Provider Help (SPF)
                    if (sec.ProviderHelp.Count > 0) { md.H3("Provider Help"); md.Ul(ul => { foreach (var (title, url) in sec.ProviderHelp.Take(5)) ul.ItemLink(title, url); }); }
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = DomainDetective.Reports.LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            // DMARC (SectionProjectors)
            if (b.Dmarc != null)
            {
                var sec = DomainDetective.Reports.SectionProjectors.BuildDmarc(b.Dmarc);
                md.H2("DMARC");
                if (sec != null)
                {
                    md.Table(t => {
                        t.Headers("Key","Value");
                        foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value);
                        t.AlignLeft(0,1);
                    });
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var dmFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (dmFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(dmFind).AlignLeft(0,1,2,3));
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = DomainDetective.Reports.LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            // DKIM (SectionProjectors)
            if (b.Dkim.Count > 0)
            {
                md.H2("DKIM");
                var sec = DomainDetective.Reports.SectionProjectors.BuildDkim(b.Dkim);
                if (sec != null)
                {
                    if (sec.Rows.Count > 0)
                    {
                        var dkimRows = sec.Rows.Select(x => (IReadOnlyList<string>)new[]{ x.Selector, x.Status, x.KeyBits, x.Hash }).ToList();
                        md.Table(t => t.Headers("Selector","Status","Key Bits","Alg").Rows(dkimRows).AlignLeft(0,1,2,3));
                    }
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var dkFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (dkFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(dkFind).AlignLeft(0,1,2,3));
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = DomainDetective.Reports.LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }
            // MX (SectionProjectors)
            if (b.Mx != null)
            {
                var sec = DomainDetective.Reports.SectionProjectors.BuildMx(b.Mx);
                md.H2("MX");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var mxFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (mxFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(mxFind).AlignLeft(0,1,2,3));
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = DomainDetective.Reports.LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            // MTA-STS (SectionProjectors)
            if (b.Mtasts != null)
            {
                var sec = DomainDetective.Reports.SectionProjectors.BuildMtasts(b.Mtasts);
                md.H2("MTA-STS");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    var mtFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (mtFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(mtFind).AlignLeft(0,1,2,3));
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = DomainDetective.Reports.LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            // TLS-RPT (SectionProjectors)
            if (b.TlsRpt != null)
            {
                var sec = DomainDetective.Reports.SectionProjectors.BuildTlsRpt(b.TlsRpt);
                md.H2("TLS-RPT");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    var trFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (trFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(trFind).AlignLeft(0,1,2,3));
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = DomainDetective.Reports.LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            // DNSBL (SectionProjectors)
            if (b.Dnsbl != null)
            {
                var sec = DomainDetective.Reports.SectionProjectors.BuildDnsbl(b.Dnsbl);
                md.H2("DNSBL");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (sec.Findings.Count > 0)
                    {
                        var dnsblRows = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                        md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(dnsblRows).AlignLeft(0,1,2,3));
                    }
                    // Evidence from original
                    var listed = b.Dnsbl.ListedRecords?.Select(r => (IReadOnlyList<string>)new[]{ r.SourceHost ?? r.IpAddress ?? "", r.BlackList ?? "", r.ReplyMeaning ?? "" }).ToList() ?? new List<IReadOnlyList<string>>();
                    if (listed.Count > 0) md.H3("Listed Records").Table(t => t.Headers("Host","Blacklist","Reason").Rows(listed).AlignLeft(0,1,2));
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = DomainDetective.Reports.LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            // NS (SectionProjectors)
            if (b.Ns != null)
            {
                var sec = DomainDetective.Reports.SectionProjectors.BuildNs(b.Ns);
                md.H2("NS");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var nsFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (nsFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(nsFind));
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = DomainDetective.Reports.LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            // SOA (SectionProjectors)
            if (b.Soa != null)
            {
                var sec = DomainDetective.Reports.SectionProjectors.BuildSoa(b.Soa);
                md.H2("SOA");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    var soaFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (soaFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(soaFind));
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = DomainDetective.Reports.LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            // CAA (SectionProjectors)
            if (b.Caa != null)
            {
                var sec = DomainDetective.Reports.SectionProjectors.BuildCaa(b.Caa);
                md.H2("CAA");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var caaFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (caaFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(caaFind));
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) ul.ItemLink(u, u); }); }
                }
            }

            // DNSSEC / DANE (SectionProjectors)
            if (b.Dnssec != null || b.Dane != null)
            {
                md.H2("DNSSEC/DANE");
                if (b.Dnssec != null)
                {
                    var dsec = DomainDetective.Reports.SectionProjectors.BuildDnssec(b.Dnssec);
                    if (dsec != null)
                    {
                        md.H3("DNSSEC");
                        md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in dsec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                        if (dsec.Positives.Count > 0) md.H4("Positives").Ul(dsec.Positives.ToArray());
                        var dnsFind = dsec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                        if (dnsFind.Count > 0) md.H4("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(dnsFind));
                    }
                }
                if (b.Dane != null)
                {
                    var dasec = DomainDetective.Reports.SectionProjectors.BuildDane(b.Dane);
                    if (dasec != null)
                    {
                        md.H3("DANE");
                        md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in dasec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                        var daFind = dasec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                        if (daFind.Count > 0) md.H4("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(daFind));
                    }
                }
            }

            // Mail TLS
            if (b.SmtpTls != null || b.ImapTls != null || b.PopTls != null)
            {
                md.H2("Mail TLS");
                void RenderTls(string label, DomainDetective.Views.MailTlsInfo info)
                {
                    if (info == null) return;
                    md.H3(label).Table(t => t.Headers("Key","Value")
                        .Row("Status", info.Status ?? "-")
                        .Row("Servers", (info.Servers?.Count ?? 0).ToString())
                        .AlignLeft(0,1));
                    var tlsFind = (info.Assessments ?? Array.Empty<DomainDetective.Assessment>()).Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info).Select(a => (IReadOnlyList<string>)new[]{ a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty }).ToList();
                    if (tlsFind.Count > 0) md.H4("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(tlsFind));
                }
                if (b.SmtpTls != null) RenderTls("SMTP", b.SmtpTls);
                if (b.ImapTls != null) RenderTls("IMAP", b.ImapTls);
                if (b.PopTls != null) RenderTls("POP3", b.PopTls);
            }

            // RPKI
            if (b.Rpki != null)
            {
                md.H2("RPKI").Table(t => t.Headers("Key","Value")
                    .Row("Status", b.Rpki.Status ?? "-")
                    .Row("Valid", b.Rpki.ValidCount.ToString())
                    .Row("Total Checked", b.Rpki.TotalChecked.ToString())
                    .AlignLeft(0,1));
            }

            // Zone Transfer
            if (b.ZoneTransfer != null)
            {
                md.H2("Zone Transfer").Table(t => t.Headers("Key","Value").Row("Open", $"{b.ZoneTransfer.OpenCount}/{b.ZoneTransfer.TotalChecked}").AlignLeft(0,1));
                var zRows = b.ZoneTransfer.ServerResults?.Select(kv2 => (IReadOnlyList<string>)new[]{ kv2.Key, kv2.Value ? "Yes" : "No" }).ToList() ?? new List<IReadOnlyList<string>>();
                if (zRows.Count > 0) md.Table(t => t.Headers("Server","Open").Rows(zRows));
            }

            // Wildcard DNS
            if (b.Wildcard != null)
            {
                md.H2("Wildcard DNS").Table(t => t.Headers("Key","Value").Row("Catch-All", b.Wildcard.CatchAll ? "Yes" : "No").AlignLeft(0,1));
            }
        }

        // All References parity with Word
        try
        {
            var comp = DomainDetective.Reports.CompositionBuilder.GroupBySubject(domains.Select(kv => (object)kv.Value).ToList());
            // The above GroupBySubject expects raw view items, not DomainBucket; so fall back to collecting from our DomainBucket list
            var refs = new List<string>();
            void Pull(IEnumerable<string>? urls) { if (urls == null) return; foreach (var u in urls) if (!string.IsNullOrWhiteSpace(u)) refs.Add(u); }
            foreach (var kv in domains)
            {
                var b = kv.Value;
                Pull(b.Spf?.References);
                foreach (var d in b.Dkim) Pull(d.References);
                Pull(b.Dmarc?.References);
                Pull(b.Mx?.References);
                Pull(b.Mtasts?.References);
                Pull(b.TlsRpt?.References);
                Pull(b.Dnsbl?.References);
                Pull(b.Rpki?.References);
                Pull(b.Ns?.References);
                Pull(b.Soa?.References);
                Pull(b.ZoneTransfer?.References);
                Pull(b.Wildcard?.References);
                Pull(b.Dnssec?.References);
                Pull(b.Dane?.References);
                Pull(b.Caa?.References);
                Pull(b.SmtpTls?.References);
                Pull(b.ImapTls?.References);
                Pull(b.PopTls?.References);
                Pull(b.Classification?.References);
            }
            var uniq = refs.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
            if (uniq.Count > 0)
            {
                md.H1("All References");
                md.Ul(ul => { foreach (var u in uniq) { var f = DomainDetective.Reports.LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } });
            }
        }
        catch { }

        return md;
    }

    // Adapter: map shared CompositionBuilder.DomainBucket into local Markdown DomainBucket type used below
    private static DomainBucket Map(CompositionBuilder.DomainBucket s)
    {
        var b = new DomainBucket
        {
            Subject = s.Subject,
            Mx = s.Mx,
            Spf = s.Spf,
            Dmarc = s.Dmarc,
            Dnsbl = s.Dnsbl,
            Classification = s.Classification,
            Mtasts = s.Mtasts,
            TlsRpt = s.TlsRpt,
            Ns = s.Ns,
            Soa = s.Soa,
            Caa = s.Caa,
            Dnssec = s.Dnssec,
            Dane = s.Dane,
            SmtpTls = s.SmtpTls,
            ImapTls = s.ImapTls,
            PopTls = s.PopTls,
            Rpki = s.Rpki,
            ZoneTransfer = s.ZoneTransfer,
            Wildcard = s.Wildcard
        };
        if (s.Dkim != null && s.Dkim.Count > 0) b.Dkim.AddRange(s.Dkim);
        return b;
    }

    private static string ComputeStatus(DomainBucket b)
    {
        var err = (b.Mx?.ErrorCount ?? 0) + (b.Spf?.ErrorCount ?? 0) + (b.Dmarc?.ErrorCount ?? 0) + (b.Mtasts?.ErrorCount ?? 0) + (b.TlsRpt?.ErrorCount ?? 0) + b.Dkim.Sum(x => x.ErrorCount);
        var warn = (b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + b.Dkim.Sum(x => x.WarningCount);
        return err > 0 ? "🔴 Error" : (warn > 0 ? "🟠 Warning" : "🟢 OK");
    }

    private static string BuildTitle(List<string> domains)
        => domains.Count switch { 0 => "Custom Composition", 1 => domains[0], 2 => $"{domains[0]}+{domains[1]}", _ => $"{domains[0]}+{domains[1]}(+{domains.Count - 2})" };

    private static List<KeyValuePair<string, DomainBucket>> OrderDomains(IReadOnlyList<object> items, Dictionary<string, DomainBucket> grouped, DomainOrder order)
    {
        if (order == DomainOrder.Alphabetical)
            return grouped.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase).ToList();
        var list = new List<KeyValuePair<string, DomainBucket>>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var it in items)
        {
            var s = TryGetSubject(it); if (string.IsNullOrWhiteSpace(s) || seen.Contains(s!)) continue;
            if (grouped.TryGetValue(s!, out var b)) { list.Add(new KeyValuePair<string, DomainBucket>(s!, b)); seen.Add(s!); }
        }
        foreach (var kv in grouped.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase)) if (!seen.Contains(kv.Key)) list.Add(new KeyValuePair<string, DomainBucket>(kv.Key, kv.Value));
        return list;
    }

    private static Dictionary<string, DomainBucket> GroupBySubject(IReadOnlyList<object> items)
    {
        var map = new Dictionary<string, DomainBucket>(StringComparer.OrdinalIgnoreCase);
        void Ensure(string s) { if (!map.ContainsKey(s)) map[s] = new DomainBucket { Subject = s }; }
        foreach (var it in items)
        {
            switch (it)
            {
                case DomainDetective.Views.MxInfo mx when !string.IsNullOrWhiteSpace(mx.Subject): Ensure(mx.Subject); map[mx.Subject].Mx = mx; break;
                case DomainDetective.Views.SpfRecordInfo spf when !string.IsNullOrWhiteSpace(spf.Subject): Ensure(spf.Subject); map[spf.Subject].Spf = spf; break;
                case DomainDetective.Views.DmarcRecordInfo dmarc when !string.IsNullOrWhiteSpace(dmarc.Subject): Ensure(dmarc.Subject); map[dmarc.Subject].Dmarc = dmarc; break;
                case DomainDetective.Views.DkimRecordInfo dkim when !string.IsNullOrWhiteSpace(dkim.Subject): Ensure(dkim.Subject); map[dkim.Subject].Dkim.Add(dkim); break;
                case DomainDetective.Views.MtastsInfo ms when !string.IsNullOrWhiteSpace(ms.Subject): Ensure(ms.Subject); map[ms.Subject].Mtasts = ms; break;
                case DomainDetective.Views.TlsRptInfo tr when !string.IsNullOrWhiteSpace(tr.Subject): Ensure(tr.Subject); map[tr.Subject].TlsRpt = tr; break;
                case DomainDetective.Views.MailClassificationInfo mc when !string.IsNullOrWhiteSpace(mc.Subject): Ensure(mc.Subject); map[mc.Subject].Classification = mc; break;
                case DomainDetective.Views.DnsblInfo db when !string.IsNullOrWhiteSpace(db.Subject): Ensure(db.Subject); map[db.Subject].Dnsbl = db; break;
                case DomainDetective.Views.NsInfo ns when !string.IsNullOrWhiteSpace(ns.Subject): Ensure(ns.Subject); map[ns.Subject].Ns = ns; break;
                case DomainDetective.Views.SoaInfo soa when !string.IsNullOrWhiteSpace(soa.Subject): Ensure(soa.Subject); map[soa.Subject].Soa = soa; break;
                case DomainDetective.Views.CaaInfo caa when !string.IsNullOrWhiteSpace(caa.Subject): Ensure(caa.Subject); map[caa.Subject].Caa = caa; break;
                case DomainDetective.Views.DnssecStatusInfo dn when !string.IsNullOrWhiteSpace(dn.Subject): Ensure(dn.Subject); map[dn.Subject].Dnssec = dn; break;
                case DomainDetective.Views.DaneRecordInfo da when !string.IsNullOrWhiteSpace(da.Subject): Ensure(da.Subject); map[da.Subject].Dane = da; break;
                case DomainDetective.Views.MailTlsInfo mt when !string.IsNullOrWhiteSpace(mt.Subject): Ensure(mt.Subject);
                    switch (mt.Check) {
                        case DomainDetective.HealthCheckType.SMTPTLS: map[mt.Subject].SmtpTls = mt; break;
                        case DomainDetective.HealthCheckType.IMAPTLS: map[mt.Subject].ImapTls = mt; break;
                        case DomainDetective.HealthCheckType.POP3TLS: map[mt.Subject].PopTls = mt; break;
                        default: break;
                    }
                    break;
                case DomainDetective.Views.RpkiInfo rp when !string.IsNullOrWhiteSpace(rp.Subject): Ensure(rp.Subject); map[rp.Subject].Rpki = rp; break;
                case DomainDetective.Views.ZoneTransferInfo zt when !string.IsNullOrWhiteSpace(zt.Subject): Ensure(zt.Subject); map[zt.Subject].ZoneTransfer = zt; break;
                case DomainDetective.Views.WildcardDnsInfo wc: Ensure(map.Keys.FirstOrDefault() ?? ""); /* subject may be null; attach to first */ break;
                default: break;
            }
        }
        return map;
    }

    private static string? TryGetSubject(object item)
    {
        try { var p = item.GetType().GetProperty("Subject"); return p?.GetValue(item) as string; } catch { return null; }
    }

    private sealed class DomainBucket
    {
        public string Subject { get; set; } = string.Empty;
        public DomainDetective.Views.MxInfo? Mx { get; set; }
        public DomainDetective.Views.SpfRecordInfo? Spf { get; set; }
        public DomainDetective.Views.DmarcRecordInfo? Dmarc { get; set; }
        public List<DomainDetective.Views.DkimRecordInfo> Dkim { get; } = new();
        public DomainDetective.Views.MtastsInfo? Mtasts { get; set; }
        public DomainDetective.Views.TlsRptInfo? TlsRpt { get; set; }
        public DomainDetective.Views.MailClassificationInfo? Classification { get; set; }
        public DomainDetective.Views.DnsblInfo? Dnsbl { get; set; }
        public DomainDetective.Views.NsInfo? Ns { get; set; }
        public DomainDetective.Views.SoaInfo? Soa { get; set; }
        public DomainDetective.Views.CaaInfo? Caa { get; set; }
        public DomainDetective.Views.DnssecStatusInfo? Dnssec { get; set; }
        public DomainDetective.Views.DaneRecordInfo? Dane { get; set; }
        public DomainDetective.Views.MailTlsInfo? SmtpTls { get; set; }
        public DomainDetective.Views.MailTlsInfo? ImapTls { get; set; }
        public DomainDetective.Views.MailTlsInfo? PopTls { get; set; }
        public DomainDetective.Views.RpkiInfo? Rpki { get; set; }
        public DomainDetective.Views.ZoneTransferInfo? ZoneTransfer { get; set; }
        public DomainDetective.Views.WildcardDnsInfo? Wildcard { get; set; }
    }
}
