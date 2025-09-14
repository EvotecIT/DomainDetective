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

        int totalWarn = 0, totalErr = 0;
        var summary = new List<(string Domain, string MX, string SPF, string DKIM, string DMARC, string MTASTS, string TLSRPT, string Classification, string Findings)>();
        foreach (var kv in domains)
        {
            var b = kv.Value;
            int warn = (b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + b.Dkim.Sum(x => x.WarningCount);
            int err  = (b.Mx?.ErrorCount ?? 0) + (b.Spf?.ErrorCount ?? 0) + (b.Dmarc?.ErrorCount ?? 0) + (b.Mtasts?.ErrorCount ?? 0) + (b.TlsRpt?.ErrorCount ?? 0) + b.Dkim.Sum(x => x.ErrorCount);
            totalWarn += warn; totalErr += err;
            string status(string? s) => string.IsNullOrWhiteSpace(s) ? "-" : s!;
            string dkimStatus = b.Dkim.Count > 0 ? (b.Dkim.Max(x => x.Status) ?? "-") : "-";
            summary.Add((kv.Key, status(b.Mx?.Status), status(b.Spf?.Status), dkimStatus, status(b.Dmarc?.Status), status(b.Mtasts?.Status), status(b.TlsRpt?.Status), status(b.Classification?.Classification), $"{warn} / {err}"));
        }

        var md = BuildDoc(domains, title);
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

        var md = BuildDoc(domains, title);
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

    private static MarkdownDoc BuildDoc(List<KeyValuePair<string, DomainBucket>> domains, string title)
    {
        int totalWarn = 0, totalErr = 0;
        var summary = new List<(string Domain, string MX, string SPF, string DKIM, string DMARC, string MTASTS, string TLSRPT, string Classification, string Findings)>();
        foreach (var kv in domains)
        {
            var b = kv.Value;
            int warn = (b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + b.Dkim.Sum(x => x.WarningCount);
            int err  = (b.Mx?.ErrorCount ?? 0) + (b.Spf?.ErrorCount ?? 0) + (b.Dmarc?.ErrorCount ?? 0) + (b.Mtasts?.ErrorCount ?? 0) + (b.TlsRpt?.ErrorCount ?? 0) + b.Dkim.Sum(x => x.ErrorCount);
            totalWarn += warn; totalErr += err;
            string status(string? s) => string.IsNullOrWhiteSpace(s) ? "-" : s!;
            string dkimStatus = b.Dkim.Count > 0 ? (b.Dkim.Max(x => x.Status) ?? "-") : "-";
            summary.Add((kv.Key, status(b.Mx?.Status), status(b.Spf?.Status), dkimStatus, status(b.Dmarc?.Status), status(b.Mtasts?.Status), status(b.TlsRpt?.Status), status(b.Classification?.Classification), $"{warn} / {err}"));
        }

        var md = MarkdownDoc.Create()
            .FrontMatter(new { title = $"Security Report — {title}", date = DateTimeOffset.Now.ToString("u") })
            .H1("Executive Summary")
            .Toc(opts => { opts.MinLevel = 1; opts.MaxLevel = 3; opts.IncludeTitle = false; opts.Collapsible = true; }, placeAtTop: true)
            .H2("Overview")
            .P(p => p.Text("This report summarizes email and DNS security signals for ")
                    .Bold(domains.Count.ToString()).Text(" domain(s). Totals: ").Underline($"{totalWarn} warning(s), {totalErr} error(s)").Text("."))
            .H2("Legend")
            .Table(t => t.Headers("Status","Meaning")
                           .Row("🟢 OK","All checks passed or acceptable")
                           .Row("🟠 Warning","Requires attention; not blocking")
                           .Row("🔴 Error","Blocking or invalid configuration")
                           .AlignLeft(0,1))
            .H2("Domains");

        md.Table(t => t
            .Headers("Domain","MX","SPF","DKIM","DMARC","MTA-STS","TLS-RPT","Classification","Findings (W/E)")
            .Rows(summary.Select(r => (IReadOnlyList<string>)new []{ r.Domain, r.MX, r.SPF, r.DKIM, r.DMARC, r.MTASTS, r.TLSRPT, r.Classification, r.Findings }))
            .AlignLeft(0).AlignCenter(1,2,3,4,5,6,7).AlignRight(8));

        // Provider chain + quick links (Word parity, condensed)
        md.H2("Mail Providers");
        foreach (var kv in domains)
        {
            var domain = kv.Key; var b = kv.Value;
            var primary = b.Mx?.ProviderPrimary ?? string.Empty;
            var gateways = b.Mx?.ProviderGateways ?? new List<string>();
            var outbound = new List<string>();
            try
            {
                var names = (b.Spf?.ProviderHelp ?? new List<DomainDetective.Views.ProviderHelpLinks>())
                    .Select(p => p?.ProviderName)
                    .Where(n => !string.IsNullOrWhiteSpace(n))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
                foreach (var n in names)
                {
                    if (string.IsNullOrWhiteSpace(n)) continue;
                    if (string.Equals(n, primary, StringComparison.OrdinalIgnoreCase)) continue;
                    if (gateways.Contains(n, StringComparer.OrdinalIgnoreCase)) continue;
                    outbound.Add(n);
                }
            }
            catch { }

            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(primary)) parts.Add($"Primary: {primary}");
            if (gateways.Count > 0) parts.Add($"Gateways: {string.Join(", ", gateways)}");
            if (outbound.Count > 0) parts.Add($"Outbound: {string.Join(", ", outbound)}");
            var line = parts.Count > 0 ? string.Join("; ", parts) : "(no provider detected)";

            md.P(p => p.Bold(domain + ": ").Text(line));

            // Top provider links (DMARC/SPF/DKIM) for the primary provider if available
            try
            {
                var links = b.Mx?.ProviderHelp ?? b.Spf?.ProviderHelp;
                var primaryHelp = links?.FirstOrDefault(p => string.Equals(p?.ProviderName, primary, StringComparison.OrdinalIgnoreCase))
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
                md.Ul(ul => { foreach (var u in b.Classification.References) ul.ItemLink(u, u); });
            }

            // Per‑section details (core parity with Word)
            // SPF
            if (b.Spf != null)
            {
                md.H2("SPF")
                  .Table(t => t.Headers("Key","Value")
                    .Row("Status", b.Spf.Status ?? "-")
                    .Row("DNS Lookups", b.Spf.DnsLookupsCount.ToString())
                    .Row("Record Present", b.Spf.SpfRecordExists ? "Yes" : "No")
                    .AlignLeft(0,1));
                if ((b.Spf.Recommendations?.Count ?? 0) > 0)
                    md.H3("Recommendations").Ul(b.Spf.Recommendations.Select(r => r.Title ?? r.Code).ToArray());
                if ((b.Spf.Positives?.Count ?? 0) > 0)
                    md.H3("Positives").Ul(b.Spf.Positives.Select(p => p.Title ?? p.Code).ToArray());
                var spfFind = (b.Spf.Assessments ?? Array.Empty<DomainDetective.Assessment>())
                                .Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info)
                                .Select(a => new[]{ a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty })
                                .ToList();
                if (spfFind.Count > 0)
                    md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(spfFind.Select(r => (IReadOnlyList<string>)r)).AlignLeft(0,1,2,3));
                if ((b.Spf.References?.Count ?? 0) > 0)
                { md.H3("References"); md.Ul(ul => { foreach (var u in b.Spf.References) ul.ItemLink(u, u); }); }
            }

            // DMARC
            if (b.Dmarc != null)
            {
                md.H2("DMARC")
                  .Table(t => t.Headers("Key","Value")
                    .Row("Status", b.Dmarc.Status ?? "-")
                    .Row("Policy", string.IsNullOrWhiteSpace(b.Dmarc.Policy) ? "-" : b.Dmarc.Policy)
                    .Row("rua", (b.Dmarc.MailtoRua?.Count ?? 0).ToString())
                    .Row("ruf", (b.Dmarc.MailtoRuf?.Count ?? 0).ToString())
                    .AlignLeft(0,1));
                if ((b.Dmarc.Recommendations?.Count ?? 0) > 0)
                    md.H3("Recommendations").Ul(b.Dmarc.Recommendations.Select(r => r.Title ?? r.Code).ToArray());
                if ((b.Dmarc.Positives?.Count ?? 0) > 0)
                    md.H3("Positives").Ul(b.Dmarc.Positives.Select(p => p.Title ?? p.Code).ToArray());
                var dmFind = (b.Dmarc.Assessments ?? Array.Empty<DomainDetective.Assessment>())
                                .Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info)
                                .Select(a => new[]{ a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty })
                                .ToList();
                if (dmFind.Count > 0)
                    md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(dmFind.Select(r => (IReadOnlyList<string>)r)).AlignLeft(0,1,2,3));
                if ((b.Dmarc.References?.Count ?? 0) > 0)
                { md.H3("References"); md.Ul(ul => { foreach (var u in b.Dmarc.References) ul.ItemLink(u, u); }); }
            }

            // DKIM
            if (b.Dkim.Count > 0)
            {
                md.H2("DKIM");
                var rows = b.Dkim.Select(k => (IReadOnlyList<string>)new [] {
                    k.Selector ?? string.Empty,
                    k.Status ?? "-",
                    k.PublicKeyExists ? k.KeyLength.ToString() : "-",
                    string.IsNullOrWhiteSpace(k.HashAlgorithm) ? "-" : k.HashAlgorithm
                }).ToList();
                md.Table(t => t.Headers("Selector","Status","KeyBits","Hash").Rows(rows).AlignLeft(0,1).AlignRight(2).AlignLeft(3));
                var dkPos = b.Dkim.SelectMany(x => x.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()).Select(p => p?.Title).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s!).Distinct().ToArray();
                if (dkPos.Length > 0) md.H3("Positives").Ul(dkPos);
                var dkFind = b.Dkim.SelectMany(x => x.Assessments ?? Array.Empty<DomainDetective.Assessment>()).Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info).Select(a => (IReadOnlyList<string>)new[]{ a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty }).ToList();
                if (dkFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(dkFind).AlignLeft(0,1,2,3));
                var dkRefs = b.Dkim.SelectMany(x => x.References ?? Array.Empty<string>()).Where(s => !string.IsNullOrWhiteSpace(s)).Distinct().ToArray();
                if (dkRefs.Length > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in dkRefs) ul.ItemLink(u, u); }); }
            }

            // MX
            if (b.Mx != null)
            {
                md.H2("MX")
                  .Table(t => t.Headers("Key","Value")
                    .Row("Status", b.Mx.Status ?? "-")
                    .Row("MX Records", (b.Mx.MxRecords?.Count ?? 0).ToString())
                    .Row("Backup Servers", b.Mx.HasBackupServers ? "Yes" : "No")
                    .Row("IPv6 Supported", b.Mx.Ipv6Supported ? "Yes" : "No")
                    .Row("Priorities In Order", b.Mx.PrioritiesInOrder ? "Yes" : "No")
                    .AlignLeft(0,1));
                if ((b.Mx.Recommendations?.Count ?? 0) > 0)
                    md.H3("Recommendations").Ul(b.Mx.Recommendations.Select(r => r.Title ?? r.Code).ToArray());
                if ((b.Mx.Positives?.Count ?? 0) > 0)
                    md.H3("Positives").Ul(b.Mx.Positives.Select(p => p.Title ?? p.Code).ToArray());
                var mxFind = (b.Mx.Assessments ?? Array.Empty<DomainDetective.Assessment>())
                                .Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info)
                                .Select(a => (IReadOnlyList<string>)new[]{ a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty }).ToList();
                if (mxFind.Count > 0)
                    md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(mxFind).AlignLeft(0,1,2,3));
                if ((b.Mx.References?.Count ?? 0) > 0)
                { md.H3("References"); md.Ul(ul => { foreach (var u in b.Mx.References) ul.ItemLink(u, u); }); }
            }

            // MTA-STS
            if (b.Mtasts != null)
            {
                md.H2("MTA-STS").Table(t => t.Headers("Key","Value")
                    .Row("Status", b.Mtasts.Status ?? "-")
                    .Row("Mode", b.Mtasts.Mode ?? "-")
                    .Row("DNS TXT", b.Mtasts.DnsRecordPresent ? (b.Mtasts.DnsRecordValid?"Present (valid)":"Present (invalid)") : "Missing")
                    .Row("Policy", b.Mtasts.PolicyPresent ? (b.Mtasts.PolicyValid?"Present (valid)":"Present (invalid)") : "Missing")
                    .AlignLeft(0,1));
                var mtFind = (b.Mtasts.Assessments ?? Array.Empty<DomainDetective.Assessment>())
                    .Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info)
                    .Select(a => (IReadOnlyList<string>)new[]{ a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty }).ToList();
                if (mtFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(mtFind).AlignLeft(0,1,2,3));
                if ((b.Mtasts.References?.Count ?? 0) > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in b.Mtasts.References) ul.ItemLink(u, u); }); }
            }

            // TLS-RPT
            if (b.TlsRpt != null)
            {
                md.H2("TLS-RPT").Table(t => t.Headers("Key","Value")
                    .Row("Status", b.TlsRpt.Status ?? "-")
                    .Row("Record Exists", b.TlsRpt.TlsRptRecordExists ? "Yes" : "No")
                    .AlignLeft(0,1));
                var trFind = (b.TlsRpt.Assessments ?? Array.Empty<DomainDetective.Assessment>())
                    .Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info)
                    .Select(a => (IReadOnlyList<string>)new[]{ a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty }).ToList();
                if (trFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(trFind).AlignLeft(0,1,2,3));
                if ((b.TlsRpt.References?.Count ?? 0) > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in b.TlsRpt.References) ul.ItemLink(u, u); }); }
            }

            // DNSBL
            if (b.Dnsbl != null)
            {
                md.H2("DNSBL").Table(t => t.Headers("Key","Value")
                    .Row("Status", b.Dnsbl.Status ?? "-")
                    .Row("Providers Checked", b.Dnsbl.ProvidersChecked.ToString())
                    .Row("Hosts Listed", b.Dnsbl.HostsListed.ToString())
                    .AlignLeft(0,1));
                var listed = b.Dnsbl.ListedRecords?.Select(r => (IReadOnlyList<string>)new[]{ r.SourceHost ?? r.IpAddress ?? "", r.BlackList ?? "", r.ReplyMeaning ?? "" }).ToList() ?? new List<IReadOnlyList<string>>();
                if (listed.Count > 0) md.H3("Listed Records").Table(t => t.Headers("Host","Blacklist","Reason").Rows(listed).AlignLeft(0,1,2));
            }

            // NS
            if (b.Ns != null)
            {
                md.H2("NS").Table(t => t.Headers("Key","Value")
                    .Row("Status", b.Ns.Status ?? "-")
                    .Row("At Least Two", b.Ns.AtLeastTwoRecords ? "Yes" : "No")
                    .Row("All Have A/AAAA", b.Ns.AllHaveAOrAaaa ? "Yes" : "No")
                    .Row("Glue Complete", b.Ns.GlueRecordsComplete ? "Yes" : "No")
                    .Row("Glue Consistent", b.Ns.GlueRecordsConsistent ? "Yes" : "No")
                    .Row("Delegation Matches", b.Ns.DelegationMatches ? "Yes" : "No")
                    .Row("Distinct ASNs", b.Ns.AsnDistinctCount.ToString())
                    .AlignLeft(0,1));
                if ((b.Ns.Recommendations?.Count ?? 0) > 0) md.H3("Recommendations").Ul(b.Ns.Recommendations.Select(r => r.Title ?? r.Code).ToArray());
                if ((b.Ns.Positives?.Count ?? 0) > 0) md.H3("Positives").Ul(b.Ns.Positives.Select(p => p.Title ?? p.Code).ToArray());
                var nsFind = (b.Ns.Assessments ?? Array.Empty<DomainDetective.Assessment>()).Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info).Select(a => (IReadOnlyList<string>)new[]{ a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty }).ToList();
                if (nsFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(nsFind));
            }

            // SOA
            if (b.Soa != null)
            {
                md.H2("SOA").Table(t => t.Headers("Key","Value")
                    .Row("Primary NS", b.Soa.PrimaryNameServer ?? "")
                    .Row("Responsible", b.Soa.ResponsibleMailbox ?? "")
                    .Row("Serial", b.Soa.SerialNumber.ToString())
                    .Row("Serial Format", b.Soa.SerialFormatValid ? "Valid" : "Check")
                    .AlignLeft(0,1));
            }

            // CAA
            if (b.Caa != null)
            {
                md.H2("CAA").Table(t => t.Headers("Key","Value")
                    .Row("Valid Records", b.Caa.ValidRecords.ToString())
                    .Row("Invalid Records", b.Caa.InvalidRecords.ToString())
                    .Row("Conflicting", b.Caa.Conflicting ? "Yes" : "No")
                    .AlignLeft(0,1));
                if ((b.Caa.Recommendations?.Count ?? 0) > 0) md.H3("Recommendations").Ul(b.Caa.Recommendations.Select(r => r.Title ?? r.Code).ToArray());
                if ((b.Caa.Positives?.Count ?? 0) > 0) md.H3("Positives").Ul(b.Caa.Positives.Select(p => p.Title ?? p.Code).ToArray());
            }

            // DNSSEC / DANE
            if (b.Dnssec != null || b.Dane != null)
            {
                md.H2("DNSSEC/DANE");
                if (b.Dnssec != null)
                {
                    md.H3("DNSSEC").Table(t => t.Headers("Key","Value").Row("Status", b.Dnssec.Status ?? "-").Row("Chain", b.Dnssec.ChainValid ? "Valid" : "Invalid").AlignLeft(0,1));
                    var dnssecPos = (b.Dnssec.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()).Select(p => p?.Title).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s!).ToArray();
                    if (dnssecPos.Length > 0) md.H4("Positives").Ul(dnssecPos);
                    var dnsFind = (b.Dnssec.Assessments ?? Array.Empty<DomainDetective.Assessment>()).Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info).Select(a => (IReadOnlyList<string>)new[]{ a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty }).ToList();
                    if (dnsFind.Count > 0) md.H4("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(dnsFind));
                }
                if (b.Dane != null)
                {
                    md.H3("DANE").Table(t => t.Headers("Key","Value").Row("Status", b.Dane.Status ?? "-").Row("Records", b.Dane.NumberOfRecords.ToString()).AlignLeft(0,1));
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
