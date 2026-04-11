using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using OfficeIMO.Markdown;

namespace DomainDetective.Reports.Markdown;

/// <summary>
/// Markdown composition across mixed view items (SPF/DKIM/DMARC/MX/Classification...).
/// Mirrors Word layout at a high level and supports MarkdownHtml export.
/// </summary>
public static partial class MarkdownCompositionReport
{
    /// <summary>
    /// Generates a composed Markdown report for the supplied report items.
    /// </summary>
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
        var inputSectionOrder = SectionOrdering.DetermineSectionOrderByDomain(items);
        var md = BuildDoc(domains, title, rows, overview, ordering, inputSectionOrder);
        var text = md.ToMarkdown();
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)) ?? ".");
        File.WriteAllText(path, text, Encoding.UTF8);
    }

    /// <summary>
    /// Generates a composed Markdown report and saves an HTML rendering beside it.
    /// </summary>
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
        var inputSectionOrder = SectionOrdering.DetermineSectionOrderByDomain(items);
        var md = BuildDoc(domains, title, rows, overview, ordering, inputSectionOrder);
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

    private static MarkdownDoc BuildDoc(List<KeyValuePair<string, DomainBucket>> domains, string title, List<ExecutiveSummaryBuilder.Row> rows, string overviewLine, OrderingOptions? ordering, Dictionary<string, List<string>> inputSectionOrder)
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
            .Headers("Domain","MX","SPF","DKIM","DMARC","MTA-STS","TLS-RPT","DNSSEC","RPKI","M365","M365 Workloads","Classification","Findings (W/E)")
            .Rows(rows.Select(r => (IReadOnlyList<string>)new []{ r.Domain, r.Mx, r.Spf, r.Dkim, r.Dmarc, r.Mtasts, r.TlsRpt, r.Dnssec, r.Rpki, r.Microsoft365, r.Microsoft365Workloads, r.Classification, $"{r.Warnings} / {r.Errors}" }))
            .AlignLeft(0).AlignCenter(1,2,3,4,5,6,7,8,9,10).AlignLeft(11).AlignRight(12));

        // Provider chain + quick links (Word parity, condensed)
        md.H2("Mail Providers");
        // Legend for provider hints (parity with Word/HTML)
        md.P("Legend: Confidence = detection certainty; Single‑MX OK = vendor supports single MX; Gateway = inbound security gateway; Outbound = separate sender platform.");
        foreach (var kv in domains)
        {
            var domain = kv.Key; var b = kv.Value;
            var chain = DomainDetective.Reports.ProviderChainBuilder.Build(b.Mx, b.Spf);
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(chain.Primary)) parts.Add($"Primary: {chain.Primary}");
            if (chain.Gateways.Count > 0) parts.Add($"Gateways: {string.Join(", ", chain.Gateways)}");
            if (chain.Outbound.Count > 0) parts.Add($"Outbound: {string.Join(", ", chain.Outbound)}");
            var line = parts.Count == 0 ? "Unknown" : string.Join(" · ", parts);
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
            try
            {
                var links = b.Mx?.ProviderHelp ?? b.Spf?.ProviderHelp;
                var primaryHelp = links?.FirstOrDefault(p => string.Equals(p?.ProviderName, chain.Primary, StringComparison.OrdinalIgnoreCase))
                                  ?? links?.FirstOrDefault();
                var topics = primaryHelp?.Topics;
                if (topics != null && topics.Count > 0)
                {
                    var top = topics.Where(t => !string.IsNullOrWhiteSpace(t?.Url)).Take(3).ToList();
                    if (top.Count > 0)
                    {
                        md.Ul(ul => { foreach (var t in top) { var titleSafe = string.IsNullOrWhiteSpace(t?.Title) ? t!.Topic : t!.Title; ul.ItemLink(titleSafe!, t!.Url!); } });
                    }
                }
            }
            catch { }
        }

        // Per-domain content (implemented in partial file)
        WritePerDomain(md, domains, ordering, inputSectionOrder);

        // All References parity with Word
        try
        {
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
                Pull(b.Microsoft365?.References);
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
            Wildcard = s.Wildcard,
            Ttl = s.Ttl,
            DesiredState = s.DesiredState,
            Microsoft365 = s.Microsoft365,
            Typosquatting = s.Typosquatting
        };
        if (s.Dkim != null && s.Dkim.Count > 0) b.Dkim.AddRange(s.Dkim);
        return b;
    }

    private static string ComputeStatus(DomainBucket b)
    {
        var err = (b.Mx?.ErrorCount ?? 0) + (b.Spf?.ErrorCount ?? 0) + (b.Dmarc?.ErrorCount ?? 0) + (b.Mtasts?.ErrorCount ?? 0) + (b.TlsRpt?.ErrorCount ?? 0) + (b.Microsoft365?.ErrorCount ?? 0) + (b.Typosquatting?.ErrorCount ?? 0) + b.Dkim.Sum(x => x.ErrorCount);
        var warn = (b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + (b.Microsoft365?.WarningCount ?? 0) + (b.Typosquatting?.WarningCount ?? 0) + b.Dkim.Sum(x => x.WarningCount);
        return err > 0 ? "🔴 Error" : (warn > 0 ? "🟠 Warning" : "🟢 OK");
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
        public DomainDetective.Views.TtlInfo? Ttl { get; set; }
        public DomainDetective.Views.DesiredStateInfo? DesiredState { get; set; }
        public DomainDetective.Views.Microsoft365TenantInfo? Microsoft365 { get; set; }
        public DomainDetective.Views.TyposquattingInfo? Typosquatting { get; set; }
    }
}
