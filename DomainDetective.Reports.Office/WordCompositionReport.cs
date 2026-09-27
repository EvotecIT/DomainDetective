using System;
using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Word;
using DocumentFormat.OpenXml.Wordprocessing;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Aggregates mixed view objects (SPF/DKIM/DMARC) for one or more domains into a single Word document.
/// </summary>
/// <summary>
/// Builds a single Word document from mixed per-section view objects across one or many domains.
/// </summary>
public static partial class WordCompositionReport {
    /// <summary>
    /// Generates a composed Word report.
    /// </summary>
    /// <param name="path">Output file path.</param>
    /// <param name="items">View objects (SPF/DKIM/DMARC/DNSBL/MailClassification).</param>
    /// <param name="scope">Detail level for sections.</param>
    /// <param name="showInfoFindings">Include Info-level findings in tables.</param>
    /// <param name="narrativePlacement">Where to render background narrative (global or per-domain).</param>
    /// <param name="titleOverride">Optional title override.</param>
    /// <param name="subjectOverride">Optional subject override for document properties.</param>
    /// <param name="categoryOverride">Optional category override for document properties.</param>
    /// <param name="keywordsOverride">Optional keywords override for document properties.</param>
    /// <param name="creatorOverride">Optional creator/author override for document properties.</param>
    /// <param name="companyName">Branding property.</param>
    /// <param name="companyAddress">Branding property.</param>
    /// <param name="companyYear">Branding property.</param>
    /// <param name="logoPath">Header logo.</param>
    /// <param name="headerText">Header left text.</param>
    /// <param name="footerText">Footer left text.</param>
    /// <param name="watermarkText">Watermark text.</param>
    /// <param name="showDkimSelectorCountInSummary">Show DKIM selector count next to DKIM status in executive summary.</param>
    /// <param name="showMailTlsProtocolHintInSummary">Show protocol hint (SMTP/IMAP/POP) for Mail TLS in summary.</param>
    /// <param name="summaryColumnCap">Optional cap for the number of status columns in the executive summary table.</param>
    /// <param name="headerLogoSizePx">Header logo height in pixels.</param>
    /// <param name="footerLogoSizePx">Footer logo height in pixels.</param>
    /// <param name="providerHelp">Provider reference rendering options for sections.</param>
    /// <param name="domainOrder">How to order domains in the output (Alphabetical or Input).</param>
    /// <param name="sectionOrderMode">How to order sections within a domain (Canonical, Input, or Custom).</param>
    /// <param name="sectionOrder">Explicit section order used when <paramref name="sectionOrderMode"/> is Custom.</param>
    public static void Generate(
        string path,
        IReadOnlyList<object> items,
        ReportScope scope,
        bool showInfoFindings,
        NarrativePlacement narrativePlacement = NarrativePlacement.Auto,
        string? titleOverride = null,
        string? subjectOverride = null,
        string? categoryOverride = null,
        string? keywordsOverride = null,
        string? creatorOverride = null,
        string? companyName = null,
        string? companyAddress = null,
        string? companyYear = null,
        string? logoPath = null,
        string? headerText = null,
        string? footerText = null,
        string? watermarkText = null,
        bool showDkimSelectorCountInSummary = true,
        bool showMailTlsProtocolHintInSummary = true,
        ProviderHelpRenderOptions? providerHelp = null,
        DomainDetective.Reports.DomainOrder domainOrder = DomainDetective.Reports.DomainOrder.Alphabetical,
        DomainDetective.Reports.SectionOrderMode sectionOrderMode = DomainDetective.Reports.SectionOrderMode.Canonical,
        string[]? sectionOrder = null,
        int? summaryColumnCap = null,
        int? headerLogoSizePx = null,
        int? footerLogoSizePx = null) {
        if (items == null || items.Count == 0) throw new ArgumentException("No items to compose.", nameof(items));

        // Group items by domain/subject
        var grouped = GroupBySubject(items);
        bool multiDomain = grouped.Count > 1;
        bool placeGlobal = narrativePlacement == NarrativePlacement.Global || (narrativePlacement == NarrativePlacement.Auto && multiDomain);
        bool includeNarrativePerDomain = narrativePlacement == NarrativePlacement.PerDomain || (narrativePlacement == NarrativePlacement.Auto && !multiDomain);
        bool includeMechanismMeaningsPerDomain = includeNarrativePerDomain; // meanings go with narratives when per-domain
        var subjectTitle = BuildSubjectTitle(grouped.Keys.ToList());
        var title = string.IsNullOrWhiteSpace(titleOverride)
            ? $"Security Report — {subjectTitle}"
            : titleOverride!;

        using var doc = WordDocument.Create(path);
        doc.Settings.UpdateFieldsOnOpen = true;
        var generatedAt = DateTime.Now;

        // Built-in and custom properties
        var subj = string.IsNullOrWhiteSpace(subjectOverride) ? "Custom Composition" : subjectOverride;
        var keys = string.IsNullOrWhiteSpace(keywordsOverride) ? "Email Security" : keywordsOverride;
        var cat = string.IsNullOrWhiteSpace(categoryOverride) ? "Security" : categoryOverride;
        var creator = string.IsNullOrWhiteSpace(creatorOverride) ? "DomainDetective" : creatorOverride;
        WordReportCommon.ApplyBuiltInProperties(doc, title, subj, keys, cat, creator);
        WordReportCommon.ApplyCompanyBranding(doc, companyName, companyAddress, companyYear);

        // A concise front page opens cleanly in Word and PDF, even when no company
        // branding was supplied. The canned cover/TOC carried unresolved placeholders.
        doc.AddParagraph(title).SetBold().SetFontSize(24);
        doc.AddParagraph($"{grouped.Count} domain(s) · Generated {generatedAt:yyyy-MM-dd HH:mm}").SetFontSize(11);
        WordReportCommon.AddHeader(doc, WordReportCommon.ResolveHeaderLeftText(headerText, new { Title = title }, title),
            $"Generated: {generatedAt:yyyy-MM-dd HH:mm:ss}", logoPath, watermarkText, headerLogoSizePx);
        WordReportCommon.AddFooter(doc, footerText, null, logoPath, footerLogoSizePx);

        var headings = doc.AddTableOfContentList(WordListStyle.Headings111);
        headings.AddItem("Executive Summary");
        headings.AddItem("Overview", 1);
        // Determine which sections are actually present in the composed items
        // so Executive Summary reflects what the user requested.
        bool hasMx = grouped.Values.Any(b => b.Mx != null);
        bool hasSpf = grouped.Values.Any(b => b.Spf != null);
        bool hasDkim = grouped.Values.Any(b => b.Dkim != null && b.Dkim.Count > 0);
        bool hasDmarc = grouped.Values.Any(b => b.Dmarc != null);
        bool hasArc = grouped.Values.Any(b => b.Arc != null);
        bool hasBimi = grouped.Values.Any(b => b.Bimi != null);
        bool hasMtasts = grouped.Values.Any(b => b.Mtasts != null);
        bool hasTlsRpt = grouped.Values.Any(b => b.TlsRpt != null);
        bool hasDnsbl = grouped.Values.Any(b => b.Dnsbl != null);
        bool hasRpki = grouped.Values.Any(b => b.Rpki != null);
        bool hasNs = grouped.Values.Any(b => b.Ns != null);
        bool hasSoa = grouped.Values.Any(b => b.Soa != null);
        bool hasZone = grouped.Values.Any(b => b.ZoneTransfer != null);
        bool hasWildcard = grouped.Values.Any(b => b.Wildcard != null);
        bool hasCaa = grouped.Values.Any(b => b.Caa != null);
        bool hasClass = grouped.Values.Any(b => b.Classification != null);
        bool hasMailTls = grouped.Values.Any(b => b.SmtpTls != null || b.ImapTls != null || b.PopTls != null);
        bool hasDnssec = grouped.Values.Any(b => b.Dnssec != null);
        bool hasDane = grouped.Values.Any(b => b.Dane != null);
        bool hasDnsAmplification = grouped.Values.Any(b => b.DnsAmplification != null);
        bool hasDnsOverTls = grouped.Values.Any(b => b.DnsOverTls != null);
        bool hasMicrosoft365 = grouped.Values.Any(b => b.Microsoft365 != null);
        bool hasTyposquatting = grouped.Values.Any(b => b.Typosquatting != null);

        var presentLabels = new List<string>();
        if (hasMx) presentLabels.Add("MX");
        if (hasSpf) presentLabels.Add("SPF");
        if (hasDkim) presentLabels.Add("DKIM");
        if (hasDmarc) presentLabels.Add("DMARC");
        if (hasArc) presentLabels.Add("ARC");
        if (hasBimi) presentLabels.Add("BIMI");
        if (hasMtasts) presentLabels.Add("MTA-STS");
        if (hasTlsRpt) presentLabels.Add("TLS-RPT");
        if (hasDnsbl) presentLabels.Add("DNSBL");
        if (hasRpki) presentLabels.Add("RPKI");
        if (hasMailTls) presentLabels.Add("MAILTLS");
        if (hasClass) presentLabels.Add("Classification");
        if (hasDnssec) presentLabels.Add("DNSSEC");
        if (hasDane) presentLabels.Add("DANE");
        if (hasNs) presentLabels.Add("NS");
        if (hasSoa) presentLabels.Add("SOA");
        if (hasZone) presentLabels.Add("ZoneXFR");
        if (hasWildcard) presentLabels.Add("Wildcard");
        if (hasCaa) presentLabels.Add("CAA");
        if (hasDnsAmplification) presentLabels.Add("DNS Amplification");
        if (hasDnsOverTls) presentLabels.Add("DNS over TLS");
        if (hasMicrosoft365) presentLabels.Add("Microsoft 365");
        if (hasTyposquatting) presentLabels.Add("Typosquatting");

        // Executive Summary intro text — single source of truth for wording
        string overviewLine = OverviewWording.ComposeFromItems(items);
        doc.AddParagraph(overviewLine);

        // Executive Summary table (defensive build to avoid style-dependent index issues)
        List<KeyValuePair<string, DomainBucket>> allRows;
        if (domainOrder == DomainOrder.Input) {
            var inputOrder = DetermineDomainOrder(items);
            var tmp = new List<KeyValuePair<string, DomainBucket>>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var d in inputOrder) {
                if (grouped.TryGetValue(d, out var b)) { tmp.Add(new KeyValuePair<string, DomainBucket>(d, b)); seen.Add(d); }
            }
            foreach (var kv in grouped.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase)) if (!seen.Contains(kv.Key)) tmp.Add(new KeyValuePair<string, DomainBucket>(kv.Key, kv.Value));
            allRows = tmp;
        } else {
            allRows = grouped.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase).ToList();
        }
        try {
            // Build dynamic header list and writers; cap content columns to keep layout tidy in Word.
            // Max total columns ≈ 6 (including Domain + Findings) → content columns cap = 4 by default.
            int contentColumnCap = summaryColumnCap.HasValue ? Math.Max(1, summaryColumnCap.Value) : 4;
            var candidates = new List<(string Header, Action<WordTableCell, DomainBucket> WriteCell, Func<DomainBucket, int>? Warns, Func<DomainBucket, int>? Errs, int Priority)>();
            if (hasSpf) candidates.Add(("SPF", (cell, b) => cell.AddParagraph(b.Spf?.Status ?? "-"), b => b.Spf?.WarningCount ?? 0, b => b.Spf?.ErrorCount ?? 0, 10));
            if (hasDkim) candidates.Add(("DKIM", (cell, b) => cell.AddParagraph(ComposeDkimStatus(b.Dkim, showDkimSelectorCountInSummary)), b => b.Dkim?.Sum(x => x.WarningCount) ?? 0, b => b.Dkim?.Sum(x => x.ErrorCount) ?? 0, 9));
            if (hasDmarc) candidates.Add(("DMARC", (cell, b) => cell.AddParagraph(b.Dmarc?.Status ?? "-"), b => b.Dmarc?.WarningCount ?? 0, b => b.Dmarc?.ErrorCount ?? 0, 8));
            if (hasArc) candidates.Add(("ARC", (cell, b) => cell.AddParagraph(b.Arc?.Status ?? "-"), b => b.Arc?.WarningCount ?? 0, b => b.Arc?.ErrorCount ?? 0, 8));
            if (hasMx) candidates.Add(("MX", (cell, b) => cell.AddParagraph(b.Mx?.Status ?? "-"), b => b.Mx?.WarningCount ?? 0, b => b.Mx?.ErrorCount ?? 0, 7));
            if (hasDnsbl) candidates.Add(("DNSBL", (cell, b) => cell.AddParagraph(b.Dnsbl?.Status ?? "-"), b => b.Dnsbl?.WarningCount ?? 0, b => b.Dnsbl?.ErrorCount ?? 0, 6));
            if (hasNs) candidates.Add(("NS", (cell, b) => cell.AddParagraph(b.Ns?.Status ?? "-"), b => b.Ns?.WarningCount ?? 0, b => b.Ns?.ErrorCount ?? 0, 6));
            if (hasSoa) candidates.Add(("SOA", (cell, b) => cell.AddParagraph(b.Soa?.Status ?? "-"), b => b.Soa?.WarningCount ?? 0, b => b.Soa?.ErrorCount ?? 0, 5));
            if (hasZone) candidates.Add(("ZoneXFR", (cell, b) => cell.AddParagraph(b.ZoneTransfer?.Status ?? "-"), b => b.ZoneTransfer?.WarningCount ?? 0, b => b.ZoneTransfer?.ErrorCount ?? 0, 5));
            if (hasWildcard) candidates.Add(("Wildcard", (cell, b) => cell.AddParagraph(b.Wildcard?.Status ?? "-"), b => b.Wildcard?.WarningCount ?? 0, b => b.Wildcard?.ErrorCount ?? 0, 4));
            // CAA tile added below with static mapping
            if (hasDnssec) candidates.Add(("DNSSEC", (cell, b) => cell.AddParagraph(ComposeDnssecStatus(b)), b => b.Dnssec?.WarningCount ?? 0, b => b.Dnssec?.ErrorCount ?? 0, 6));
            if (hasMailTls) candidates.Add(("MAILTLS", (cell, b) => cell.AddParagraph(ComposeMailTlsStatus(b, showMailTlsProtocolHintInSummary)), b => (b.SmtpTls?.WarningCount ?? 0) + (b.ImapTls?.WarningCount ?? 0) + (b.PopTls?.WarningCount ?? 0), b => (b.SmtpTls?.ErrorCount ?? 0) + (b.ImapTls?.ErrorCount ?? 0) + (b.PopTls?.ErrorCount ?? 0), 6));
            if (hasMicrosoft365) candidates.Add(("M365", (cell, b) => cell.AddParagraph(b.Microsoft365?.Status ?? "-"), b => b.Microsoft365?.WarningCount ?? 0, b => b.Microsoft365?.ErrorCount ?? 0, 6));
            if (hasMtasts) candidates.Add(("MTA-STS", (cell, b) => cell.AddParagraph(b.Mtasts?.Status ?? "-"), b => b.Mtasts?.WarningCount ?? 0, b => b.Mtasts?.ErrorCount ?? 0, 5));
            if (hasTlsRpt) candidates.Add(("TLS-RPT", (cell, b) => cell.AddParagraph(b.TlsRpt?.Status ?? "-"), b => b.TlsRpt?.WarningCount ?? 0, b => b.TlsRpt?.ErrorCount ?? 0, 4));
            if (hasDane) candidates.Add(("DANE", (cell, b) => cell.AddParagraph(b.Dane?.Status ?? "-"), b => b.Dane?.WarningCount ?? 0, b => b.Dane?.ErrorCount ?? 0, 4));
            if (hasRpki) candidates.Add(("RPKI", (cell, b) => cell.AddParagraph(ComposeRpkiStatus(b)), b => b.Rpki?.WarningCount ?? 0, b => b.Rpki?.ErrorCount ?? 0, 4));
            if (hasCaa) candidates.Add(("CAA", (cell, b) => cell.AddParagraph(b.Caa?.Status ?? "-"), b => b.Caa?.WarningCount ?? 0, b => b.Caa?.ErrorCount ?? 0, 4));
            if (hasClass) candidates.Add(("Classification", (cell, b) => cell.AddParagraph(b.Classification?.Status ?? "-"), b => b.Classification?.WarningCount ?? 0, b => b.Classification?.ErrorCount ?? 0, 3));

            var selected = candidates
                .OrderByDescending(c => c.Priority)
                .ThenBy(c => c.Header, StringComparer.OrdinalIgnoreCase)
                .Take(contentColumnCap)
                .ToList();
            int omitted = candidates.Count - selected.Count;

            // Use shared ExecutiveSummaryBuilder for core statuses where possible
            var execRows = ExecutiveSummaryBuilder.Build(items, domainOrder);
            var execMap = execRows.ToDictionary(r => r.Domain, StringComparer.OrdinalIgnoreCase);

            var columns = new List<(string Header, Action<WordTableCell, DomainBucket> WriteCell, Func<DomainBucket, int>? Warns, Func<DomainBucket, int>? Errs)>();
            columns.Add(("Domain", (cell, b) => cell.AddParagraph(b.Subject), null, null));
            foreach (var s in selected)
            {
                Action<WordTableCell, DomainBucket> writer = s.WriteCell;
                switch (s.Header.ToUpperInvariant())
                {
                    case "MX":
                        writer = (cell, b) => { if (execMap.TryGetValue(b.Subject ?? string.Empty, out var r)) cell.AddParagraph(r.Mx); else s.WriteCell(cell, b); };
                        break;
                    case "SPF":
                        writer = (cell, b) => { if (execMap.TryGetValue(b.Subject ?? string.Empty, out var r)) cell.AddParagraph(r.Spf); else s.WriteCell(cell, b); };
                        break;
                    case "DMARC":
                        writer = (cell, b) => { if (execMap.TryGetValue(b.Subject ?? string.Empty, out var r)) cell.AddParagraph(r.Dmarc); else s.WriteCell(cell, b); };
                        break;
                    case "MTA-STS":
                        writer = (cell, b) => { if (execMap.TryGetValue(b.Subject ?? string.Empty, out var r)) cell.AddParagraph(r.Mtasts); else s.WriteCell(cell, b); };
                        break;
                    case "TLS-RPT":
                        writer = (cell, b) => { if (execMap.TryGetValue(b.Subject ?? string.Empty, out var r)) cell.AddParagraph(r.TlsRpt); else s.WriteCell(cell, b); };
                        break;
                    case "CLASSIFICATION":
                        writer = (cell, b) => { if (execMap.TryGetValue(b.Subject ?? string.Empty, out var r)) cell.AddParagraph(r.Classification); else s.WriteCell(cell, b); };
                        break;
                    case "M365":
                        writer = (cell, b) => { if (execMap.TryGetValue(b.Subject ?? string.Empty, out var r)) cell.AddParagraph(r.Microsoft365); else s.WriteCell(cell, b); };
                        break;
                    // DKIM: keep Word extras (selector count), so keep original writer
                }
                columns.Add((s.Header, writer, s.Warns, s.Errs));
            }
            columns.Add(("Findings (W/E)", (cell, b) => {
                if (execMap.TryGetValue(b.Subject ?? string.Empty, out var ex)) cell.AddParagraph($"{ex.Warnings} / {ex.Errors}");
                else cell.AddParagraph("- / -");
            }, null, null));

            var sum = doc.AddTable(allRows.Count + 1, columns.Count, WordTableStyle.TableGrid);
            int headerCols = Math.Min(columns.Count, sum.Rows[0].Cells.Count);
            for (int c = 0; c < headerCols; c++) {
                sum.Rows[0].Cells[c].AddParagraph(columns[c].Header);
            }
            for (int i = 0; i < allRows.Count; i++) {
                var (domain, bucket) = (allRows[i].Key, allRows[i].Value);
                bucket.Subject = domain; // ensure subject set for domain cell
                var cells = sum.Rows[i + 1].Cells;
                int rowCols = Math.Min(columns.Count, cells.Count);
                for (int c = 0; c < rowCols; c++) columns[c].WriteCell(cells[c], bucket);
            }

            if (omitted > 0) {
                doc.AddParagraph($"Note: showing top {selected.Count} controls; {omitted} additional check(s) summarized below.")
                   .SetItalic(true);
            }

            // Provider chain + quick links (Executive Summary)
            try {
                var helpOpts = providerHelp ?? new ProviderHelpRenderOptions();
                headings.AddItem("Mail Providers", 1);
                foreach (var row in allRows) {
                    var domain = row.Key;
                    var bucket = row.Value;
                    var chain = ProviderChainBuilder.Build(bucket.Mx, bucket.Spf);

                    // Build badges and confidence
                    var badges = new List<string>();
                    int confidencePct = 0;
                    try { confidencePct = (int)Math.Round(Math.Max(0.0, Math.Min(1.0, (bucket.Mx?.ProviderPrimaryScore ?? 0.0) / 1.2)) * 100.0); } catch { }
                    // Resolve provider metadata for hints
                    DomainDetective.Providers.Email.IMailProvider? providerMeta = null;
                    if (!string.IsNullOrWhiteSpace(chain.Primary)) {
                        providerMeta = DomainDetective.Providers.Email.ProviderRegistry.All.FirstOrDefault(p => string.Equals(p?.DisplayName, chain.Primary, StringComparison.OrdinalIgnoreCase));
                        if (providerMeta?.SingleMxOk == true) badges.Add("[Single‑MX OK]");
                    }
                    if (chain.Gateways.Count > 0) badges.Add("[Gateway]");
                    if (chain.Outbound.Count > 0) badges.Add("[Outbound]");

                    // Compose provider chain text with confidence and hints
                    var chainParts = new List<string>();
                    if (!string.IsNullOrWhiteSpace(chain.Primary)) chainParts.Add($"Primary: {chain.Primary}");
                    if (chain.Gateways.Count > 0) chainParts.Add($"Gateways: {string.Join(", ", chain.Gateways)}");
                    if (chain.Outbound.Count > 0) chainParts.Add($"Outbound: {string.Join(", ", chain.Outbound)}");
                    var baseLine = chainParts.Count > 0 ? string.Join("; ", chainParts) : "(no provider detected)";
                    var hintParts = new List<string>();
                    if (confidencePct > 0) hintParts.Add($"Confidence {confidencePct}%");
                    if (providerMeta != null) {
                        if (providerMeta.MinimumDkimSelectorsToPass > 0) hintParts.Add($"DKIM min {providerMeta.MinimumDkimSelectorsToPass}");
                        if (providerMeta.RecommendedMinMxRecords > 0) hintParts.Add($"Rec MX {providerMeta.RecommendedMinMxRecords}");
                    }
                    var hintText = hintParts.Count > 0 ? $" — {string.Join(" · ", hintParts)}" : string.Empty;
                    var badgeText = badges.Count > 0 ? $" {string.Join(" ", badges)}" : string.Empty;
                    doc.AddParagraph($"{domain}: {baseLine}{hintText}{badgeText}");

                    // Quick links for primary provider (DMARC/SPF/DKIM), if available
                    try {
                        var links = bucket.Mx?.ProviderHelp ?? bucket.Spf?.ProviderHelp;
                        var primaryHelp = links?.FirstOrDefault(p => string.Equals(p?.ProviderName, chain.Primary, StringComparison.OrdinalIgnoreCase))
                                          ?? links?.FirstOrDefault();
                        var topics = primaryHelp?.Topics;
                        if (topics != null && topics.Count > 0) {
                            var ordered = (helpOpts.TopicOrder?.Length > 0)
                                ? topics.OrderBy(t => Array.IndexOf(helpOpts.TopicOrder, (t?.Topic ?? string.Empty).ToUpperInvariant())).ToList()
                                : topics.ToList();
                            var top = ordered.Where(t => !string.IsNullOrWhiteSpace(t?.Url)).Take(3).ToList();
                            if (top.Count > 0) {
                                var l = doc.AddList(WordListStyle.Bulleted);
                                foreach (var t in top) {
                                    var p = l.AddItem(string.Empty);
                                    var text = string.IsNullOrWhiteSpace(t.Title) ? ($"{primaryHelp!.ProviderName} — {t.Topic}") : t.Title!;
                                    try { p.AddHyperLink(text, new Uri(t.Url!), addStyle: true); } catch { p.AddText(text + ": " + t.Url); }
                                }
                            }
                        }
                    } catch { }
                }
                // Add legend for badges and confidence
                try {
                    var legend = doc.AddParagraph("Legend: Confidence = detection certainty; [Single‑MX OK] = vendor supports single MX; [Gateway] = inbound security gateway present; [Outbound] = separate sender platform detected.");
                    legend.SetItalic(true);
                } catch { }
            } catch { }

            // Footnote for MAILTLS rollup sources
            if (hasMailTls && selected.Any(s => string.Equals(s.Header, "MAILTLS", StringComparison.OrdinalIgnoreCase))) {
                var list = doc.AddList(WordListStyle.Bulleted);
                foreach (var row in allRows) {
                    var b = row.Value;
                    if (b.SmtpTls == null && b.ImapTls == null && b.PopTls == null) continue;
                    string smtp = b.SmtpTls != null ? b.SmtpTls.Status : "-";
                    string imap = b.ImapTls != null ? b.ImapTls.Status : "-";
                    string pop = b.PopTls != null ? b.PopTls.Status : "-";
                    list.AddItem($"MailTLS sources for {row.Key}: SMTP={smtp}, IMAP={imap}, POP={pop}");
                }
            }

            // Additional Summary (list) for checks not rendered as columns
            // Aggregate any extra checks present in the input items and not covered by the columns above
            // using a reflection-based adapter over view types.
            var coveredChecks = new HashSet<HealthCheckType>();
            foreach (var h in new[] { hasMx ? (HealthCheckType?)HealthCheckType.MX : null, hasSpf ? HealthCheckType.SPF : null, hasDkim ? HealthCheckType.DKIM : null, hasDmarc ? HealthCheckType.DMARC : null, hasMtasts ? HealthCheckType.MTASTS : null, hasTlsRpt ? HealthCheckType.TLSRPT : null, hasDnsbl ? HealthCheckType.DNSBL : null, hasClass ? HealthCheckType.MAILCLASSIFICATION : null, hasDnssec ? HealthCheckType.DNSSEC : null, hasDane ? HealthCheckType.DANE : null, hasNs ? HealthCheckType.NS : null, hasSoa ? HealthCheckType.SOA : null, hasZone ? HealthCheckType.ZONETRANSFER : null, hasWildcard ? HealthCheckType.WILDCARDDNS : null, hasCaa ? HealthCheckType.CAA : null, hasRpki ? HealthCheckType.RPKI : null, hasMicrosoft365 ? HealthCheckType.MICROSOFT365 : null }.Where(static item => item.HasValue).Select(static item => item!.Value))
            {
                coveredChecks.Add(h);
            }
            if (hasMailTls) { coveredChecks.Add(HealthCheckType.SMTPTLS); coveredChecks.Add(HealthCheckType.IMAPTLS); coveredChecks.Add(HealthCheckType.POP3TLS); }

            var extras = AggregateExtras(items, coveredChecks);
            var allExtraChecks = new HashSet<HealthCheckType>(extras.SelectMany(kv => kv.Value.Keys));
            if (allExtraChecks.Count > 0) {
                headings.AddItem("Additional Summary", 1);
                doc.AddParagraph("Other requested checks summarized per domain (status and counts):");
                foreach (var row in allRows) {
                    var domain = row.Key;
                    if (!extras.TryGetValue(domain, out var map) || map.Count == 0) continue;
                    var list = doc.AddList(WordListStyle.Bulleted);
                    foreach (var kv in map.OrderBy(k => k.Key.ToString())) {
                        var (status, w, e) = kv.Value;
                        list.AddItem($"{kv.Key}: {status} ({w} warn / {e} err)");
                    }
                }
            }
        } catch { /* skip summary on edge cases */ }

        AssessmentEvidenceOfficeSections.WriteWord(doc, headings, AssessmentEvidenceInfo.Collect(items), showInfoFindings);

        // Background narratives (global) when requested
        if (placeGlobal) {
            BackgroundWordSectionWriter.Write(doc, headings, 1, items);
        }

        // Per-domain sections
        bool firstDomain = true;
        // Precompute input-driven section order if requested
        var inputSectionOrder = (sectionOrderMode == SectionOrderMode.Input) ? DetermineSectionOrderByDomain(items) : new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var normalizedCustom = (sectionOrderMode == SectionOrderMode.Custom && sectionOrder != null) ? NormalizeSectionList(sectionOrder) : Array.Empty<string>();
        foreach (var kv in allRows.Where(_ => scope != ReportScope.Minimal)) {
            var domain = kv.Key;
            var bucket = kv.Value;
            if (!firstDomain) doc.AddPageBreak();
            firstDomain = false;
            headings.AddItem(domain);

            var writers = new System.Collections.Generic.Dictionary<string, System.Action>(System.StringComparer.OrdinalIgnoreCase);
            var present = new System.Collections.Generic.HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
            void add(string key, System.Action action, bool isPresent) { if (isPresent) present.Add(key); writers[key] = action; }
            add("MX", () => {
                headings.AddItem("MX", 1);
                var dto = DomainDetective.Reports.SectionProjectors.BuildMx(bucket.Mx!);
                if (dto != null) MxWordSectionWriter.Write(doc, headings, 2, dto, bucket.Mx, domain, scope, showInfoFindings, includeNarrativePerDomain, providerHelp ?? new ProviderHelpRenderOptions());
                else MxWordSectionWriter.Write(doc, headings, 2, bucket.Mx!, domain, scope, showInfoFindings, includeNarrativePerDomain, providerHelp ?? new ProviderHelpRenderOptions());
            }, bucket.Mx != null);
            add("Mail Transport Posture", () => {
                headings.AddItem("Mail Transport Posture", 1);
                var dto = DomainDetective.Reports.SectionProjectors.BuildMailTransportPosture(
                    bucket.Mx,
                    bucket.SmtpTls,
                    bucket.ImapTls,
                    bucket.PopTls,
                    bucket.Mtasts,
                    bucket.TlsRpt,
                    bucket.TlsRptReports,
                    bucket.Dane);
                if (dto != null)
                {
                    MailTransportPostureWordSectionWriter.Write(doc, headings, 2, dto, domain, scope, showInfoFindings);
                }
                else
                {
                    doc.AddParagraph("No mail transport posture data.").SetItalic(true);
                }
            }, bucket.Mx != null || bucket.SmtpTls != null || bucket.ImapTls != null || bucket.PopTls != null || bucket.Mtasts != null || bucket.TlsRpt != null || bucket.TlsRptReports != null || bucket.Dane != null);
            add("Desired State", () => {
                headings.AddItem("Desired State", 1);
                var dto = DomainDetective.Reports.SectionProjectors.BuildDesiredState(bucket.DesiredState!);
                if (dto != null) DesiredStateWordSectionWriter.Write(doc, headings, 2, dto, bucket.DesiredState, domain, scope, showInfoFindings);
                else DesiredStateWordSectionWriter.Write(doc, headings, 2, bucket.DesiredState!, domain, scope, showInfoFindings);
            }, bucket.DesiredState != null);
            add("SPF", () => {
                headings.AddItem("SPF", 1);
                var dto = DomainDetective.Reports.SectionProjectors.BuildSpf(bucket.Spf!);
                if (dto != null) SpfWordSectionWriter.Write(doc, headings, 2, dto, bucket.Spf, domain, scope, showInfoFindings, includeNarrativePerDomain, includeMechanismMeaningsPerDomain);
                else SpfWordSectionWriter.Write(doc, headings, 2, bucket.Spf!, domain, scope, showInfoFindings, includeNarrativePerDomain, includeMechanismMeaningsPerDomain);
                try { var opts = providerHelp ?? new ProviderHelpRenderOptions(); if (opts.ShowUnderSpf) { var help = bucket.Mx?.ProviderHelp ?? bucket.Spf?.ProviderHelp; if (help != null && help.Count > 0) ProviderHelpWordSectionWriter.Write(doc, headings, 2, help, opts); } } catch { }
            }, bucket.Spf != null);
            add("DKIM", () => {
                headings.AddItem("DKIM", 1);
                var dto = DomainDetective.Reports.SectionProjectors.BuildDkim(bucket.Dkim, bucket.Ttl);
                if (dto != null) DkimWordSectionWriter.Write(doc, headings, 2, dto, bucket.Dkim, domain, scope, showInfoFindings, includeNarrativePerDomain);
                else DkimWordSectionWriter.Write(doc, headings, 2, bucket.Dkim, domain, scope, showInfoFindings, includeNarrativePerDomain);
                try { var opts = providerHelp ?? new ProviderHelpRenderOptions(); if (opts.ShowUnderDkim) { var help = bucket.Mx?.ProviderHelp ?? bucket.Spf?.ProviderHelp; if (help != null && help.Count > 0) ProviderHelpWordSectionWriter.Write(doc, headings, 2, help, opts); } } catch { }
            }, bucket.Dkim.Count > 0);
            add("MAILTLS", () => {
                headings.AddItem("MailTLS", 1);
                MailTlsWordSectionWriter.Write(doc, headings, 2, bucket.SmtpTls, bucket.ImapTls, bucket.PopTls, scope, showInfoFindings);
            }, (bucket.SmtpTls != null || bucket.ImapTls != null || bucket.PopTls != null));
            add("DMARC", () => {
                headings.AddItem("DMARC", 1);
                var dto = DomainDetective.Reports.SectionProjectors.BuildDmarc(bucket.Dmarc!);
                if (dto != null) DmarcWordSectionWriter.Write(doc, headings, 2, dto, bucket.Dmarc, domain, scope, showInfoFindings, includeNarrativePerDomain);
                else DmarcWordSectionWriter.Write(doc, headings, 2, bucket.Dmarc!, domain, scope, showInfoFindings, includeNarrativePerDomain);
                try { var opts = providerHelp ?? new ProviderHelpRenderOptions(); if (opts.ShowUnderDmarc) { var help = bucket.Mx?.ProviderHelp ?? bucket.Spf?.ProviderHelp; if (help != null && help.Count > 0) ProviderHelpWordSectionWriter.Write(doc, headings, 2, help, opts); } } catch { }
            }, bucket.Dmarc != null);
            add("DMARC Aggregate", () => {
                headings.AddItem("DMARC Aggregate", 1);
                DmarcAggregateWordSectionWriter.Write(doc, headings, 2, bucket.DmarcAggregate!, domain, scope, showInfoFindings, includeNarrativePerDomain);
            }, bucket.DmarcAggregate != null);
            add("Registration", () => {
                headings.AddItem("Registration", 1);
                RegistrationWordSectionWriter.Write(doc, headings, 2, bucket.Registration!, domain, scope, showInfoFindings, includeNarrativePerDomain);
            }, bucket.Registration != null);
            add("Microsoft 365", () =>
            {
                headings.AddItem("Microsoft 365", 1);
                var dto = DomainDetective.Reports.SectionProjectors.BuildMicrosoft365(bucket.Microsoft365!);
                if (dto != null) Microsoft365WordSectionWriter.Write(doc, headings, 2, dto, bucket.Microsoft365, domain, scope, showInfoFindings);
                else Microsoft365WordSectionWriter.Write(doc, headings, 2, bucket.Microsoft365!, domain, scope, showInfoFindings);
            }, bucket.Microsoft365 != null);
            add("HTTP", () =>
            {
                headings.AddItem("HTTP", 1);
                var dto = DomainDetective.Reports.SectionProjectors.BuildHttp(bucket.Http!);
                if (dto != null) HttpWordSectionWriter.Write(doc, headings, 2, dto, bucket.Http, domain, scope, showInfoFindings);
                else HttpWordSectionWriter.Write(doc, headings, 2, bucket.Http!, domain, scope, showInfoFindings);
            }, bucket.Http != null);
            add("Typosquatting", () =>
            {
                headings.AddItem("Typosquatting", 1);
                var dto = DomainDetective.Reports.SectionProjectors.BuildTyposquatting(bucket.Typosquatting!);
                if (dto != null)
                {
                    TyposquattingWordSectionWriter.Write(doc, headings, 2, dto, bucket.Typosquatting!, domain, scope, showInfoFindings);
                }
            }, bucket.Typosquatting != null);
            add("CT Timeline", () =>
            {
                headings.AddItem("CT Timeline", 1);
                var dto = DomainDetective.Reports.SectionProjectors.BuildCtTimeline(bucket.CtTimeline!);
                if (dto != null) CtTimelineWordSectionWriter.Write(doc, headings, 2, dto, bucket.CtTimeline, domain, scope, showInfoFindings);
                else CtTimelineWordSectionWriter.Write(doc, headings, 2, bucket.CtTimeline!, domain, scope, showInfoFindings);
            }, bucket.CtTimeline != null);
            add("Subdomains", () => {
                headings.AddItem("Subdomains", 1);
                var dto = DomainDetective.Reports.SectionProjectors.BuildSubdomains(bucket.Subdomains!);
                if (dto != null) SubdomainsWordSectionWriter.Write(doc, headings, 2, dto, bucket.Subdomains, domain, scope, showInfoFindings);
                else SubdomainsWordSectionWriter.Write(doc, headings, 2, bucket.Subdomains!, domain, scope, showInfoFindings);
            }, bucket.Subdomains != null);
            add("DNS Inventory", () =>
            {
                headings.AddItem("DNS Inventory", 1);
                var dto = DomainDetective.Reports.SectionProjectors.BuildDnsInventory(bucket.DnsInventory!);
                if (dto != null) DnsInventoryWordSectionWriter.Write(doc, headings, 2, dto, bucket.DnsInventory, domain, scope, showInfoFindings);
                else DnsInventoryWordSectionWriter.Write(doc, headings, 2, bucket.DnsInventory!, domain, scope, showInfoFindings);
            }, bucket.DnsInventory != null);
            add("DNS Trace", () =>
            {
                headings.AddItem("DNS Trace", 1);
                var dto = DomainDetective.Reports.SectionProjectors.BuildDnsTrace(bucket.DnsTrace!);
                if (dto != null) DnsTraceWordSectionWriter.Write(doc, headings, 2, dto, bucket.DnsTrace, domain, scope, showInfoFindings);
                else DnsTraceWordSectionWriter.Write(doc, headings, 2, bucket.DnsTrace!, domain, scope, showInfoFindings);
            }, bucket.DnsTrace != null);
            add("DNS Propagation", () =>
            {
                headings.AddItem("DNS Propagation", 1);
                DnsPropagationWordSectionWriter.Write(doc, headings, 2, bucket.DnsPropagation, domain, scope, showInfoFindings);
            }, bucket.DnsPropagation.Count > 0);
            add("DNS Amplification", () =>
            {
                headings.AddItem("DNS Amplification", 1);
                var dto = DomainDetective.Reports.SectionProjectors.BuildDnsAmplification(bucket.DnsAmplification!);
                if (dto != null) DnsAmplificationWordSectionWriter.Write(doc, headings, 2, dto, bucket.DnsAmplification, domain, scope, showInfoFindings);
                else DnsAmplificationWordSectionWriter.Write(doc, headings, 2, bucket.DnsAmplification!, domain, scope, showInfoFindings);
            }, bucket.DnsAmplification != null);
            add("DNS over TLS", () =>
            {
                headings.AddItem("DNS over TLS", 1);
                var dto = DomainDetective.Reports.SectionProjectors.BuildDnsOverTls(bucket.DnsOverTls!);
                if (dto != null) DnsOverTlsWordSectionWriter.Write(doc, headings, 2, dto, bucket.DnsOverTls, domain, scope, showInfoFindings);
                else DnsOverTlsWordSectionWriter.Write(doc, headings, 2, bucket.DnsOverTls!, domain, scope, showInfoFindings);
            }, bucket.DnsOverTls != null);
            add("IP Enrichment", () =>
            {
                headings.AddItem("IP Enrichment", 1);
                var dto = DomainDetective.Reports.SectionProjectors.BuildIpEnrichment(bucket.IpEnrichment!);
                if (dto != null) IpEnrichmentWordSectionWriter.Write(doc, headings, 2, dto, bucket.IpEnrichment, domain, scope, showInfoFindings);
                else IpEnrichmentWordSectionWriter.Write(doc, headings, 2, bucket.IpEnrichment!, domain, scope, showInfoFindings);
            }, bucket.IpEnrichment != null);
            add("ARC", () => { headings.AddItem("ARC", 1); ArcWordSectionWriter.Write(doc, headings, 2, bucket.Arc!, domain, scope, showInfoFindings, includeNarrativePerDomain); try { var opts = providerHelp ?? new ProviderHelpRenderOptions(); if (opts.ShowUnderArc) { var help = bucket.Mx?.ProviderHelp ?? bucket.Spf?.ProviderHelp; if (help != null && help.Count > 0) ProviderHelpWordSectionWriter.Write(doc, headings, 2, help, opts); } } catch { } }, bucket.Arc != null);  
            add("BIMI", () => { headings.AddItem("BIMI", 1); BimiWordSectionWriter.Write(doc, headings, 2, bucket.Bimi!, domain, scope, showInfoFindings, includeNarrativePerDomain); try { var opts = providerHelp ?? new ProviderHelpRenderOptions(); if (opts.ShowUnderBimi) { var help = bucket.Mx?.ProviderHelp ?? bucket.Spf?.ProviderHelp; if (help != null && help.Count > 0) ProviderHelpWordSectionWriter.Write(doc, headings, 2, help, opts); } } catch { } }, bucket.Bimi != null);
            add("DNSBL", () => { headings.AddItem("DNSBL", 1); var dto = DomainDetective.Reports.SectionProjectors.BuildDnsbl(bucket.Dnsbl!); if (dto != null) DnsblWordSectionWriter.Write(doc, headings, 2, dto, bucket.Dnsbl, domain, scope, showInfoFindings); else DnsblWordSectionWriter.Write(doc, headings, 2, bucket.Dnsbl!, domain, scope, showInfoFindings); }, bucket.Dnsbl != null);
            add("RPKI", () => { headings.AddItem("RPKI", 1); var dto = DomainDetective.Reports.SectionProjectors.BuildRpki(bucket.Rpki!); if (dto != null) RpkiWordSectionWriter.Write(doc, headings, 2, dto, bucket.Rpki, domain, scope, showInfoFindings); else RpkiWordSectionWriter.Write(doc, headings, 2, bucket.Rpki!, domain, scope, showInfoFindings); }, bucket.Rpki != null);
            add("NS", () => { headings.AddItem("NS", 1); var dto = DomainDetective.Reports.SectionProjectors.BuildNs(bucket.Ns!); if (dto != null) NsWordSectionWriter.Write(doc, headings, 2, dto, bucket.Ns, domain, scope, showInfoFindings); else NsWordSectionWriter.Write(doc, headings, 2, bucket.Ns!, domain, scope, showInfoFindings); }, bucket.Ns != null);
            add("SOA", () => { headings.AddItem("SOA", 1); var dto = DomainDetective.Reports.SectionProjectors.BuildSoa(bucket.Soa!); if (dto != null) SoaWordSectionWriter.Write(doc, headings, 2, dto, bucket.Soa, domain, scope, showInfoFindings); else SoaWordSectionWriter.Write(doc, headings, 2, bucket.Soa!, domain, scope, showInfoFindings); }, bucket.Soa != null);
            add("ZoneTransfer", () => { headings.AddItem("Zone Transfer", 1); var dto = DomainDetective.Reports.SectionProjectors.BuildZoneTransfer(bucket.ZoneTransfer!); if (dto != null) ZoneTransferWordSectionWriter.Write(doc, headings, 2, dto, bucket.ZoneTransfer, domain, scope, showInfoFindings); else ZoneTransferWordSectionWriter.Write(doc, headings, 2, bucket.ZoneTransfer!, domain, scope, showInfoFindings); }, bucket.ZoneTransfer != null);
            add("Wildcard", () => { headings.AddItem("Wildcard DNS", 1); var dto = DomainDetective.Reports.SectionProjectors.BuildWildcard(bucket.Wildcard!); if (dto != null) WildcardWordSectionWriter.Write(doc, headings, 2, dto, bucket.Wildcard, domain, scope, showInfoFindings); else WildcardWordSectionWriter.Write(doc, headings, 2, bucket.Wildcard!, domain, scope, showInfoFindings); }, bucket.Wildcard != null);
            add("CAA", () => { headings.AddItem("CAA", 1); var dto = DomainDetective.Reports.SectionProjectors.BuildCaa(bucket.Caa!); if (dto != null) CaaWordSectionWriter.Write(doc, headings, 2, dto, bucket.Caa, domain, scope, showInfoFindings); else CaaWordSectionWriter.Write(doc, headings, 2, bucket.Caa!, domain, scope, showInfoFindings); }, bucket.Caa != null);
            add("Classification", () => { headings.AddItem("Mail Classification", 1); MailClassificationWordSectionWriter.Write(doc, headings, 2, bucket.Classification!, domain, scope, showInfoFindings); }, bucket.Classification != null);
            add("MTA-STS", () => { headings.AddItem("MTA-STS", 1); var dto = DomainDetective.Reports.SectionProjectors.BuildMtasts(bucket.Mtasts!); if (dto != null) MtastsWordSectionWriter.Write(doc, headings, 2, dto, bucket.Mtasts, domain, scope, showInfoFindings, includeNarrativePerDomain); else MtastsWordSectionWriter.Write(doc, headings, 2, bucket.Mtasts!, domain, scope, showInfoFindings, includeNarrativePerDomain); }, bucket.Mtasts != null);
            add("TLS-RPT", () => { headings.AddItem("TLS-RPT", 1); var dto = DomainDetective.Reports.SectionProjectors.BuildTlsRpt(bucket.TlsRpt!); if (dto != null) TlsRptWordSectionWriter.Write(doc, headings, 2, dto, bucket.TlsRpt, domain, scope, showInfoFindings, includeNarrativePerDomain); else TlsRptWordSectionWriter.Write(doc, headings, 2, bucket.TlsRpt!, domain, scope, showInfoFindings, includeNarrativePerDomain); }, bucket.TlsRpt != null);
            add("TLS-RPT Reports", () => {
                headings.AddItem("TLS-RPT Reports", 1);
                TlsRptReportsWordSectionWriter.Write(doc, headings, 2, bucket.TlsRptReports!, domain, scope, showInfoFindings, includeNarrativePerDomain);
            }, bucket.TlsRptReports != null);
            add("DNSSEC", () => { headings.AddItem("DNSSEC", 1); var dto = DomainDetective.Reports.SectionProjectors.BuildDnssec(bucket.Dnssec!); if (dto != null) DnssecWordSectionWriter.Write(doc, headings, 2, dto, bucket.Dnssec, domain, scope, showInfoFindings, includeNarrativePerDomain); else DnssecWordSectionWriter.Write(doc, headings, 2, bucket.Dnssec!, domain, scope, showInfoFindings, includeNarrativePerDomain); }, bucket.Dnssec != null);
            add("DANE", () => { headings.AddItem("DANE", 1); var dto = DomainDetective.Reports.SectionProjectors.BuildDane(bucket.Dane!); if (dto != null) DaneWordSectionWriter.Write(doc, headings, 2, dto, bucket.Dane, domain, scope, showInfoFindings, includeNarrativePerDomain); else DaneWordSectionWriter.Write(doc, headings, 2, bucket.Dane!, domain, scope, showInfoFindings, includeNarrativePerDomain); }, bucket.Dane != null);

            var canonical = CanonicalSections;
            var finalOrder = new System.Collections.Generic.List<string>();
            if (sectionOrderMode == SectionOrderMode.Custom && normalizedCustom.Length > 0) {
                foreach (var s in normalizedCustom) if (present.Contains(s)) finalOrder.Add(s);
                foreach (var s in canonical) if (present.Contains(s) && !finalOrder.Contains(s, System.StringComparer.OrdinalIgnoreCase)) finalOrder.Add(s);
            } else if (sectionOrderMode == SectionOrderMode.Input && inputSectionOrder.TryGetValue(domain, out var seenOrder) && seenOrder.Count > 0) {
                foreach (var s in seenOrder) if (present.Contains(s)) finalOrder.Add(s);
                foreach (var s in canonical) if (present.Contains(s) && !finalOrder.Contains(s, System.StringComparer.OrdinalIgnoreCase)) finalOrder.Add(s);
            } else {
                foreach (var s in canonical) if (present.Contains(s)) finalOrder.Add(s);
            }

            foreach (var key in finalOrder) { try { writers[key](); } catch { } }
        }

        // Consolidated Recommendations (grouped across all domains)
        try {
            // Consolidated References (shared collector)
            var compMap = CompositionBuilder.GroupBySubject(items);
            var refs = ReferencesCollector.CollectAll(compMap.Values);
            if (refs.Count > 0) {
                headings.AddItem("All References");
                doc.AddParagraph("References cited across all sections. Use these for standards and implementation guidance.");
                var list = doc.AddList(WordListStyle.Bulleted);
                foreach (var r in refs) {
                    var fmt = LinkFormatter.Format(r);
                    var item = list.AddItem(string.Empty);
                    try { item.AddHyperLink(fmt.Title, new Uri(fmt.Url), addStyle: true); }
                    catch { item.AddText(fmt.Title + ": " + fmt.Url); }
                }
            }
        } catch { }

        doc.Save();
    }

}
