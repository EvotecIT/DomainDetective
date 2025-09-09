using System;
using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Word;
using DocumentFormat.OpenXml.Wordprocessing;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Aggregates mixed view objects (SPF/DKIM/DMARC) for one or more domains into a single Word document.
/// </summary>
/// <summary>
/// Builds a single Word document from mixed per-section view objects across one or many domains.
/// </summary>
public static class WordCompositionReport {
    /// <summary>
    /// Generates a composed Word report.
    /// </summary>
    /// <param name="path">Output file path.</param>
    /// <param name="items">View objects (SPF/DKIM/DMARC/DNSBL/MailClassification).</param>
    /// <param name="scope">Detail level for sections.</param>
    /// <param name="showInfoFindings">Include Info-level findings in tables.</param>
    /// <param name="titleOverride">Optional title override.</param>
    /// <param name="companyName">Branding property.</param>
    /// <param name="companyAddress">Branding property.</param>
    /// <param name="companyYear">Branding property.</param>
    /// <param name="logoPath">Header logo.</param>
    /// <param name="headerText">Header left text.</param>
    /// <param name="watermarkText">Watermark text.</param>
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
        string? watermarkText = null,
        bool showDkimSelectorCountInSummary = true,
        bool showMailTlsProtocolHintInSummary = true,
        ProviderHelpRenderOptions? providerHelp = null) {
        if (items == null || items.Count == 0) throw new ArgumentException("No items to compose.", nameof(items));

        // Group items by domain/subject
        var grouped = GroupBySubject(items);
        var subjectTitle = BuildSubjectTitle(grouped.Keys.ToList());
        var title = string.IsNullOrWhiteSpace(titleOverride)
            ? $"Security Report — {subjectTitle}"
            : titleOverride!;

        using var doc = WordDocument.Create(path);
        doc.Settings.UpdateFieldsOnOpen = true;

        // Built-in and custom properties
        var subj = string.IsNullOrWhiteSpace(subjectOverride) ? "Custom Composition" : subjectOverride;
        var keys = string.IsNullOrWhiteSpace(keywordsOverride) ? "Email Security" : keywordsOverride;
        var cat = string.IsNullOrWhiteSpace(categoryOverride) ? "Security" : categoryOverride;
        var creator = string.IsNullOrWhiteSpace(creatorOverride) ? "DomainDetective" : creatorOverride;
        WordReportCommon.ApplyBuiltInProperties(doc, title, subj, keys, cat, creator);
        WordReportCommon.ApplyCompanyBranding(doc, companyName, companyAddress, companyYear);

        // Cover/TOC/Header
        doc.AddCoverPage(CoverPageTemplate.IonDark);
        doc.AddTableOfContent(TableOfContentStyle.Template1);
        doc.AddPageBreak();
        WordReportCommon.AddHeader(doc, WordReportCommon.ResolveHeaderLeftText(headerText, new { Title = title }, title),
            $"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}", logoPath, watermarkText, null);
        WordReportCommon.AddFooter(doc, null, null, logoPath, null); // left defaults to CompanyLine; add logo when provided

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

        // Compute totals across domains for only the present sections
        int totalWarns = 0, totalErrs = 0;
        foreach (var kv in grouped) {
            var b = kv.Value;
            if (hasSpf) { totalWarns += b.Spf?.WarningCount ?? 0; totalErrs += b.Spf?.ErrorCount ?? 0; }
            if (hasDmarc) { totalWarns += b.Dmarc?.WarningCount ?? 0; totalErrs += b.Dmarc?.ErrorCount ?? 0; }
            if (hasArc) { totalWarns += b.Arc?.WarningCount ?? 0; totalErrs += b.Arc?.ErrorCount ?? 0; }
            if (hasDkim) { totalWarns += b.Dkim?.Sum(x => x.WarningCount) ?? 0; totalErrs += b.Dkim?.Sum(x => x.ErrorCount) ?? 0; }
            if (hasBimi) { totalWarns += b.Bimi?.WarningCount ?? 0; totalErrs += b.Bimi?.ErrorCount ?? 0; }
            if (hasMtasts) { totalWarns += b.Mtasts?.WarningCount ?? 0; totalErrs += b.Mtasts?.ErrorCount ?? 0; }
            if (hasTlsRpt) { totalWarns += b.TlsRpt?.WarningCount ?? 0; totalErrs += b.TlsRpt?.ErrorCount ?? 0; }
            if (hasMx) { totalWarns += b.Mx?.WarningCount ?? 0; totalErrs += b.Mx?.ErrorCount ?? 0; }
            if (hasDnsbl) { totalWarns += b.Dnsbl?.WarningCount ?? 0; totalErrs += b.Dnsbl?.ErrorCount ?? 0; }
            if (hasRpki) { totalWarns += b.Rpki?.WarningCount ?? 0; totalErrs += b.Rpki?.ErrorCount ?? 0; }
            if (hasMailTls) {
                totalWarns += (b.SmtpTls?.WarningCount ?? 0) + (b.ImapTls?.WarningCount ?? 0) + (b.PopTls?.WarningCount ?? 0);
                totalErrs += (b.SmtpTls?.ErrorCount ?? 0) + (b.ImapTls?.ErrorCount ?? 0) + (b.PopTls?.ErrorCount ?? 0);
            }
            if (hasClass) { totalWarns += b.Classification?.WarningCount ?? 0; totalErrs += b.Classification?.ErrorCount ?? 0; }
            if (hasDnssec) { totalWarns += b.Dnssec?.WarningCount ?? 0; totalErrs += b.Dnssec?.ErrorCount ?? 0; }
            if (hasDane) { totalWarns += b.Dane?.WarningCount ?? 0; totalErrs += b.Dane?.ErrorCount ?? 0; }
            if (hasNs) { totalWarns += b.Ns?.WarningCount ?? 0; totalErrs += b.Ns?.ErrorCount ?? 0; }
            if (hasSoa) { totalWarns += b.Soa?.WarningCount ?? 0; totalErrs += b.Soa?.ErrorCount ?? 0; }
            if (hasZone) { totalWarns += b.ZoneTransfer?.WarningCount ?? 0; totalErrs += b.ZoneTransfer?.ErrorCount ?? 0; }
            if (hasWildcard) { totalWarns += b.Wildcard?.WarningCount ?? 0; totalErrs += b.Wildcard?.ErrorCount ?? 0; }
            if (hasCaa) { totalWarns += b.Caa?.WarningCount ?? 0; totalErrs += b.Caa?.ErrorCount ?? 0; }
        }

        // Executive Summary intro text — dynamic list of controls present
        string controlsText = presentLabels.Count > 0 ? string.Join(", ", presentLabels) : "requested checks";
        doc.AddParagraph($"This report summarizes the email security posture for {grouped.Count} domain(s). The table highlights the presence and status of key controls ({controlsText}) and the count of warnings/errors detected. Total across all domains: {totalWarns} warning(s), {totalErrs} error(s).");

        // Executive Summary table (defensive build to avoid style-dependent index issues)
        var allRows = grouped.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase).ToList();
        try {
            // Build dynamic header list and writers; cap content columns to keep layout tidy in Word.
            // Max total columns ≈ 6 (including Domain + Findings) → content columns cap = 4.
            const int maxContentColumns = 4;
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
            if (hasMtasts) candidates.Add(("MTA-STS", (cell, b) => cell.AddParagraph(b.Mtasts?.Status ?? "-"), b => b.Mtasts?.WarningCount ?? 0, b => b.Mtasts?.ErrorCount ?? 0, 5));
            if (hasTlsRpt) candidates.Add(("TLS-RPT", (cell, b) => cell.AddParagraph(b.TlsRpt?.Status ?? "-"), b => b.TlsRpt?.WarningCount ?? 0, b => b.TlsRpt?.ErrorCount ?? 0, 4));
            if (hasDane) candidates.Add(("DANE", (cell, b) => cell.AddParagraph(b.Dane?.Status ?? "-"), b => b.Dane?.WarningCount ?? 0, b => b.Dane?.ErrorCount ?? 0, 4));
            if (hasRpki) candidates.Add(("RPKI", (cell, b) => cell.AddParagraph(ComposeRpkiStatus(b)), b => b.Rpki?.WarningCount ?? 0, b => b.Rpki?.ErrorCount ?? 0, 4));
            if (hasCaa) candidates.Add(("CAA", (cell, b) => cell.AddParagraph(b.Caa?.Status ?? "-"), b => b.Caa?.WarningCount ?? 0, b => b.Caa?.ErrorCount ?? 0, 4));
            if (hasClass) candidates.Add(("Classification", (cell, b) => cell.AddParagraph(b.Classification?.Status ?? "-"), b => b.Classification?.WarningCount ?? 0, b => b.Classification?.ErrorCount ?? 0, 3));

            var selected = candidates
                .OrderByDescending(c => c.Priority)
                .ThenBy(c => c.Header, StringComparer.OrdinalIgnoreCase)
                .Take(maxContentColumns)
                .ToList();
            int omitted = candidates.Count - selected.Count;

            var columns = new List<(string Header, Action<WordTableCell, DomainBucket> WriteCell, Func<DomainBucket, int>? Warns, Func<DomainBucket, int>? Errs)>();
            columns.Add(("Domain", (cell, b) => cell.AddParagraph(b.Subject), null, null));
            foreach (var s in selected)
                columns.Add((s.Header, s.WriteCell, s.Warns, s.Errs));
            columns.Add(("Findings (W/E)", (cell, b) => {
                int w = 0, e = 0;
                foreach (var col in columns) {
                    if (col.Warns != null) w += col.Warns(b);
                    if (col.Errs != null) e += col.Errs(b);
                }
                cell.AddParagraph($"{w} / {e}");
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
                    var primary = bucket.Mx?.ProviderPrimary ?? string.Empty;
                    var gateways = bucket.Mx?.ProviderGateways ?? new List<string>();
                    var outbound = new List<string>();
                    try {
                        // Infer outbound from SPF provider help names excluding primary/gateways
                        var names = (bucket.Spf?.ProviderHelp ?? Array.Empty<DomainDetective.Views.ProviderHelpLinks>())
                            .Select(p => p?.ProviderName)
                            .Where(n => !string.IsNullOrWhiteSpace(n))
                            .Distinct(StringComparer.OrdinalIgnoreCase)
                            .ToList();
                        foreach (var n in names) {
                            if (string.IsNullOrWhiteSpace(n)) continue;
                            if (string.Equals(n, primary, StringComparison.OrdinalIgnoreCase)) continue;
                            if (gateways.Contains(n, StringComparer.OrdinalIgnoreCase)) continue;
                            outbound.Add(n);
                        }
                    } catch { }

                    // Build badges and confidence
                    var badges = new List<string>();
                    int confidencePct = 0;
                    try { confidencePct = (int)Math.Round(Math.Max(0.0, Math.Min(1.0, (bucket.Mx?.ProviderPrimaryScore ?? 0.0) / 1.2)) * 100.0); } catch { }
                    // Resolve provider metadata for hints
                    DomainDetective.Providers.Email.IMailProvider? providerMeta = null;
                    if (!string.IsNullOrWhiteSpace(primary)) {
                        providerMeta = DomainDetective.Providers.Email.ProviderRegistry.All.FirstOrDefault(p => string.Equals(p?.DisplayName, primary, StringComparison.OrdinalIgnoreCase));
                        if (providerMeta?.SingleMxOk == true) badges.Add("[Single‑MX OK]");
                    }
                    if (gateways.Count > 0) badges.Add("[Gateway]");
                    if (outbound.Count > 0) badges.Add("[Outbound]");

                    // Compose provider chain text with confidence and hints
                    var chain = new List<string>();
                    if (!string.IsNullOrWhiteSpace(primary)) chain.Add($"Primary: {primary}");
                    if (gateways.Count > 0) chain.Add($"Gateways: {string.Join(", ", gateways)}");
                    if (outbound.Count > 0) chain.Add($"Outbound: {string.Join(", ", outbound)}");
                    var baseLine = chain.Count > 0 ? string.Join("; ", chain) : "(no provider detected)";
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
                        var primaryHelp = links?.FirstOrDefault(p => string.Equals(p?.ProviderName, primary, StringComparison.OrdinalIgnoreCase))
                                          ?? links?.FirstOrDefault();
                        if (primaryHelp != null && (primaryHelp.Topics?.Count ?? 0) > 0) {
                            var ordered = (helpOpts.TopicOrder?.Length > 0)
                                ? primaryHelp.Topics.OrderBy(t => Array.IndexOf(helpOpts.TopicOrder, (t?.Topic ?? string.Empty).ToUpperInvariant())).ToList()
                                : primaryHelp.Topics.ToList();
                            var top = ordered.Where(t => !string.IsNullOrWhiteSpace(t?.Url)).Take(3).ToList();
                            if (top.Count > 0) {
                                var l = doc.AddList(WordListStyle.Bulleted);
                                foreach (var t in top) {
                                    var p = l.AddItem(string.Empty);
                                    var text = string.IsNullOrWhiteSpace(t.Title) ? ($"{primaryHelp.ProviderName} — {t.Topic}") : t.Title!;
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
            foreach (var h in new[] { hasMx ? (HealthCheckType?)HealthCheckType.MX : null, hasSpf ? HealthCheckType.SPF : null, hasDkim ? HealthCheckType.DKIM : null, hasDmarc ? HealthCheckType.DMARC : null, hasMtasts ? HealthCheckType.MTASTS : null, hasTlsRpt ? HealthCheckType.TLSRPT : null, hasDnsbl ? HealthCheckType.DNSBL : null, hasClass ? HealthCheckType.MAILCLASSIFICATION : null, hasDnssec ? HealthCheckType.DNSSEC : null, hasDane ? HealthCheckType.DANE : null, hasNs ? HealthCheckType.NS : null, hasSoa ? HealthCheckType.SOA : null, hasZone ? HealthCheckType.ZONETRANSFER : null, hasWildcard ? HealthCheckType.WILDCARDDNS : null, hasCaa ? HealthCheckType.CAA : null, hasRpki ? HealthCheckType.RPKI : null })
                if (h.HasValue) coveredChecks.Add(h.Value);
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

        // Background narratives (global) when requested
        bool multiDomain = allRows.Count > 1;
        bool placeGlobal = narrativePlacement == NarrativePlacement.Global || (narrativePlacement == NarrativePlacement.Auto && multiDomain);
        bool includeNarrativePerDomain = narrativePlacement == NarrativePlacement.PerDomain || (narrativePlacement == NarrativePlacement.Auto && !multiDomain);
        bool includeMechanismMeaningsPerDomain = includeNarrativePerDomain; // meanings go with narratives when per-domain
        if (placeGlobal) {
            BackgroundWordSectionWriter.Write(doc, headings, 1, items);
        }

        // Per-domain sections
        bool firstDomain = true;
        foreach (var kv in allRows) {
            var domain = kv.Key;
            var bucket = kv.Value;
            if (!firstDomain) doc.AddPageBreak();
            firstDomain = false;
            headings.AddItem(domain);

            if (bucket.Mx != null) {
                headings.AddItem("MX", 1);
                MxWordSectionWriter.Write(doc, headings, 2, bucket.Mx, domain, scope, showInfoFindings, includeNarrativePerDomain, providerHelp ?? new ProviderHelpRenderOptions());
            }

            if (bucket.Spf != null) {
                headings.AddItem("SPF", 1);
                // Base level 2 under the 'SPF' node: 0=domain, 1=SPF, 2=subsections
                SpfWordSectionWriter.Write(doc, headings, 2, bucket.Spf, domain, scope, showInfoFindings, includeNarrativePerDomain, includeMechanismMeaningsPerDomain);
                try { var opts = providerHelp ?? new ProviderHelpRenderOptions(); if (opts.ShowUnderSpf) { var help = bucket.Mx?.ProviderHelp ?? bucket.Spf?.ProviderHelp; if (help != null && help.Count > 0) ProviderHelpWordSectionWriter.Write(doc, headings, 2, help, opts); } } catch { }
            }

            if (bucket.Dkim.Count > 0) {
                headings.AddItem("DKIM", 1);
                DkimWordSectionWriter.Write(doc, headings, 2, bucket.Dkim, domain, scope, showInfoFindings, includeNarrativePerDomain);
                try { var opts = providerHelp ?? new ProviderHelpRenderOptions(); if (opts.ShowUnderDkim) { var help = bucket.Mx?.ProviderHelp ?? bucket.Spf?.ProviderHelp; if (help != null && help.Count > 0) ProviderHelpWordSectionWriter.Write(doc, headings, 2, help, opts); } } catch { }
            }

            if (bucket.Dmarc != null) {
                headings.AddItem("DMARC", 1);
                DmarcWordSectionWriter.Write(doc, headings, 2, bucket.Dmarc, domain, scope, showInfoFindings, includeNarrativePerDomain);
                try { var opts = providerHelp ?? new ProviderHelpRenderOptions(); if (opts.ShowUnderDmarc) { var help = bucket.Mx?.ProviderHelp ?? bucket.Spf?.ProviderHelp; if (help != null && help.Count > 0) ProviderHelpWordSectionWriter.Write(doc, headings, 2, help, opts); } } catch { }
            }

            if (bucket.Arc != null) {
                headings.AddItem("ARC", 1);
                ArcWordSectionWriter.Write(doc, headings, 2, bucket.Arc, domain, scope, showInfoFindings, includeNarrativePerDomain);
                try { var opts = providerHelp ?? new ProviderHelpRenderOptions(); if (opts.ShowUnderArc) { var help = bucket.Mx?.ProviderHelp ?? bucket.Spf?.ProviderHelp; if (help != null && help.Count > 0) ProviderHelpWordSectionWriter.Write(doc, headings, 2, help, opts); } } catch { }
            }

            if (bucket.Bimi != null) {
                headings.AddItem("BIMI", 1);
                BimiWordSectionWriter.Write(doc, headings, 2, bucket.Bimi, domain, scope, showInfoFindings, includeNarrativePerDomain);
                try { var opts = providerHelp ?? new ProviderHelpRenderOptions(); if (opts.ShowUnderBimi) { var help = bucket.Mx?.ProviderHelp ?? bucket.Spf?.ProviderHelp; if (help != null && help.Count > 0) ProviderHelpWordSectionWriter.Write(doc, headings, 2, help, opts); } } catch { }
            }

            if (bucket.Dnsbl != null) {
                headings.AddItem("DNSBL", 1);
                DnsblWordSectionWriter.Write(doc, headings, 2, bucket.Dnsbl, domain, scope, showInfoFindings);
            }
            if (bucket.Rpki != null) {
                headings.AddItem("RPKI", 1);
                RpkiWordSectionWriter.Write(doc, headings, 2, bucket.Rpki, domain, scope, showInfoFindings);
            }
            if (bucket.Ns != null) {
                headings.AddItem("NS", 1);
                NsWordSectionWriter.Write(doc, headings, 2, bucket.Ns, domain, scope, showInfoFindings);
            }
            if (bucket.Soa != null) {
                headings.AddItem("SOA", 1);
                SoaWordSectionWriter.Write(doc, headings, 2, bucket.Soa, domain, scope, showInfoFindings);
            }
            if (bucket.ZoneTransfer != null) {
                headings.AddItem("Zone Transfer", 1);
                ZoneTransferWordSectionWriter.Write(doc, headings, 2, bucket.ZoneTransfer, domain, scope, showInfoFindings);
            }
            if (bucket.Wildcard != null) {
                headings.AddItem("Wildcard DNS", 1);
                WildcardWordSectionWriter.Write(doc, headings, 2, bucket.Wildcard, domain, scope, showInfoFindings);
            }
            if (bucket.Caa != null) {
                headings.AddItem("CAA", 1);
                CaaWordSectionWriter.Write(doc, headings, 2, bucket.Caa, domain, scope, showInfoFindings);
            }

            if (bucket.Classification != null) {
                headings.AddItem("Mail Classification", 1);
                MailClassificationWordSectionWriter.Write(doc, headings, 2, bucket.Classification, domain, scope, showInfoFindings);
            }

            if (bucket.Mtasts != null) {
                headings.AddItem("MTA-STS", 1);
                MtastsWordSectionWriter.Write(doc, headings, 2, bucket.Mtasts, domain, scope, showInfoFindings, includeNarrativePerDomain);
            }
            if (bucket.TlsRpt != null) {
                headings.AddItem("TLS-RPT", 1);
                TlsRptWordSectionWriter.Write(doc, headings, 2, bucket.TlsRpt, domain, scope, showInfoFindings, includeNarrativePerDomain);
            }
            if (bucket.Dnssec != null) {
                headings.AddItem("DNSSEC", 1);
                DnssecWordSectionWriter.Write(doc, headings, 2, bucket.Dnssec, domain, scope, showInfoFindings, includeNarrativePerDomain);
            }
            if (bucket.Dane != null) {
                headings.AddItem("DANE", 1);
                DaneWordSectionWriter.Write(doc, headings, 2, bucket.Dane, domain, scope, showInfoFindings, includeNarrativePerDomain);
            }
        }

        // Consolidated Recommendations (grouped across all domains)
        try {
            var allAssessments = new System.Collections.Generic.List<DomainDetective.Assessment>();
            foreach (var kv in allRows) {
                var b = kv.Value;
                void PullAssessments(System.Collections.Generic.IReadOnlyList<DomainDetective.Assessment>? a) { if (a != null && a.Count > 0) allAssessments.AddRange(a); }
                PullAssessments(b.Spf?.Assessments);
                foreach (var d in b.Dkim) PullAssessments(d.Assessments);
                PullAssessments(b.Dmarc?.Assessments);
                PullAssessments(b.Mx?.Assessments);
                PullAssessments(b.Mtasts?.Assessments);
                PullAssessments(b.TlsRpt?.Assessments);
                PullAssessments(b.Dnsbl?.Assessments);
                PullAssessments(b.Ns?.Assessments);
                PullAssessments(b.Soa?.Assessments);
                PullAssessments(b.ZoneTransfer?.Assessments);
                PullAssessments(b.Wildcard?.Assessments);
                PullAssessments(b.Dnssec?.Assessments);
                PullAssessments(b.Dane?.Assessments);
                PullAssessments(b.SmtpTls?.Assessments);
                PullAssessments(b.ImapTls?.Assessments);
                PullAssessments(b.PopTls?.Assessments);
            }
            var recGroups = DomainDetective.RecommendationEngine.GroupByCode(allAssessments);
            var negative = recGroups.Where(g => g.MaxSeverity != DomainDetective.AssessmentSeverity.Info).ToList();
            if (negative.Count > 0) {
                headings.AddItem("Consolidated Recommendations");
                doc.AddParagraph("Actions to improve posture across all analyzed domains. Recommendations are grouped to avoid duplicates.");
                var rt = doc.AddTable(negative.Count + 1, 5, WordTableStyle.TableGrid);
                var rc0 = rt.Rows[0].Cells; int hc = Math.Min(5, rc0.Count);
                if (hc > 0) rc0[0].AddParagraph("Severity");
                if (hc > 1) rc0[1].AddParagraph("Code");
                if (hc > 2) rc0[2].AddParagraph("Title");
                if (hc > 3) rc0[3].AddParagraph("How");
                if (hc > 4) rc0[4].AddParagraph("Domains");
                for (int i = 0; i < negative.Count; i++) {
                    var g = negative[i];
                    var rc = rt.Rows[i + 1].Cells; int cc = Math.Min(5, rc.Count);
                    if (cc > 0) rc[0].AddParagraph(g.MaxSeverity.ToString());
                    if (cc > 1) rc[1].AddParagraph(g.Code ?? string.Empty);
                    if (cc > 2) rc[2].AddParagraph(g.Advice?.Title ?? string.Empty);
                    if (cc > 3) rc[3].AddParagraph(g.Advice?.How ?? string.Empty);
                    // Domains column: cap to N and append +N more
                    const int maxDomains = 6;
                    string domainsText = string.Empty;
                    if (g.Targets != null && g.Targets.Count > 0) {
                        var shown = g.Targets.Take(maxDomains).ToList();
                        int extra = g.Targets.Count - shown.Count;
                        domainsText = string.Join(", ", shown);
                        if (extra > 0) domainsText += $" +{extra} more";
                    }
                    if (cc > 4) rc[4].AddParagraph(domainsText);
                }
            }

            // Consolidated Positives (Info-level)
            var positives = recGroups.Where(g => g.MaxSeverity == DomainDetective.AssessmentSeverity.Info).ToList();
            if (positives.Count > 0) {
                headings.AddItem("Consolidated Positives");
                doc.AddParagraph("Positive posture signals observed across domains.");
                var pt = doc.AddTable(positives.Count + 1, 3, WordTableStyle.TableGrid);
                var p0 = pt.Rows[0].Cells; int phc = Math.Min(3, p0.Count);
                if (phc > 0) p0[0].AddParagraph("Code");
                if (phc > 1) p0[1].AddParagraph("Title");
                if (phc > 2) p0[2].AddParagraph("Targets");
                for (int i = 0; i < positives.Count; i++) {
                    var g = positives[i];
                    var rc = pt.Rows[i + 1].Cells; int cc = Math.Min(3, rc.Count);
                    if (cc > 0) rc[0].AddParagraph(g.Code ?? string.Empty);
                    if (cc > 1) rc[1].AddParagraph(g.Advice?.Title ?? string.Empty);
                    var targets = (g.Targets != null && g.Targets.Count > 0) ? string.Join(", ", g.Targets) : string.Empty;
                    if (cc > 2) rc[2].AddParagraph(targets);
                }
            }

            // Consolidated References (deduped)
            var allRefs = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in allRows) {
                var b = kv.Value;
                void PullRefs(System.Collections.Generic.IReadOnlyList<string>? r) { if (r != null) foreach (var x in r) if (!string.IsNullOrWhiteSpace(x)) allRefs.Add(x); }
                PullRefs(b.Spf?.References);
                foreach (var d in b.Dkim) PullRefs(d.References);
                PullRefs(b.Dmarc?.References);
                PullRefs(b.Mx?.References);
                PullRefs(b.Mtasts?.References);
                PullRefs(b.TlsRpt?.References);
                PullRefs(b.Dnsbl?.References);
                PullRefs(b.Rpki?.References);
                PullRefs(b.Ns?.References);
                PullRefs(b.Soa?.References);
                PullRefs(b.ZoneTransfer?.References);
                PullRefs(b.Wildcard?.References);
                PullRefs(b.Dnssec?.References);
                PullRefs(b.Dane?.References);
                PullRefs(b.Caa?.References);
                PullRefs(b.SmtpTls?.References);
                PullRefs(b.ImapTls?.References);
                PullRefs(b.PopTls?.References);
                PullRefs(b.Classification?.References);
            }
            if (allRefs.Count > 0) {
                headings.AddItem("All References");
                doc.AddParagraph("References cited across all sections. Use these for standards and implementation guidance.");
                var list = doc.AddList(WordListStyle.Bulleted);
                foreach (var r in allRefs.OrderBy(x => x, StringComparer.OrdinalIgnoreCase)) list.AddItem(r);
            }
        } catch { }

        doc.Save();
    }

    private static Dictionary<string, Dictionary<HealthCheckType, (string Status, int Warn, int Err)>> AggregateExtras(IReadOnlyList<object> items, HashSet<HealthCheckType> covered) {
        var map = new Dictionary<string, Dictionary<HealthCheckType, (string, int, int)>>(StringComparer.OrdinalIgnoreCase);
        void Acc(string subject, HealthCheckType check, string status, int warn, int err) {
            if (!map.TryGetValue(subject ?? string.Empty, out var byCheck)) {
                byCheck = new Dictionary<HealthCheckType, (string, int, int)>();
                map[subject ?? string.Empty] = byCheck;
            }
            if (byCheck.TryGetValue(check, out var cur)) {
                var nextStatus = MaxStatus(cur.Item1, status);
                byCheck[check] = (nextStatus, cur.Item2 + warn, cur.Item3 + err);
            } else {
                byCheck[check] = (status, warn, err);
            }
        }

        foreach (var raw in items ?? Array.Empty<object>()) {
            foreach (var it in EnumeratePossiblyNested(raw)) {
                var t = it.GetType();
                var checkProp = t.GetProperty("Check");
                var subjProp = t.GetProperty("Subject");
                var statusProp = t.GetProperty("Status");
                var warnProp = t.GetProperty("WarningCount");
                var errProp = t.GetProperty("ErrorCount");
                if (checkProp == null || subjProp == null || statusProp == null || warnProp == null || errProp == null) continue;
                if (checkProp.GetValue(it) is not HealthCheckType check) continue;
                if (covered.Contains(check)) continue;
                var subject = subjProp.GetValue(it) as string ?? string.Empty;
                var status = statusProp.GetValue(it) as string ?? "";
                var warn = warnProp.GetValue(it) as int? ?? 0;
                var err = errProp.GetValue(it) as int? ?? 0;
                Acc(subject, check, status, warn, err);
            }
        }
        return map;
    }

    private static IEnumerable<object> EnumeratePossiblyNested(object o) {
        if (o is System.Collections.IEnumerable seq && o is not string) {
            foreach (var e in seq) if (e != null) yield return e;
        } else {
            yield return o;
        }
    }

    private static string MaxStatus(string a, string b) {
        int Rank(string s) => string.Equals(s, "Error", StringComparison.OrdinalIgnoreCase) ? 3
            : string.Equals(s, "Warning", StringComparison.OrdinalIgnoreCase) ? 2
            : string.Equals(s, "OK", StringComparison.OrdinalIgnoreCase) ? 1
            : 0;
        return Rank(a) >= Rank(b) ? a : b;
    }

    private static string BuildSubjectTitle(List<string> domains) {
        if (domains.Count == 1) return domains[0];
        if (domains.Count == 2) return $"{domains[0]}+{domains[1]}";
        return $"{domains[0]}+{domains[1]}(+{domains.Count - 2})";
    }

    /// <summary>Internal grouping container for per-domain section data.</summary>
    private sealed class DomainBucket {
        public string Subject { get; set; } = string.Empty;
        public DomainDetective.Views.MxInfo? Mx { get; set; }
        public DomainDetective.Views.SpfRecordInfo? Spf { get; set; }
        public DomainDetective.Views.DmarcRecordInfo? Dmarc { get; set; }
        public List<DomainDetective.Views.DkimRecordInfo> Dkim { get; } = new();
        public DomainDetective.Views.ArcInfo? Arc { get; set; }
        public DomainDetective.Views.BimiRecordInfo? Bimi { get; set; }
        public DomainDetective.Views.DnsblInfo? Dnsbl { get; set; }
        public DomainDetective.Views.CaaInfo? Caa { get; set; }
        public DomainDetective.Views.RpkiInfo? Rpki { get; set; }
        public DomainDetective.Views.NsInfo? Ns { get; set; }
        public DomainDetective.Views.SoaInfo? Soa { get; set; }
        public DomainDetective.Views.ZoneTransferInfo? ZoneTransfer { get; set; }
        public DomainDetective.Views.WildcardDnsInfo? Wildcard { get; set; }
        public DomainDetective.Views.MailClassificationInfo? Classification { get; set; }
        public DomainDetective.Views.MtastsInfo? Mtasts { get; set; }
        public DomainDetective.Views.TlsRptInfo? TlsRpt { get; set; }
        public DomainDetective.Views.DnssecStatusInfo? Dnssec { get; set; }
        public DomainDetective.Views.DaneRecordInfo? Dane { get; set; }
        // Mail TLS (per protocol) for rollup column
        public DomainDetective.Views.MailTlsInfo? SmtpTls { get; set; }
        public DomainDetective.Views.MailTlsInfo? ImapTls { get; set; }
        public DomainDetective.Views.MailTlsInfo? PopTls { get; set; }
    }

    private static string ComposeDkimStatus(List<DomainDetective.Views.DkimRecordInfo> dkim, bool showCount) {
        if (dkim == null || dkim.Count == 0) return "-";
        int err = dkim.Sum(x => x?.ErrorCount ?? 0);
        int warn = dkim.Sum(x => x?.WarningCount ?? 0);
        string core = err > 0 ? "Error" : (warn > 0 ? "Warning" : "OK");
        if (showCount) {
            int n = dkim.Count;
            core += $" ({n} selector{(n == 1 ? string.Empty : "s")})";
        }
        return core;
    }

    private static string ComposeMailTlsStatus(DomainBucket b, bool showProto) {
        // Prefer SMTP, else IMAP, else POP. If none present, "-".
        if (b.SmtpTls != null) {
            var s = b.SmtpTls.Status ?? "-";
            return showProto && s != "-" ? $"{s} (SMTP)" : s;
        }
        if (b.ImapTls != null) {
            var s = b.ImapTls.Status ?? "-";
            return showProto && s != "-" ? $"{s} (IMAP)" : s;
        }
        if (b.PopTls != null) {
            var s = b.PopTls.Status ?? "-";
            return showProto && s != "-" ? $"{s} (POP)" : s;
        }
        return "-";
    }

    private static string ComposeDnssecStatus(DomainBucket b) {
        var ds = b.Dnssec;
        if (ds == null) return "-";
        var parts = new List<string>();
        parts.Add(ds.ChainValid ? "chain=valid" : "chain=invalid");
        parts.Add(ds.DsMatch ? "ds=match" : "ds=check");
        if (ds.RootAnchorExpiration.HasValue) {
            var days = (int)Math.Ceiling((ds.RootAnchorExpiration.Value - DateTimeOffset.UtcNow).TotalDays);
            parts.Add(days > 0 ? $"root={days}d" : "root=expired");
        }
        return string.Join("; ", parts);
    }

    private static string ComposeRpkiStatus(DomainBucket b) {
        var r = b.Rpki;
        if (r == null) return "-";
        if (r.TotalChecked <= 0) return "-";
        var core = (r.ValidCount == r.TotalChecked) ? "All valid" : (r.ValidCount > 0 ? "Partial" : "None valid");
        return $"{core} ({r.ValidCount}/{r.TotalChecked})";
    }

    private static Dictionary<string, DomainBucket> GroupBySubject(IReadOnlyList<object> items) {
        var map = new Dictionary<string, DomainBucket>(StringComparer.OrdinalIgnoreCase);
        void Ensure(string subject) {
            if (!map.ContainsKey(subject)) map[subject] = new DomainBucket { Subject = subject };
        }

        foreach (var it in items) {
            switch (it) {
                case DomainDetective.Views.MxInfo mx when !string.IsNullOrWhiteSpace(mx.Subject):
                    Ensure(mx.Subject); map[mx.Subject].Mx = mx; break;
                case DomainDetective.Views.SpfRecordInfo spf when !string.IsNullOrWhiteSpace(spf.Subject):
                    Ensure(spf.Subject); map[spf.Subject].Spf = spf; break;
                case DomainDetective.Views.DmarcRecordInfo dmarc when !string.IsNullOrWhiteSpace(dmarc.Subject):
                    Ensure(dmarc.Subject); map[dmarc.Subject].Dmarc = dmarc; break;
                case DomainDetective.Views.DkimRecordInfo dkim when !string.IsNullOrWhiteSpace(dkim.Subject):
                    Ensure(dkim.Subject); map[dkim.Subject].Dkim.Add(dkim); break;
                case DomainDetective.Views.ArcInfo arc when !string.IsNullOrWhiteSpace(arc.Subject):
                    Ensure(arc.Subject); map[arc.Subject].Arc = arc; break;
                case DomainDetective.Views.BimiRecordInfo bimi when !string.IsNullOrWhiteSpace(bimi.Subject):
                    Ensure(bimi.Subject); map[bimi.Subject].Bimi = bimi; break;
                case DomainDetective.Views.DnsblInfo dnsbl when !string.IsNullOrWhiteSpace(dnsbl.Subject):
                    Ensure(dnsbl.Subject); map[dnsbl.Subject].Dnsbl = dnsbl; break;
                case DomainDetective.Views.RpkiInfo rpki when !string.IsNullOrWhiteSpace(rpki.Subject):
                    Ensure(rpki.Subject); map[rpki.Subject].Rpki = rpki; break;
                case DomainDetective.Views.CaaInfo caa when !string.IsNullOrWhiteSpace(caa.Subject):
                    Ensure(caa.Subject); map[caa.Subject].Caa = caa; break;
                case DomainDetective.Views.NsInfo ns when !string.IsNullOrWhiteSpace(ns.Subject):
                    Ensure(ns.Subject); map[ns.Subject].Ns = ns; break;
                case DomainDetective.Views.SoaInfo soa when !string.IsNullOrWhiteSpace(soa.Subject):
                    Ensure(soa.Subject); map[soa.Subject].Soa = soa; break;
                case DomainDetective.Views.ZoneTransferInfo zt when !string.IsNullOrWhiteSpace(zt.Subject):
                    Ensure(zt.Subject); map[zt.Subject].ZoneTransfer = zt; break;
                case DomainDetective.Views.WildcardDnsInfo wc when !string.IsNullOrWhiteSpace(wc.Subject):
                    Ensure(wc.Subject); map[wc.Subject].Wildcard = wc; break;
                case DomainDetective.Views.MailClassificationInfo mc when !string.IsNullOrWhiteSpace(mc.Subject):
                    Ensure(mc.Subject); map[mc.Subject].Classification = mc; break;
                case DomainDetective.Views.MtastsInfo ms when !string.IsNullOrWhiteSpace(ms.Subject):
                    Ensure(ms.Subject); map[ms.Subject].Mtasts = ms; break;
                case DomainDetective.Views.TlsRptInfo tr when !string.IsNullOrWhiteSpace(tr.Subject):
                    Ensure(tr.Subject); map[tr.Subject].TlsRpt = tr; break;
                case DomainDetective.Views.DnssecStatusInfo ds when !string.IsNullOrWhiteSpace(ds.Subject):
                    Ensure(ds.Subject); map[ds.Subject].Dnssec = ds; break;
                case DomainDetective.Views.DaneRecordInfo dn when !string.IsNullOrWhiteSpace(dn.Subject):
                    Ensure(dn.Subject); map[dn.Subject].Dane = dn; break;
                case DomainDetective.Views.MailTlsInfo mt when !string.IsNullOrWhiteSpace(mt.Subject):
                    Ensure(mt.Subject);
                    switch (mt.Check) {
                        case HealthCheckType.SMTPTLS: map[mt.Subject].SmtpTls = mt; break;
                        case HealthCheckType.IMAPTLS: map[mt.Subject].ImapTls = mt; break;
                        case HealthCheckType.POP3TLS: map[mt.Subject].PopTls = mt; break;
                        default: break;
                    }
                    break;
                default:
                    break;
            }
        }
        return map;
    }
}
