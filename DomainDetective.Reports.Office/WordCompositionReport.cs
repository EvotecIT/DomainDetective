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
public static class WordCompositionReport
{
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
        string? watermarkText = null)
    {
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
            $"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}", logoPath, watermarkText);
        WordReportCommon.AddFooter(doc); // left defaults to CompanyLine when present

        var headings = doc.AddTableOfContentList(WordListStyle.Headings111);
        headings.AddItem("Executive Summary");
        headings.AddItem("Overview", 1);
        // Compute totals across domains (MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT)
        int totalWarns = 0, totalErrs = 0;
        foreach (var kv in grouped)
        {
            var bucket = kv.Value;
            totalWarns += (bucket.Spf?.WarningCount ?? 0)
                        + (bucket.Dmarc?.WarningCount ?? 0)
                        + (bucket.Dkim?.Sum(x => x.WarningCount) ?? 0)
                        + (bucket.Mtasts?.WarningCount ?? 0)
                        + (bucket.TlsRpt?.WarningCount ?? 0)
                        + (bucket.Mx?.WarningCount ?? 0);
            totalErrs  += (bucket.Spf?.ErrorCount   ?? 0)
                        + (bucket.Dmarc?.ErrorCount   ?? 0)
                        + (bucket.Dkim?.Sum(x => x.ErrorCount) ?? 0)
                        + (bucket.Mtasts?.ErrorCount ?? 0)
                        + (bucket.TlsRpt?.ErrorCount ?? 0)
                        + (bucket.Mx?.ErrorCount ?? 0);
        }
        // Executive Summary intro text
        doc.AddParagraph($"This report summarizes the email security posture for {grouped.Count} domain(s). The table highlights the presence and status of key controls (MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT) and the count of warnings/errors detected. Total across all domains: {totalWarns} warning(s), {totalErrs} error(s).");

        // Executive Summary table (defensive build to avoid style-dependent index issues)
        var allRows = grouped.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase).ToList();
        try
        {
            string[] hdrs = new[] { "Domain", "MX", "SPF", "DKIM", "DMARC", "MTA-STS", "TLS-RPT", "Findings (W/E)" };
            var sum = doc.AddTable(allRows.Count + 1, hdrs.Length, WordTableStyle.TableGrid);
            for (int c = 0; c < hdrs.Length; c++)
            {
                // Use AddParagraph defensively to avoid empty Paragraphs collection edge cases
                sum.Rows[0].Cells[c].AddParagraph(hdrs[c]);
            }
            for (int i = 0; i < allRows.Count; i++)
            {
                var (domain, bucket) = (allRows[i].Key, allRows[i].Value);
                var spf = bucket.Spf; var dmarc = bucket.Dmarc; var dkim = bucket.Dkim; var mx = bucket.Mx; var mtasts = bucket.Mtasts; var tlsrpt = bucket.TlsRpt;
                int warns = (spf?.WarningCount ?? 0) + (dmarc?.WarningCount ?? 0) + dkim.Sum(x => x.WarningCount) + (mtasts?.WarningCount ?? 0) + (tlsrpt?.WarningCount ?? 0) + (mx?.WarningCount ?? 0);
                int errs  = (spf?.ErrorCount   ?? 0) + (dmarc?.ErrorCount   ?? 0) + dkim.Sum(x => x.ErrorCount)   + (mtasts?.ErrorCount ?? 0) + (tlsrpt?.ErrorCount ?? 0) + (mx?.ErrorCount ?? 0);
                var cells = sum.Rows[i + 1].Cells;
                cells[0].AddParagraph(domain);
                cells[1].AddParagraph(mx?.Status ?? "-");
                cells[2].AddParagraph(spf?.Status ?? "-");
                cells[3].AddParagraph(dkim.Count > 0 ? (dkim.Max(x => x.Status) ?? "-") : "-");
                cells[4].AddParagraph(dmarc?.Status ?? "-");
                cells[5].AddParagraph(bucket.Mtasts?.Status ?? "-");
                cells[6].AddParagraph(bucket.TlsRpt?.Status ?? "-");
                cells[7].AddParagraph($"{warns} / {errs}");
            }
        }
        catch { /* skip summary on edge cases */ }

        // Background narratives (global) when requested
        bool multiDomain = allRows.Count > 1;
        bool placeGlobal = narrativePlacement == NarrativePlacement.Global || (narrativePlacement == NarrativePlacement.Auto && multiDomain);
        bool includeNarrativePerDomain = narrativePlacement == NarrativePlacement.PerDomain || (narrativePlacement == NarrativePlacement.Auto && !multiDomain);
        bool includeMechanismMeaningsPerDomain = includeNarrativePerDomain; // meanings go with narratives when per-domain
        if (placeGlobal)
        {
            BackgroundWordSectionWriter.Write(doc, headings, 1, items);
        }

        // Per-domain sections
        bool firstDomain = true;
        foreach (var kv in allRows)
        {
            var domain = kv.Key;
            var bucket = kv.Value;
            if (!firstDomain) doc.AddPageBreak();
            firstDomain = false;
            headings.AddItem(domain);

            if (bucket.Mx != null)
            {
                headings.AddItem("MX", 1);
                MxWordSectionWriter.Write(doc, headings, 2, bucket.Mx, domain, scope, showInfoFindings, includeNarrativePerDomain);
            }

            if (bucket.Spf != null)
            {
                headings.AddItem("SPF", 1);
                // Base level 2 under the 'SPF' node: 0=domain, 1=SPF, 2=subsections
                SpfWordSectionWriter.Write(doc, headings, 2, bucket.Spf, domain, scope, showInfoFindings, includeNarrativePerDomain, includeMechanismMeaningsPerDomain);
            }

            if (bucket.Dkim.Count > 0)
            {
                headings.AddItem("DKIM", 1);
                DkimWordSectionWriter.Write(doc, headings, 2, bucket.Dkim, domain, scope, showInfoFindings, includeNarrativePerDomain);
            }

            if (bucket.Dmarc != null)
            {
                headings.AddItem("DMARC", 1);
                DmarcWordSectionWriter.Write(doc, headings, 2, bucket.Dmarc, domain, scope, showInfoFindings, includeNarrativePerDomain);
            }

            if (bucket.Dnsbl != null)
            {
                headings.AddItem("DNSBL", 1);
                DnsblWordSectionWriter.Write(doc, headings, 2, bucket.Dnsbl, domain, scope, showInfoFindings);
            }

            if (bucket.Classification != null)
            {
                headings.AddItem("Mail Classification", 1);
                MailClassificationWordSectionWriter.Write(doc, headings, 2, bucket.Classification, domain, scope, showInfoFindings);
            }

            if (bucket.Mtasts != null)
            {
                headings.AddItem("MTA-STS", 1);
                MtastsWordSectionWriter.Write(doc, headings, 2, bucket.Mtasts, domain, scope, showInfoFindings, includeNarrativePerDomain);
            }
            if (bucket.TlsRpt != null)
            {
                headings.AddItem("TLS-RPT", 1);
                TlsRptWordSectionWriter.Write(doc, headings, 2, bucket.TlsRpt, domain, scope, showInfoFindings, includeNarrativePerDomain);
            }
        }

        // Consolidated Recommendations (grouped across all domains)
        try
        {
            var allAssessments = new System.Collections.Generic.List<DomainDetective.Assessment>();
            foreach (var kv in allRows)
            {
                var b = kv.Value;
                void PullAssessments(System.Collections.Generic.IReadOnlyList<DomainDetective.Assessment>? a)
                { if (a != null && a.Count > 0) allAssessments.AddRange(a); }
                PullAssessments(b.Spf?.Assessments);
                foreach (var d in b.Dkim) PullAssessments(d.Assessments);
                PullAssessments(b.Dmarc?.Assessments);
                PullAssessments(b.Mx?.Assessments);
                PullAssessments(b.Mtasts?.Assessments);
                PullAssessments(b.TlsRpt?.Assessments);
                PullAssessments(b.Dnsbl?.Assessments);
            }
            var recGroups = DomainDetective.RecommendationEngine.GroupByCode(allAssessments);
            var negative = recGroups.Where(g => g.MaxSeverity != DomainDetective.AssessmentSeverity.Info).ToList();
            if (negative.Count > 0)
            {
                headings.AddItem("Consolidated Recommendations");
                doc.AddParagraph("Actions to improve posture across all analyzed domains. Recommendations are grouped to avoid duplicates.");
                var rt = doc.AddTable(negative.Count + 1, 5, WordTableStyle.TableGrid);
                rt.Rows[0].Cells[0].AddParagraph("Severity");
                rt.Rows[0].Cells[1].AddParagraph("Code");
                rt.Rows[0].Cells[2].AddParagraph("Title");
                rt.Rows[0].Cells[3].AddParagraph("How");
                rt.Rows[0].Cells[4].AddParagraph("Domains");
                for (int i = 0; i < negative.Count; i++)
                {
                    var g = negative[i];
                    rt.Rows[i + 1].Cells[0].AddParagraph(g.MaxSeverity.ToString());
                    rt.Rows[i + 1].Cells[1].AddParagraph(g.Code ?? string.Empty);
                    rt.Rows[i + 1].Cells[2].AddParagraph(g.Advice?.Title ?? string.Empty);
                    rt.Rows[i + 1].Cells[3].AddParagraph(g.Advice?.How ?? string.Empty);
                    // Domains column: cap to N and append +N more
                    const int maxDomains = 6;
                    string domainsText = string.Empty;
                    if (g.Targets != null && g.Targets.Count > 0)
                    {
                        var shown = g.Targets.Take(maxDomains).ToList();
                        int extra = g.Targets.Count - shown.Count;
                        domainsText = string.Join(", ", shown);
                        if (extra > 0) domainsText += $" +{extra} more";
                    }
                    rt.Rows[i + 1].Cells[4].AddParagraph(domainsText);
                }
            }

            // Consolidated Positives (Info-level)
            var positives = recGroups.Where(g => g.MaxSeverity == DomainDetective.AssessmentSeverity.Info).ToList();
            if (positives.Count > 0)
            {
                headings.AddItem("Consolidated Positives");
                doc.AddParagraph("Positive posture signals observed across domains.");
                var pt = doc.AddTable(positives.Count + 1, 3, WordTableStyle.TableGrid);
                pt.Rows[0].Cells[0].AddParagraph("Code");
                pt.Rows[0].Cells[1].AddParagraph("Title");
                pt.Rows[0].Cells[2].AddParagraph("Targets");
                for (int i = 0; i < positives.Count; i++)
                {
                    var g = positives[i];
                    pt.Rows[i + 1].Cells[0].AddParagraph(g.Code ?? string.Empty);
                    pt.Rows[i + 1].Cells[1].AddParagraph(g.Advice?.Title ?? string.Empty);
                    var targets = (g.Targets != null && g.Targets.Count > 0) ? string.Join(", ", g.Targets) : string.Empty;
                    pt.Rows[i + 1].Cells[2].AddParagraph(targets);
                }
            }

            // Consolidated References (deduped)
            var allRefs = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in allRows)
            {
                var b = kv.Value;
                void PullRefs(System.Collections.Generic.IReadOnlyList<string>? r)
                { if (r != null) foreach (var x in r) if (!string.IsNullOrWhiteSpace(x)) allRefs.Add(x); }
                PullRefs(b.Spf?.References);
                foreach (var d in b.Dkim) PullRefs(d.References);
                PullRefs(b.Dmarc?.References);
                PullRefs(b.Mx?.References);
                PullRefs(b.Mtasts?.References);
                PullRefs(b.TlsRpt?.References);
                PullRefs(b.Dnsbl?.References);
                PullRefs(b.Classification?.References);
            }
            if (allRefs.Count > 0)
            {
                headings.AddItem("All References");
                doc.AddParagraph("References cited across all sections. Use these for standards and implementation guidance.");
                var list = doc.AddList(WordListStyle.Bulleted);
                foreach (var r in allRefs.OrderBy(x => x, StringComparer.OrdinalIgnoreCase)) list.AddItem(r);
            }
        }
        catch { }

        doc.Save();
    }

    private static string BuildSubjectTitle(List<string> domains)
    {
        if (domains.Count == 1) return domains[0];
        if (domains.Count == 2) return $"{domains[0]}+{domains[1]}";
        return $"{domains[0]}+{domains[1]}(+{domains.Count - 2})";
    }

    /// <summary>Internal grouping container for per-domain section data.</summary>
    private sealed class DomainBucket
    {
        public string Subject { get; set; } = string.Empty;
        public DomainDetective.Views.MxInfo? Mx { get; set; }
        public DomainDetective.Views.SpfRecordInfo? Spf { get; set; }
        public DomainDetective.Views.DmarcRecordInfo? Dmarc { get; set; }
        public List<DomainDetective.Views.DkimRecordInfo> Dkim { get; } = new();
        public DomainDetective.Views.DnsblInfo? Dnsbl { get; set; }
        public DomainDetective.Views.MailClassificationInfo? Classification { get; set; }
        public DomainDetective.Views.MtastsInfo? Mtasts { get; set; }
        public DomainDetective.Views.TlsRptInfo? TlsRpt { get; set; }
    }

    private static Dictionary<string, DomainBucket> GroupBySubject(IReadOnlyList<object> items)
    {
        var map = new Dictionary<string, DomainBucket>(StringComparer.OrdinalIgnoreCase);
        void Ensure(string subject)
        {
            if (!map.ContainsKey(subject)) map[subject] = new DomainBucket { Subject = subject };
        }

        foreach (var it in items)
        {
            switch (it)
            {
                case DomainDetective.Views.MxInfo mx when !string.IsNullOrWhiteSpace(mx.Subject):
                    Ensure(mx.Subject); map[mx.Subject].Mx = mx; break;
                case DomainDetective.Views.SpfRecordInfo spf when !string.IsNullOrWhiteSpace(spf.Subject):
                    Ensure(spf.Subject); map[spf.Subject].Spf = spf; break;
                case DomainDetective.Views.DmarcRecordInfo dmarc when !string.IsNullOrWhiteSpace(dmarc.Subject):
                    Ensure(dmarc.Subject); map[dmarc.Subject].Dmarc = dmarc; break;
                case DomainDetective.Views.DkimRecordInfo dkim when !string.IsNullOrWhiteSpace(dkim.Subject):
                    Ensure(dkim.Subject); map[dkim.Subject].Dkim.Add(dkim); break;
                case DomainDetective.Views.DnsblInfo dnsbl when !string.IsNullOrWhiteSpace(dnsbl.Subject):
                    Ensure(dnsbl.Subject); map[dnsbl.Subject].Dnsbl = dnsbl; break;
                case DomainDetective.Views.MailClassificationInfo mc when !string.IsNullOrWhiteSpace(mc.Subject):
                    Ensure(mc.Subject); map[mc.Subject].Classification = mc; break;
                case DomainDetective.Views.MtastsInfo ms when !string.IsNullOrWhiteSpace(ms.Subject):
                    Ensure(ms.Subject); map[ms.Subject].Mtasts = ms; break;
                case DomainDetective.Views.TlsRptInfo tr when !string.IsNullOrWhiteSpace(tr.Subject):
                    Ensure(tr.Subject); map[tr.Subject].TlsRpt = tr; break;
                default:
                    break;
            }
        }
        return map;
    }
}
