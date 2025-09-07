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
        string? titleOverride = null,
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
        WordReportCommon.ApplyBuiltInProperties(doc, title, "Custom Composition", "Email Security", "Security", "DomainDetective");
        WordReportCommon.ApplyCompanyBranding(doc, companyName, companyAddress, companyYear);

        // Cover/TOC/Header
        doc.AddCoverPage(CoverPageTemplate.IonDark);
        doc.AddTableOfContent(TableOfContentStyle.Template1);
        doc.AddPageBreak();
        WordReportCommon.AddHeader(doc, WordReportCommon.ResolveHeaderLeftText(headerText, new { Title = title }, title),
            $"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}", logoPath, watermarkText);

        var headings = doc.AddTableOfContentList(WordListStyle.Headings111);
        headings.AddItem("Executive Summary");

        // Executive Summary table
        var allRows = grouped.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase).ToList();
        var sum = doc.AddTable(allRows.Count + 1, 7, WordTableStyle.TableGrid);
        sum.Rows[0].Cells[0].Paragraphs[0].Text = "Domain";
        sum.Rows[0].Cells[1].Paragraphs[0].Text = "SPF";
        sum.Rows[0].Cells[2].Paragraphs[0].Text = "DKIM";
        sum.Rows[0].Cells[3].Paragraphs[0].Text = "DMARC";
        sum.Rows[0].Cells[4].Paragraphs[0].Text = "MTA-STS";
        sum.Rows[0].Cells[5].Paragraphs[0].Text = "TLS-RPT";
        sum.Rows[0].Cells[6].Paragraphs[0].Text = "Findings (W/E)";
        for (int i = 0; i < allRows.Count; i++)
        {
            var (domain, bucket) = (allRows[i].Key, allRows[i].Value);
            var spf = bucket.Spf; var dmarc = bucket.Dmarc; var dkim = bucket.Dkim;
            sum.Rows[i + 1].Cells[0].Paragraphs[0].Text = domain;
            sum.Rows[i + 1].Cells[1].Paragraphs[0].Text = spf?.Status ?? "-";
            sum.Rows[i + 1].Cells[2].Paragraphs[0].Text = dkim.Count > 0 ? (dkim.Max(x => x.Status) ?? "-") : "-";
            sum.Rows[i + 1].Cells[3].Paragraphs[0].Text = dmarc?.Status ?? "-";
            int warns = (spf?.WarningCount ?? 0) + (dmarc?.WarningCount ?? 0) + dkim.Sum(x => x.WarningCount);
            int errs  = (spf?.ErrorCount   ?? 0) + (dmarc?.ErrorCount   ?? 0) + dkim.Sum(x => x.ErrorCount);
            sum.Rows[i + 1].Cells[4].Paragraphs[0].Text = bucket.Mtasts?.Status ?? "-";
            sum.Rows[i + 1].Cells[5].Paragraphs[0].Text = bucket.TlsRpt?.Status ?? "-";
            sum.Rows[i + 1].Cells[6].Paragraphs[0].Text = $"{warns} / {errs}";
        }

        // Per-domain sections
        foreach (var kv in allRows)
        {
            var domain = kv.Key;
            var bucket = kv.Value;
            headings.AddItem(domain);

            if (bucket.Spf != null)
            {
                headings.AddItem("SPF", 1);
                SpfWordSectionWriter.Write(doc, bucket.Spf, domain, scope, showInfoFindings);
            }

            if (bucket.Dkim.Count > 0)
            {
                headings.AddItem("DKIM", 1);
                DkimWordSectionWriter.Write(doc, bucket.Dkim, domain, scope, showInfoFindings);
            }

            if (bucket.Dmarc != null)
            {
                headings.AddItem("DMARC", 1);
                DmarcWordSectionWriter.Write(doc, bucket.Dmarc, domain, scope, showInfoFindings);
            }

            if (bucket.Dnsbl != null)
            {
                headings.AddItem("DNSBL", 1);
                DnsblWordSectionWriter.Write(doc, bucket.Dnsbl, domain, scope, showInfoFindings);
            }

            if (bucket.Classification != null)
            {
                headings.AddItem("Mail Classification", 1);
                MailClassificationWordSectionWriter.Write(doc, bucket.Classification, domain, scope, showInfoFindings);
            }

            if (bucket.Mtasts != null)
            {
                headings.AddItem("MTA-STS", 1);
                MtastsWordSectionWriter.Write(doc, bucket.Mtasts, domain, scope, showInfoFindings);
            }
            if (bucket.TlsRpt != null)
            {
                headings.AddItem("TLS-RPT", 1);
                TlsRptWordSectionWriter.Write(doc, bucket.TlsRpt, domain, scope, showInfoFindings);
            }
        }

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
