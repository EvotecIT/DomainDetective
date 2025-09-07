using System;
using System.Linq;
using System.Collections.Generic;
using DomainDetective;
using System.IO;
using OfficeIMO.Word;
using DocumentFormat.OpenXml.Wordprocessing;
using DomainDetective.Narratives;

namespace DomainDetective.Reports.Office;

public static class SpfWordReport
{
    public static void Generate(string path, DomainDetective.SpfAnalysis spf, string domain, string? logoPath = null, string? headerText = null, string? footerText = null, string? watermarkText = null, bool showInfoFindings = true, string? companyName = null, string? companyAddress = null, string? companyYear = null)
    {
        using var doc = WordDocument.Create(path);

        // Document settings
        doc.Settings.UpdateFieldsOnOpen = true;

        // Narrative (provides Title/Subtitle/Intro/Why + metadata)
        var nar = SpfNarrative.Build(spf);

        // Built-in properties from narrative (with defaults)
        WordReportCommon.ApplyNarrativeProperties(
            doc,
            narrative: nar,
            defaultTitle: $"SPF Report — {domain}",
            defaultSubject: "SPF Assessment",
            defaultCategory: "Email Security",
            defaultKeywords: $"SPF, email, security, DomainDetective, {domain}",
            defaultCreator: "DomainDetective");

        // Custom properties for company branding
        WordReportCommon.ApplyCompanyBranding(doc, companyName, companyAddress, companyYear);

        // Cover page and table of contents
        doc.AddCoverPage(CoverPageTemplate.IonDark);
        doc.AddTableOfContent(TableOfContentStyle.Template1);
        doc.AddPageBreak();

        // Header & footer with page numbers and branding
        WordReportCommon.AddHeader(
            doc,
            leftText: WordReportCommon.ResolveHeaderLeftText(headerText, nar, $"SPF Report — {domain}"),
            rightText: $"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}",
            logoPath: logoPath,
            watermarkText: watermarkText);
        var footerTable = doc.Footer.Default.AddTable(1, 2, WordTableStyle.TableNormal);
        footerTable.WidthType = TableWidthUnitValues.Pct; // 5000 = 100%
        footerTable.Width = 5000;
        footerTable.Rows[0].Cells[0].AddParagraph(string.IsNullOrWhiteSpace(footerText) ? "Confidential" : footerText);
        var footerRight = footerTable.Rows[0].Cells[1].AddParagraph();
        footerRight.ParagraphAlignment = JustificationValues.Right;
        footerRight.AddPageNumber(includeTotalPages: true, separator: " / ");
        
        // Numbered headings list (TOC-driven)
        var headings = doc.AddTableOfContentList(WordListStyle.Headings111);
        headings.AddItem(string.IsNullOrWhiteSpace(nar.Subtitle) ? $"SPF Assessment for {domain}" : nar.Subtitle);

        // Introduction & Why it matters (business facing)
        headings.AddItem("Introduction", 1);
        doc.AddParagraph(nar.Introduction);
        headings.AddItem("Why this matters", 1);
        doc.AddParagraph(nar.WhyItMatters);

        // 1.1 SPF Section — reuse the section writer
        headings.AddItem("SPF", 1);
        var spfView = DomainDetective.Views.Converters.Convert(spf);
        SpfWordSectionWriter.Write(doc, headings, 2, spfView, domain, Reports.ReportScope.Detailed, showInfoFindings);

        // Lookups
        headings.AddItem("DNS Lookups", 1);
        if (spf.DnsLookups != null && spf.DnsLookups.Count > 0)
        {
            var lookList = doc.AddList(WordListStyle.Bulleted);
            foreach (var l in spf.DnsLookups.Distinct()) lookList.AddItem(l);
        }

        // Resolved ranges (top 10)
        if (spf.ResolvedIpv4Records != null && spf.ResolvedIpv4Records.Count > 0)
        {
            doc.AddParagraph($"Resolved IPv4 ranges ({spf.ResolvedIpv4Records.Count})");
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var cidr in spf.ResolvedIpv4Records.Take(10)) list.AddItem(cidr);
        }
        if (spf.ResolvedIpv6Records != null && spf.ResolvedIpv6Records.Count > 0)
        {
            doc.AddParagraph($"Resolved IPv6 ranges ({spf.ResolvedIpv6Records.Count})");
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var cidr in spf.ResolvedIpv6Records.Take(10)) list.AddItem(cidr);
        }

        // Flattened IP Analysis
        var flat = spf.FlattenedIpAnalysis;
        headings.AddItem("Flattened IP Analysis", 1);
        var flatTable = doc.AddTable(3, 2, WordTableStyle.TableGrid);
        flatTable.Rows[0].Cells[0].Paragraphs[0].Text = "Unique IPs";
        flatTable.Rows[0].Cells[1].Paragraphs[0].Text = (flat?.UniqueIps?.Count ?? 0).ToString();
        flatTable.Rows[1].Cells[0].Paragraphs[0].Text = "Duplicate IPs";
        flatTable.Rows[1].Cells[1].Paragraphs[0].Text = (flat?.DuplicateIps?.Count ?? 0).ToString();
        flatTable.Rows[2].Cells[0].Paragraphs[0].Text = "Tokens Resolved";
        flatTable.Rows[2].Cells[1].Paragraphs[0].Text = (flat?.TokenIpMap?.Count ?? 0).ToString();
        if (flat?.TokenIpMap != null && flat.TokenIpMap.Count > 0)
        {
            doc.AddParagraph("Token → IPs (counts)");
            var t = doc.AddTable(flat.TokenIpMap.Count + 1, 2, WordTableStyle.TableGrid);
            t.Rows[0].Cells[0].Paragraphs[0].Text = "Token";
            t.Rows[0].Cells[1].Paragraphs[0].Text = "IP Count";
            int r = 1;
            foreach (var kv in flat.TokenIpMap)
            {
                t.Rows[r].Cells[0].Paragraphs[0].Text = kv.Key;
                t.Rows[r].Cells[1].Paragraphs[0].Text = (kv.Value?.Count ?? 0).ToString();
                r++;
            }
            // Show sample of unique IPs
            doc.AddParagraph("Sample Unique IPs");
            var ipList = doc.AddList(WordListStyle.Bulleted);
            foreach (var ip in flat.UniqueIps.Take(20)) ipList.AddItem(ip);
        }

        // Cycles & Advisory
        headings.AddItem("Policy Checks", 1);
        var checks = doc.AddTable(3, 2, WordTableStyle.TableGrid);
        checks.Rows[0].Cells[0].Paragraphs[0].Text = "Cycle Detected";
        checks.Rows[0].Cells[1].Paragraphs[0].Text = spf.CycleDetected ? "Yes" : "No";
        checks.Rows[1].Cells[0].Paragraphs[0].Text = "Cycle Path";
        checks.Rows[1].Cells[1].Paragraphs[0].Text = spf.CyclePath ?? string.Empty;
        checks.Rows[2].Cells[0].Paragraphs[0].Text = "Advisory";
        checks.Rows[2].Cells[1].Paragraphs[0].Text = spf.Advisory ?? string.Empty;

        // Recommendations
        var assessList = (IEnumerable<Assessment>)(spf.Assessments ?? new List<Assessment>());
        var grouped = RecommendationEngine.GroupByCode(assessList);
        var negative = grouped.Where(g => g.MaxSeverity != AssessmentSeverity.Info).ToList();
        if (negative.Count > 0)
        {
            headings.AddItem("Recommendations", 1);
            var rt = doc.AddTable(negative.Count + 1, 3, WordTableStyle.TableGrid);
            rt.Rows[0].Cells[0].Paragraphs[0].Text = "Code";
            rt.Rows[0].Cells[1].Paragraphs[0].Text = "Title";
            rt.Rows[0].Cells[2].Paragraphs[0].Text = "How";
            for (int i = 0; i < negative.Count; i++)
            {
                var rv = negative[i];
                rt.Rows[i + 1].Cells[0].Paragraphs[0].Text = rv.Code ?? string.Empty;
                rt.Rows[i + 1].Cells[1].Paragraphs[0].Text = rv.Advice?.Title ?? string.Empty;
                rt.Rows[i + 1].Cells[2].Paragraphs[0].Text = rv.Advice?.How ?? string.Empty;
            }
        }

        // Detailed narrative
        if (nar.Details.Count > 0)
        {
            headings.AddItem("Details", 1);
            foreach (var d in nar.Details) doc.AddParagraph(d);
        }

        // References
        if (nar.References.Count > 0)
        {
            headings.AddItem("References", 1);
            foreach (var r in nar.References) doc.AddParagraph(r);
        }

        doc.Save();
    }
}
