using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Writes TLS-RPT section content into a Word document.
/// </summary>
public static class TlsRptWordSectionWriter
{
    /// <summary>
    /// Writes the TLS-RPT section.
    /// </summary>
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.TlsRptInfo tlsrpt, string domain, ReportScope scope, bool showInfoFindings, bool includeNarrative = true)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (tlsrpt == null) throw new ArgumentNullException(nameof(tlsrpt));

        if (includeNarrative)
        {
            var nar = DomainDetective.Narratives.TlsRptNarrative.Build(tlsrpt.Raw);
            if (!string.IsNullOrWhiteSpace(nar.Introduction)) { headings.AddItem("Introduction", baseLevel); doc.AddParagraph(nar.Introduction); }
            if (!string.IsNullOrWhiteSpace(nar.WhyItMatters)) { headings.AddItem("Why this matters", baseLevel); doc.AddParagraph(nar.WhyItMatters); }
        }

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("TLS-RPT record presence and configured reporting URIs.");
        var t = doc.AddTable(7, 2, WordTableStyle.TableGrid);
        t.Rows[0].Cells[0].Paragraphs[0].Text = "Record Present";
        t.Rows[0].Cells[1].Paragraphs[0].Text = tlsrpt.TlsRptRecordExists ? (tlsrpt.StartsCorrectly ? "Yes (v=TLSRPTv1)" : "Yes (invalid start)") : "No";
        t.Rows[1].Cells[0].Paragraphs[0].Text = "DNS TTL (s)";
        t.Rows[1].Cells[1].Paragraphs[0].Text = tlsrpt.DnsRecordTtl?.ToString() ?? "-";
        t.Rows[2].Cells[0].Paragraphs[0].Text = "Multiple Records";
        t.Rows[2].Cells[1].Paragraphs[0].Text = tlsrpt.MultipleRecords ? "Yes" : "No";
        t.Rows[3].Cells[0].Paragraphs[0].Text = "mailto: rua";
        t.Rows[3].Cells[1].Paragraphs[0].Text = (tlsrpt.MailtoRua?.Count ?? 0).ToString();
        t.Rows[4].Cells[0].Paragraphs[0].Text = "http: rua";
        t.Rows[4].Cells[1].Paragraphs[0].Text = (tlsrpt.HttpRua?.Count ?? 0).ToString();
        t.Rows[5].Cells[0].Paragraphs[0].Text = "Invalid URIs";
        t.Rows[5].Cells[1].Paragraphs[0].Text = (tlsrpt.InvalidRua?.Count ?? 0).ToString();
        t.Rows[6].Cells[0].Paragraphs[0].Text = "Status";
        t.Rows[6].Cells[1].Paragraphs[0].Text = tlsrpt.Status ?? string.Empty;

        if (scope == ReportScope.Minimal) return;

        // Good posture
        if (scope != ReportScope.Minimal && tlsrpt.Positives != null && tlsrpt.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            doc.AddParagraph("This domain demonstrates the following positive posture:");
            var plist = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in tlsrpt.Positives)
            {
                if (!string.IsNullOrWhiteSpace(p?.Title)) plist.AddItem(p!.Title);
            }
        }

        var assessments = (tlsrpt.Assessments ?? Array.Empty<DomainDetective.Assessment>()).ToList();
        if (!showInfoFindings) assessments = assessments.Where(a => a.Severity != DomainDetective.AssessmentSeverity.Info).ToList();
        if (assessments.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            doc.AddParagraph("The following issues were detected:");
            var ft = doc.AddTable(assessments.Count + 1, 4, WordTableStyle.TableGrid);
            ft.Rows[0].Cells[0].Paragraphs[0].Text = "Severity";
            ft.Rows[0].Cells[1].Paragraphs[0].Text = "Code";
            ft.Rows[0].Cells[2].Paragraphs[0].Text = "Target";
            ft.Rows[0].Cells[3].Paragraphs[0].Text = "Message";
            for (int i = 0; i < assessments.Count; i++)
            {
                var a = assessments[i];
                ft.Rows[i + 1].Cells[0].Paragraphs[0].Text = a.Severity.ToString();
                ft.Rows[i + 1].Cells[1].Paragraphs[0].Text = a.Code ?? string.Empty;
                ft.Rows[i + 1].Cells[2].Paragraphs[0].Text = a.Target ?? string.Empty;
                ft.Rows[i + 1].Cells[3].Paragraphs[0].Text = a.Message;
            }
        }

        // References
        if (tlsrpt.References != null && tlsrpt.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            doc.AddParagraph("Further reading and relevant standards.");
            WordLinkHelpers.AddReferencesList(doc, tlsrpt.References);
        }
    }

    /// <summary>
    /// Projector-aware overload using SectionProjectors.TlsRptSection.
    /// </summary>
    public static void Write(WordDocument doc, WordList headings, int baseLevel,
        DomainDetective.Reports.SectionProjectors.TlsRptSection sec,
        DomainDetective.Views.TlsRptInfo? original,
        string domain, ReportScope scope, bool showInfoFindings, bool includeNarrative = true)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sec == null) throw new ArgumentNullException(nameof(sec));

        if (includeNarrative && original != null)
        {
            var nar = DomainDetective.Narratives.TlsRptNarrative.Build(original.Raw);
            if (!string.IsNullOrWhiteSpace(nar.Introduction)) { headings.AddItem("Introduction", baseLevel); doc.AddParagraph(nar.Introduction); }
            if (!string.IsNullOrWhiteSpace(nar.WhyItMatters)) { headings.AddItem("Why this matters", baseLevel); doc.AddParagraph(nar.WhyItMatters); }
        }

        headings.AddItem("Summary", baseLevel);
        var rows = sec.Summary.Count > 0 ? sec.Summary : new System.Collections.Generic.List<(string Key,string Value)>() { ("Status", sec.Status), ("rua", sec.RuaCount.ToString()) };
        var t = doc.AddTable(rows.Count, 2, WordTableStyle.TableGrid);
        for (int i=0;i<rows.Count;i++){ t.Rows[i].Cells[0].Paragraphs[0].Text = rows[i].Key; t.Rows[i].Cells[1].Paragraphs[0].Text = rows[i].Value; }

        if (sec.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            doc.AddParagraph("This domain demonstrates the following positive posture:");
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in sec.Positives) list.AddItem(p);
        }

        var f = sec.Findings; if (!showInfoFindings) f = f.Where(x => !string.Equals(x.Severity, "Info", System.StringComparison.OrdinalIgnoreCase)).ToList();
        if (f.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            doc.AddParagraph("The following issues were detected:");
            var ft = doc.AddTable(f.Count + 1, 4, WordTableStyle.TableGrid);    
            ft.Rows[0].Cells[0].AddParagraph("Severity"); ft.Rows[0].Cells[1].AddParagraph("Code"); ft.Rows[0].Cells[2].AddParagraph("Target"); ft.Rows[0].Cells[3].AddParagraph("Message");
            for (int i=0;i<f.Count;i++){ var a=f[i]; ft.Rows[i+1].Cells[0].AddParagraph(a.Severity); ft.Rows[i+1].Cells[1].AddParagraph(a.Code); ft.Rows[i+1].Cells[2].AddParagraph(a.Target); ft.Rows[i+1].Cells[3].AddParagraph(a.Message);}        
        }

        if (original != null)
        {
            // Evidence: show URIs if present
            var any = (original.MailtoRua?.Count ?? 0) + (original.HttpRua?.Count ?? 0);
            if (any > 0)
            {
                headings.AddItem("Evidence", baseLevel);
                var list = doc.AddList(WordListStyle.Bulleted);
                var mailtoRua = original.MailtoRua;
                if (mailtoRua != null && mailtoRua.Count > 0) list.AddItem($"mailto: {string.Join(", ", mailtoRua)}");

                var httpRua = original.HttpRua;
                if (httpRua != null && httpRua.Count > 0) list.AddItem($"http: {string.Join(", ", httpRua)}");
            }
        }

        if (sec.References.Count > 0)
        { headings.AddItem("References", baseLevel); WordLinkHelpers.AddReferencesList(doc, sec.References); }
    }
}
