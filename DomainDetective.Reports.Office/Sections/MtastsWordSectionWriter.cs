using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Writes MTA-STS section content into a Word document.
/// </summary>
public static class MtastsWordSectionWriter
{
    /// <summary>
    /// Writes the MTA-STS section.
    /// </summary>
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.MtastsInfo mtasts, string domain, ReportScope scope, bool showInfoFindings, bool includeNarrative = true)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (mtasts == null) throw new ArgumentNullException(nameof(mtasts));

        if (includeNarrative)
        {
            var nar = DomainDetective.Narratives.MtaStsNarrative.Build(mtasts.Raw, mtasts.Assessments);
            if (!string.IsNullOrWhiteSpace(nar.Introduction)) { headings.AddItem("Introduction", baseLevel); doc.AddParagraph(nar.Introduction); }
            if (!string.IsNullOrWhiteSpace(nar.WhyItMatters)) { headings.AddItem("Why this matters", baseLevel); doc.AddParagraph(nar.WhyItMatters); }
        }

        headings.AddItem("Summary", baseLevel);
        var t = doc.AddTable(7, 2, WordTableStyle.TableGrid);
        t.Rows[0].Cells[0].Paragraphs[0].Text = "DNS Policy TXT";
        t.Rows[0].Cells[1].Paragraphs[0].Text = mtasts.DnsRecordPresent ? (mtasts.DnsRecordValid ? "Present (valid)" : "Present (invalid)") : "Missing";
        t.Rows[1].Cells[0].Paragraphs[0].Text = "Policy File";
        t.Rows[1].Cells[1].Paragraphs[0].Text = mtasts.PolicyPresent ? (mtasts.PolicyValid ? "Present (valid)" : "Present (invalid)") : "Missing";
        t.Rows[2].Cells[0].Paragraphs[0].Text = "Mode";
        t.Rows[2].Cells[1].Paragraphs[0].Text = mtasts.Mode ?? string.Empty;
        t.Rows[3].Cells[0].Paragraphs[0].Text = "Max-Age";
        t.Rows[3].Cells[1].Paragraphs[0].Text = mtasts.MaxAge.ToString();
        t.Rows[4].Cells[0].Paragraphs[0].Text = "MX Present";
        t.Rows[4].Cells[1].Paragraphs[0].Text = mtasts.HasMx ? "Yes" : "No";
        t.Rows[5].Cells[0].Paragraphs[0].Text = "MX Aligned";
        t.Rows[5].Cells[1].Paragraphs[0].Text = mtasts.MxAligned ? "Yes" : "No";
        t.Rows[6].Cells[0].Paragraphs[0].Text = "Status";
        t.Rows[6].Cells[1].Paragraphs[0].Text = mtasts.Status ?? string.Empty;

        if (scope == ReportScope.Minimal) return;

        var missing = mtasts.MissingMxFromPolicy ?? Array.Empty<string>();
        if (missing.Length > 0)
        {
            headings.AddItem("Highlights", baseLevel);
            var p = doc.AddParagraph("MX missing from policy:");
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var s in missing) list.AddItem(s);
        }

        var assessments = (mtasts.Assessments ?? Array.Empty<DomainDetective.Assessment>()).ToList();
        if (!showInfoFindings) assessments = assessments.Where(a => a.Severity != DomainDetective.AssessmentSeverity.Info).ToList();
        if (assessments.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
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
    }
}
