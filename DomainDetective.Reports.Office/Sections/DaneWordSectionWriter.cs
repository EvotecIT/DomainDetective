using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Writes DANE/TLSA section content into a Word document.
/// </summary>
public static class DaneWordSectionWriter
{
    /// <summary>
    /// Writes the DANE section.
    /// </summary>
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.DaneRecordInfo dane, string domain, ReportScope scope, bool showInfoFindings, bool includeNarrative = true)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (dane == null) throw new ArgumentNullException(nameof(dane));

        if (includeNarrative)
        {
            var nar = DomainDetective.Narratives.DaneNarrative.Build(dane.Raw, dane.Assessments);
            if (!string.IsNullOrWhiteSpace(nar.Introduction)) { headings.AddItem("Introduction", baseLevel); doc.AddParagraph(nar.Introduction); }
            if (!string.IsNullOrWhiteSpace(nar.WhyItMatters)) { headings.AddItem("Why this matters", baseLevel); doc.AddParagraph(nar.WhyItMatters); }
        }

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("DANE/TLSA record presence and basic validation.");
        var t = doc.AddTable(6, 2, WordTableStyle.TableGrid);
        t.Rows[0].Cells[0].Paragraphs[0].Text = "Records";
        t.Rows[0].Cells[1].Paragraphs[0].Text = dane.NumberOfRecords.ToString();
        t.Rows[1].Cells[0].Paragraphs[0].Text = "Invalid Records";
        t.Rows[1].Cells[1].Paragraphs[0].Text = dane.HasInvalidRecords ? "Yes" : "No";
        t.Rows[2].Cells[0].Paragraphs[0].Text = "Duplicate Records";
        t.Rows[2].Cells[1].Paragraphs[0].Text = dane.HasDuplicateRecords ? "Yes" : "No";
        t.Rows[3].Cells[0].Paragraphs[0].Text = "Queried Names";
        t.Rows[3].Cells[1].Paragraphs[0].Text = (dane.QueriedNames?.Count ?? 0).ToString();
        t.Rows[4].Cells[0].Paragraphs[0].Text = "Queried Ports";
        t.Rows[4].Cells[1].Paragraphs[0].Text = (dane.QueriedPorts?.Count ?? 0).ToString();
        t.Rows[5].Cells[0].Paragraphs[0].Text = "Status";
        t.Rows[5].Cells[1].Paragraphs[0].Text = dane.Status ?? string.Empty;

        if (scope == ReportScope.Minimal) return;

        // Good posture
        if (dane.Positives != null && dane.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            doc.AddParagraph("This domain demonstrates the following positive posture:");
            var plist = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in dane.Positives)
            {
                if (!string.IsNullOrWhiteSpace(p?.Title)) plist.AddItem(p!.Title);
            }
        }

        // Findings
        var assessments = (dane.Assessments ?? Array.Empty<DomainDetective.Assessment>()).ToList();
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
        if (dane.References != null && dane.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            doc.AddParagraph("Further reading and relevant standards.");
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var r in dane.References) if (!string.IsNullOrWhiteSpace(r)) list.AddItem(r);
        }
    }
}

