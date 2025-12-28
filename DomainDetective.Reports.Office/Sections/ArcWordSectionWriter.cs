using System;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

/// <summary>
/// ARC section writer for Word reports.
/// </summary>
public static class ArcWordSectionWriter
{
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.ArcInfo arc, string subjectLabel, ReportScope scope, bool showInfoFindings, bool includeNarrative = true)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (arc == null) throw new ArgumentNullException(nameof(arc));

        if (includeNarrative && arc.Narrative != null)
        {
            var nar = arc.Narrative;
            if (!string.IsNullOrWhiteSpace(nar.Introduction)) { headings.AddItem("Introduction", baseLevel); doc.AddParagraph(nar.Introduction); }
            if (!string.IsNullOrWhiteSpace(nar.WhyItMatters)) { headings.AddItem("Why this matters", baseLevel); doc.AddParagraph(nar.WhyItMatters); }
        }

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("ARC headers (ARC-Seal and ARC-Authentication-Results) and chain validation status.");
        var t = doc.AddTable(6, 2, WordTableStyle.TableGrid);
        t.Rows[0].Cells[0].Paragraphs[0].Text = "Headers Present";
        t.Rows[0].Cells[1].Paragraphs[0].Text = arc.ArcHeadersFound ? "Yes" : "No";
        t.Rows[1].Cells[0].Paragraphs[0].Text = "ARC-Seal count";
        t.Rows[1].Cells[1].Paragraphs[0].Text = arc.SealCount.ToString();
        t.Rows[2].Cells[0].Paragraphs[0].Text = "AAR count";
        t.Rows[2].Cells[1].Paragraphs[0].Text = arc.AarCount.ToString();
        t.Rows[3].Cells[0].Paragraphs[0].Text = "Seals signed";
        t.Rows[3].Cells[1].Paragraphs[0].Text = arc.SealsIncludeSignatures ? "Yes" : "No";
        t.Rows[4].Cells[0].Paragraphs[0].Text = "Chain state";
        t.Rows[4].Cells[1].Paragraphs[0].Text = arc.ChainState ?? string.Empty;
        t.Rows[5].Cells[0].Paragraphs[0].Text = "Status";
        t.Rows[5].Cells[1].Paragraphs[0].Text = arc.Status ?? string.Empty;

        if (scope == ReportScope.Minimal) return;

        // Positives
        if (scope != ReportScope.Minimal && arc.Positives != null && arc.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            doc.AddParagraph("This domain demonstrates the following positive posture:");
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in arc.Positives) if (!string.IsNullOrWhiteSpace(p?.Title)) list.AddItem(p!.Title);
        }

        // Findings
        var assess = arc.Assessments != null ? new System.Collections.Generic.List<DomainDetective.Assessment>(arc.Assessments) : new System.Collections.Generic.List<DomainDetective.Assessment>();
        if (!showInfoFindings)
        {
            assess = assess.FindAll(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info);
        }
        if (assess.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            doc.AddParagraph("The following issues were detected:");
            var ft = doc.AddTable(assess.Count + 1, 4, WordTableStyle.TableGrid);
            ft.Rows[0].Cells[0].AddParagraph("Severity");
            ft.Rows[0].Cells[1].AddParagraph("Code");
            ft.Rows[0].Cells[2].AddParagraph("Target");
            ft.Rows[0].Cells[3].AddParagraph("Message");
            for (int i = 0; i < assess.Count; i++)
            {
                var a = assess[i];
                ft.Rows[i + 1].Cells[0].AddParagraph(a.Severity.ToString());
                ft.Rows[i + 1].Cells[1].AddParagraph(a.Code ?? string.Empty);
                ft.Rows[i + 1].Cells[2].AddParagraph(a.Target ?? string.Empty);
                ft.Rows[i + 1].Cells[3].AddParagraph(a.Message ?? string.Empty);
            }
        }

        // Evidence
        headings.AddItem("Evidence", baseLevel);
        var list2 = doc.AddList(WordListStyle.Bulleted);
        list2.AddItem($"ARC-Seal headers: {arc.SealCount}");
        list2.AddItem($"ARC-Authentication-Results headers: {arc.AarCount}");
        list2.AddItem($"Chain: {arc.ChainState}");

        // References
        if (arc.References != null && arc.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            WordLinkHelpers.AddReferencesList(doc, arc.References);
        }
    }
}
