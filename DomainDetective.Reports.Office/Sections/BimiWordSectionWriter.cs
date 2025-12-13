using System;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Minimal BIMI section writer. Mirrors DMARC/DKIM structure for consistency.
/// </summary>
public static class BimiWordSectionWriter
{
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.BimiRecordInfo bimi, string domain, ReportScope scope, bool showInfoFindings, bool includeNarrative = true)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (bimi == null) throw new ArgumentNullException(nameof(bimi));

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("BIMI record presence and indicator/certificate validation.");
        var t = doc.AddTable(8, 2, WordTableStyle.TableGrid);
        t.Rows[0].Cells[0].Paragraphs[0].Text = "Record Present";
        t.Rows[0].Cells[1].Paragraphs[0].Text = bimi.BimiRecordExists ? "Yes" : "No";
        t.Rows[1].Cells[0].Paragraphs[0].Text = "Location (l=)";
        t.Rows[1].Cells[1].Paragraphs[0].Text = bimi.Location ?? string.Empty;
        t.Rows[2].Cells[0].Paragraphs[0].Text = "Authority (a=)";
        t.Rows[2].Cells[1].Paragraphs[0].Text = bimi.Authority ?? string.Empty;
        t.Rows[3].Cells[0].Paragraphs[0].Text = "SVG Valid";
        t.Rows[3].Cells[1].Paragraphs[0].Text = bimi.SvgValid ? "Yes" : "No";
        t.Rows[4].Cells[0].Paragraphs[0].Text = "VMC Present";
        t.Rows[4].Cells[1].Paragraphs[0].Text = bimi.ValidVmc ? "Yes" : "No";
        t.Rows[5].Cells[0].Paragraphs[0].Text = "VMC Trusted";
        t.Rows[5].Cells[1].Paragraphs[0].Text = bimi.VmcSignedByKnownRoot ? "Yes" : (bimi.ValidVmc ? "Untrusted" : "-");
        t.Rows[6].Cells[0].Paragraphs[0].Text = "Declined (p=reject)";
        t.Rows[6].Cells[1].Paragraphs[0].Text = bimi.DeclinedToPublish ? "Yes" : "No";
        t.Rows[7].Cells[0].Paragraphs[0].Text = "Status";
        t.Rows[7].Cells[1].Paragraphs[0].Text = bimi.Status ?? string.Empty;

        if (scope == ReportScope.Minimal) return;

        // Positives
        if (scope != ReportScope.Minimal && bimi.Positives != null && bimi.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in bimi.Positives)
            {
                if (!string.IsNullOrWhiteSpace(p?.Title)) list.AddItem(p!.Title);
            }
        }

        // Findings
        var assessList = bimi.Assessments != null ? new System.Collections.Generic.List<DomainDetective.Assessment>(bimi.Assessments) : new System.Collections.Generic.List<DomainDetective.Assessment>();
        if (!showInfoFindings)
        {
            assessList = assessList.FindAll(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info);
        }
        if (assessList.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            var ft = doc.AddTable(assessList.Count + 1, 4, WordTableStyle.TableGrid);
            ft.Rows[0].Cells[0].Paragraphs[0].Text = "Severity";
            ft.Rows[0].Cells[1].Paragraphs[0].Text = "Code";
            ft.Rows[0].Cells[2].Paragraphs[0].Text = "Target";
            ft.Rows[0].Cells[3].Paragraphs[0].Text = "Message";
            for (int i = 0; i < assessList.Count; i++)
            {
                var a = assessList[i];
                ft.Rows[i + 1].Cells[0].Paragraphs[0].Text = a.Severity.ToString();
                ft.Rows[i + 1].Cells[1].Paragraphs[0].Text = a.Code ?? string.Empty;
                ft.Rows[i + 1].Cells[2].Paragraphs[0].Text = a.Target ?? string.Empty;
                ft.Rows[i + 1].Cells[3].Paragraphs[0].Text = a.Message;
            }
        }

        // Evidence
        headings.AddItem("Evidence", baseLevel);
        doc.AddParagraph("Raw BIMI record and validation outcomes.");
        doc.AddParagraph("BIMI Record:").SetBold();
        var pr = doc.AddParagraph(bimi.BimiRecord ?? string.Empty);
        pr.FontSize = 10;
        var elist = doc.AddList(WordListStyle.Bulleted);
        if (!string.IsNullOrWhiteSpace(bimi.Location)) elist.AddItem($"Location: {bimi.Location}");
        if (!string.IsNullOrWhiteSpace(bimi.Authority)) elist.AddItem($"Authority: {bimi.Authority}");
        if (!bimi.SvgValid && !string.IsNullOrWhiteSpace(bimi.SvgInvalidReason)) elist.AddItem($"SVG invalid: {bimi.SvgInvalidReason}");

        // References
        if (bimi.References != null && bimi.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            WordLinkHelpers.AddReferencesList(doc, bimi.References);
        }
    }
}
