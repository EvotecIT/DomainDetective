using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Minimal DKIM section writer. Can be expanded later; provides consistent headings and summary table.
/// </summary>
/// <summary>
/// Writes a DKIM section into an existing Word report.
/// </summary>
public static class DkimWordSectionWriter
{
    /// <summary>
    /// Writes DKIM section.
    /// </summary>
    /// <param name="doc">Target document.</param>
    /// <param name="dkim">DKIM views for all selectors.</param>
    /// <param name="domain">Domain subject.</param>
    /// <param name="scope">Detail level.</param>
    /// <param name="showInfoFindings">Include Info-level findings.</param>
    public static void Write(WordDocument doc, WordList headings, int baseLevel, System.Collections.Generic.IReadOnlyList<DomainDetective.Views.DkimRecordInfo> dkim, string domain, ReportScope scope, bool showInfoFindings, bool includeNarrative = true)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (dkim == null) throw new ArgumentNullException(nameof(dkim));

        if (dkim.Count == 0)
        {
            doc.AddParagraph("No DKIM selectors discovered.");
            return;
        }

        if (includeNarrative)
        {
            var nar = dkim.FirstOrDefault()?.Narrative;
            if (nar != null)
            {
                if (!string.IsNullOrWhiteSpace(nar.Introduction)) { headings.AddItem("Introduction", baseLevel); doc.AddParagraph(nar.Introduction); }
                if (!string.IsNullOrWhiteSpace(nar.WhyItMatters)) { headings.AddItem("Why this matters", baseLevel); doc.AddParagraph(nar.WhyItMatters); }
            }
        }

        headings.AddItem("Summary", baseLevel);
        var table = doc.AddTable(dkim.Count + 1, 7, WordTableStyle.TableGrid);
        table.Rows[0].Cells[0].Paragraphs[0].Text = "Selector";
        table.Rows[0].Cells[1].Paragraphs[0].Text = "Record";
        table.Rows[0].Cells[2].Paragraphs[0].Text = "Key Bits";
        table.Rows[0].Cells[3].Paragraphs[0].Text = "Alg";
        table.Rows[0].Cells[4].Paragraphs[0].Text = "Key Age";
        table.Rows[0].Cells[5].Paragraphs[0].Text = "Public Key";
        table.Rows[0].Cells[6].Paragraphs[0].Text = "Status";
        for (int i = 0; i < dkim.Count; i++)
        {
            var r = dkim[i];
            table.Rows[i + 1].Cells[0].Paragraphs[0].Text = r.Selector ?? string.Empty;
            table.Rows[i + 1].Cells[1].Paragraphs[0].Text = r.DkimRecordExists ? "Present" : "Missing";
            table.Rows[i + 1].Cells[2].Paragraphs[0].Text = r.PublicKeyExists ? r.KeyLength.ToString() : "-";
            table.Rows[i + 1].Cells[3].Paragraphs[0].Text = r.HashAlgorithm ?? string.Empty;
            table.Rows[i + 1].Cells[4].Paragraphs[0].Text = r.KeyAgeDays > 0 ? r.KeyAgeDays.ToString() : "-";
            table.Rows[i + 1].Cells[5].Paragraphs[0].Text = r.PublicKeyExists ? "Yes" : "No";
            table.Rows[i + 1].Cells[6].Paragraphs[0].Text = r.Status ?? string.Empty;
        }

        if (scope == ReportScope.Minimal) return;

        // Findings (summarized)
        var findings = dkim.SelectMany(x => x.Assessments ?? Array.Empty<DomainDetective.Assessment>()).ToList();
        if (!showInfoFindings) findings = findings.Where(a => a.Severity != DomainDetective.AssessmentSeverity.Info).ToList();
        if (findings.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            var ft = doc.AddTable(findings.Count + 1, 4, WordTableStyle.TableGrid);
            ft.Rows[0].Cells[0].Paragraphs[0].Text = "Severity";
            ft.Rows[0].Cells[1].Paragraphs[0].Text = "Code";
            ft.Rows[0].Cells[2].Paragraphs[0].Text = "Target";
            ft.Rows[0].Cells[3].Paragraphs[0].Text = "Message";
            for (int i = 0; i < findings.Count; i++)
            {
                var a = findings[i];
                ft.Rows[i + 1].Cells[0].Paragraphs[0].Text = a.Severity.ToString();
                ft.Rows[i + 1].Cells[1].Paragraphs[0].Text = a.Code ?? string.Empty;
                ft.Rows[i + 1].Cells[2].Paragraphs[0].Text = a.Target ?? string.Empty;
                ft.Rows[i + 1].Cells[3].Paragraphs[0].Text = a.Message;
            }
        }

        // Highlights / Positives / Recommendations (Detailed only)
        if (scope == ReportScope.Detailed)
        {
            var hl = dkim.SelectMany(x => x.Highlights ?? Array.Empty<string>()).Distinct().ToList();
            if (hl.Count > 0)
            {
                headings.AddItem("Highlights", baseLevel);
                var list = doc.AddList(WordListStyle.Bulleted);
                foreach (var h in hl) list.AddItem(h);
            }

            // Recommendations from assessments grouped by code
            var grouped = DomainDetective.RecommendationEngine.GroupByCode(findings);
            var negative = grouped.Where(g => g.MaxSeverity != DomainDetective.AssessmentSeverity.Info).ToList();
            if (negative.Count > 0)
            {
                headings.AddItem("Recommendations", baseLevel);
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
        }
    }
}
