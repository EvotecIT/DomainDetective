using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Writes desired state conformance and best-practice gaps into a Word report.
/// </summary>
public static class DesiredStateWordSectionWriter
{
    /// <summary>
    /// Writes Desired State section using a projection DTO.
    /// </summary>
    public static void Write(
        WordDocument doc,
        WordList headings,
        int baseLevel,
        DomainDetective.Reports.SectionProjectors.DesiredStateSection sec,
        DomainDetective.Views.DesiredStateInfo? original,
        string domain,
        ReportScope scope,
        bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sec == null) throw new ArgumentNullException(nameof(sec));

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("Desired State summarizes conformance to your baseline and highlights best-practice gaps for this mode.");
        var rows = sec.Summary.Count > 0
            ? sec.Summary
            : new System.Collections.Generic.List<(string, string)>
            {
                ("Mode", sec.Mode),
                ("Conforms", sec.Conforms ? "Yes" : "No"),
                ("Desired Warnings", sec.DesiredWarningCount.ToString()),
                ("Desired Errors", sec.DesiredErrorCount.ToString()),
                ("Best-Practice Warnings", sec.BestPracticeWarningCount.ToString()),
                ("Best-Practice Errors", sec.BestPracticeErrorCount.ToString())
            };
        var t = doc.AddTable(rows.Count, 2, WordTableStyle.TableGrid);
        for (int i = 0; i < rows.Count; i++)
        {
            t.Rows[i].Cells[0].AddParagraph(rows[i].Item1);
            t.Rows[i].Cells[1].AddParagraph(rows[i].Item2);
        }

        headings.AddItem("Desired State Conformance", baseLevel);
        doc.AddParagraph("Baseline conformance highlights deviations from the desired configuration.");
        if (sec.DesiredPositives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel + 1);
            doc.AddParagraph("This domain demonstrates the following positive posture:");
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in sec.DesiredPositives) list.AddItem(p);
        }

        if (sec.DesiredFindings.Count > 0)
        {
            headings.AddItem("Findings", baseLevel + 1);
            doc.AddParagraph("Findings highlight drift from the desired baseline.");
            var ft = doc.AddTable(sec.DesiredFindings.Count + 1, 4, WordTableStyle.TableGrid);
            ft.Rows[0].Cells[0].AddParagraph("Severity");
            ft.Rows[0].Cells[1].AddParagraph("Code");
            ft.Rows[0].Cells[2].AddParagraph("Target");
            ft.Rows[0].Cells[3].AddParagraph("Message");
            for (int i = 0; i < sec.DesiredFindings.Count; i++)
            {
                var a = sec.DesiredFindings[i];
                ft.Rows[i + 1].Cells[0].AddParagraph(a.Severity);
                ft.Rows[i + 1].Cells[1].AddParagraph(a.Code);
                ft.Rows[i + 1].Cells[2].AddParagraph(a.Target);
                ft.Rows[i + 1].Cells[3].AddParagraph(a.Message);
            }
        }
        else
        {
            doc.AddParagraph("No desired state drift findings.");
        }

        if (sec.DesiredRecommendations.Count > 0)
        {
            headings.AddItem("Recommendations", baseLevel + 1);
            doc.AddParagraph("Recommended actions to align with the desired baseline.");
            var rt = doc.AddTable(sec.DesiredRecommendations.Count + 1, 3, WordTableStyle.TableGrid);
            rt.Rows[0].Cells[0].AddParagraph("Code");
            rt.Rows[0].Cells[1].AddParagraph("Title");
            rt.Rows[0].Cells[2].AddParagraph("How");
            for (int i = 0; i < sec.DesiredRecommendations.Count; i++)
            {
                var r = sec.DesiredRecommendations[i];
                rt.Rows[i + 1].Cells[0].AddParagraph(r.Code);
                rt.Rows[i + 1].Cells[1].AddParagraph(r.Title);
                rt.Rows[i + 1].Cells[2].AddParagraph(r.How);
            }
        }

        if (!sec.IsBaselineOnly)
        {
            headings.AddItem("Best-Practice Gaps", baseLevel);
            doc.AddParagraph("Best-practice gaps show recommendations outside the baseline for this mode.");
            if (sec.BestPracticePositives.Count > 0)
            {
                headings.AddItem("Good posture", baseLevel + 1);
                doc.AddParagraph("This domain demonstrates the following positive posture:");
                var list = doc.AddList(WordListStyle.Bulleted);
                foreach (var p in sec.BestPracticePositives) list.AddItem(p);
            }

            if (sec.BestPracticeFindings.Count > 0)
            {
                headings.AddItem("Findings", baseLevel + 1);
                doc.AddParagraph("Findings highlight gaps against recommended practices.");
                var ft = doc.AddTable(sec.BestPracticeFindings.Count + 1, 4, WordTableStyle.TableGrid);
                ft.Rows[0].Cells[0].AddParagraph("Severity");
                ft.Rows[0].Cells[1].AddParagraph("Code");
                ft.Rows[0].Cells[2].AddParagraph("Target");
                ft.Rows[0].Cells[3].AddParagraph("Message");
                for (int i = 0; i < sec.BestPracticeFindings.Count; i++)
                {
                    var a = sec.BestPracticeFindings[i];
                    ft.Rows[i + 1].Cells[0].AddParagraph(a.Severity);
                    ft.Rows[i + 1].Cells[1].AddParagraph(a.Code);
                    ft.Rows[i + 1].Cells[2].AddParagraph(a.Target);
                    ft.Rows[i + 1].Cells[3].AddParagraph(a.Message);
                }
            }
            else
            {
                doc.AddParagraph("No best-practice findings for this mode.");
            }

            if (sec.BestPracticeRecommendations.Count > 0)
            {
                headings.AddItem("Recommendations", baseLevel + 1);
                doc.AddParagraph("Recommended actions to close best-practice gaps.");
                var rt = doc.AddTable(sec.BestPracticeRecommendations.Count + 1, 3, WordTableStyle.TableGrid);
                rt.Rows[0].Cells[0].AddParagraph("Code");
                rt.Rows[0].Cells[1].AddParagraph("Title");
                rt.Rows[0].Cells[2].AddParagraph("How");
                for (int i = 0; i < sec.BestPracticeRecommendations.Count; i++)
                {
                    var r = sec.BestPracticeRecommendations[i];
                    rt.Rows[i + 1].Cells[0].AddParagraph(r.Code);
                    rt.Rows[i + 1].Cells[1].AddParagraph(r.Title);
                    rt.Rows[i + 1].Cells[2].AddParagraph(r.How);
                }
            }
        }

        if (sec.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            WordLinkHelpers.AddReferencesList(doc, sec.References);
        }
    }

    /// <summary>
    /// Writes Desired State section from the view model.
    /// </summary>
    public static void Write(
        WordDocument doc,
        WordList headings,
        int baseLevel,
        DomainDetective.Views.DesiredStateInfo ds,
        string domain,
        ReportScope scope,
        bool showInfoFindings)
    {
        var dto = DomainDetective.Reports.SectionProjectors.BuildDesiredState(ds);
        if (dto != null)
        {
            Write(doc, headings, baseLevel, dto, ds, domain, scope, showInfoFindings);
        }
    }
}
