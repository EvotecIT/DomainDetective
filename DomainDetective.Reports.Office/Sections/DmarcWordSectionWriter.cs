using System;
using OfficeIMO.Word;
using System.Linq;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Minimal DMARC section writer. Provides a stable, reusable section body.
/// </summary>
public static class DmarcWordSectionWriter
{
    /// <summary>
    /// Writes DMARC section into an existing <see cref="WordDocument"/>.
    /// </summary>
    /// <param name="doc">Target document.</param>
    /// <param name="dmarc">DMARC view model.</param>
    /// <param name="domain">Domain subject.</param>
    /// <param name="scope">Detail level.</param>
    /// <param name="showInfoFindings">Whether to include Info-level findings.</param>
    public static void Write(WordDocument doc, DomainDetective.Views.DmarcRecordInfo dmarc, string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (dmarc == null) throw new ArgumentNullException(nameof(dmarc));

        var t = doc.AddTable(8, 2, WordTableStyle.TableGrid);
        t.Rows[0].Cells[0].Paragraphs[0].Text = "Record Present";
        t.Rows[0].Cells[1].Paragraphs[0].Text = dmarc.DmarcRecordExists ? "Yes" : "No";
        t.Rows[1].Cells[0].Paragraphs[0].Text = "Policy";
        t.Rows[1].Cells[1].Paragraphs[0].Text = dmarc.Policy ?? string.Empty;
        t.Rows[2].Cells[0].Paragraphs[0].Text = "adkim/aspf";
        t.Rows[2].Cells[1].Paragraphs[0].Text = $"{dmarc.DkimAlignment ?? "?"}/{dmarc.SpfAlignment ?? "?"}";
        t.Rows[3].Cells[0].Paragraphs[0].Text = "pct";
        t.Rows[3].Cells[1].Paragraphs[0].Text = dmarc.Percent ?? string.Empty;
        t.Rows[4].Cells[0].Paragraphs[0].Text = "rua";
        t.Rows[4].Cells[1].Paragraphs[0].Text = (dmarc.MailtoRua?.Count ?? 0).ToString();
        t.Rows[5].Cells[0].Paragraphs[0].Text = "ruf";
        t.Rows[5].Cells[1].Paragraphs[0].Text = (dmarc.MailtoRuf?.Count ?? 0).ToString();
        t.Rows[6].Cells[0].Paragraphs[0].Text = "ext auth";
        t.Rows[6].Cells[1].Paragraphs[0].Text = (dmarc.ExternalReportAuthorization?.Count ?? 0).ToString();
        t.Rows[7].Cells[0].Paragraphs[0].Text = "Status";
        t.Rows[7].Cells[1].Paragraphs[0].Text = dmarc.Status ?? string.Empty;

        if (scope == ReportScope.Minimal) return;

        var assessList = (dmarc.Assessments ?? Array.Empty<DomainDetective.Assessment>()).ToList();
        if (!showInfoFindings)
        {
            assessList = assessList.Where(a => a.Severity != DomainDetective.AssessmentSeverity.Info).ToList();
        }
        if (assessList.Count > 0)
        {
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

        // Detailed extras: highlights and recommendations
        if (scope == ReportScope.Detailed)
        {
            var hl = dmarc.Highlights ?? Array.Empty<string>();
            if (hl != null && hl.Count > 0)
            {
                var list = doc.AddList(WordListStyle.Bulleted);
                foreach (var h in hl) list.AddItem(h);
            }
            var grouped = DomainDetective.RecommendationEngine.GroupByCode(assessList);
            var negative = grouped.Where(g => g.MaxSeverity != DomainDetective.AssessmentSeverity.Info).ToList();
            if (negative.Count > 0)
            {
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
