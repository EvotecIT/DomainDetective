using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

public static class ZoneTransferWordSectionWriter
{
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.ZoneTransferInfo zt, string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (zt == null) throw new ArgumentNullException(nameof(zt));

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("AXFR exposure summary across authoritative name servers.");
        var t = doc.AddTable(4, 2, WordTableStyle.TableGrid);
        t.Rows[0].Cells[0].AddParagraph("Servers Checked");
        t.Rows[0].Cells[1].AddParagraph(zt.TotalChecked.ToString());
        t.Rows[1].Cells[0].AddParagraph("Open Servers");
        t.Rows[1].Cells[1].AddParagraph(zt.OpenCount.ToString());
        t.Rows[2].Cells[0].AddParagraph("Status");
        t.Rows[2].Cells[1].AddParagraph(zt.Status ?? string.Empty);
        t.Rows[3].Cells[0].AddParagraph("Inline Summary");
        t.Rows[3].Cells[1].AddParagraph(zt.Summary ?? string.Empty);

        // Server results
        if (zt.ServerResults != null && zt.ServerResults.Count > 0)
        {
            headings.AddItem("Servers", baseLevel);
            var srv = zt.ServerResults.ToList();
            var table = doc.AddTable(srv.Count + 1, 2, WordTableStyle.TableGrid);
            table.Rows[0].Cells[0].AddParagraph("Server");
            table.Rows[0].Cells[1].AddParagraph("Open");
            for (int i = 0; i < srv.Count; i++)
            {
                table.Rows[i + 1].Cells[0].AddParagraph(srv[i].Key);
                table.Rows[i + 1].Cells[1].AddParagraph(srv[i].Value ? "Yes" : "No");
            }
        }

        // Findings
        var assessments = zt.Assessments?.ToList() ?? new System.Collections.Generic.List<DomainDetective.Assessment>();
        if (!showInfoFindings) assessments = assessments.Where(a => a.Severity != DomainDetective.AssessmentSeverity.Info).ToList();
        if (assessments.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            var ft = doc.AddTable(assessments.Count + 1, 4, WordTableStyle.TableGrid);
            ft.Rows[0].Cells[0].AddParagraph("Severity");
            ft.Rows[0].Cells[1].AddParagraph("Code");
            ft.Rows[0].Cells[2].AddParagraph("Target");
            ft.Rows[0].Cells[3].AddParagraph("Message");
            for (int i = 0; i < assessments.Count; i++)
            {
                var a = assessments[i];
                ft.Rows[i + 1].Cells[0].AddParagraph(a.Severity.ToString());
                ft.Rows[i + 1].Cells[1].AddParagraph(a.Code ?? string.Empty);
                ft.Rows[i + 1].Cells[2].AddParagraph(a.Target ?? string.Empty);
                ft.Rows[i + 1].Cells[3].AddParagraph(a.Message);
            }
        }
    }

    /// <summary>
    /// Projector-aware overload using SectionProjectors.ZoneTransferSection.
    /// </summary>
    public static void Write(WordDocument doc, WordList headings, int baseLevel,
        DomainDetective.Reports.SectionProjectors.ZoneTransferSection sec,
        DomainDetective.Views.ZoneTransferInfo? original,
        string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sec == null) throw new ArgumentNullException(nameof(sec));

        headings.AddItem("Summary", baseLevel);
        var t = doc.AddTable(sec.Summary.Count, 2, WordTableStyle.TableGrid);
        for (int i=0;i<sec.Summary.Count;i++){ var kv = sec.Summary[i]; t.Rows[i].Cells[0].AddParagraph(kv.Key); t.Rows[i].Cells[1].AddParagraph(kv.Value); }

        if (original != null && (original.ServerResults?.Count ?? 0) > 0)
        {
            headings.AddItem("Servers", baseLevel);
            var srv = original.ServerResults.ToList();
            var table = doc.AddTable(srv.Count + 1, 2, WordTableStyle.TableGrid);
            table.Rows[0].Cells[0].AddParagraph("Server"); table.Rows[0].Cells[1].AddParagraph("Open");
            for (int i=0;i<srv.Count;i++){ table.Rows[i+1].Cells[0].AddParagraph(srv[i].Key); table.Rows[i+1].Cells[1].AddParagraph(srv[i].Value ? "Yes" : "No"); }
        }

        var f = sec.Findings; if (!showInfoFindings) f = f.Where(x => !string.Equals(x.Severity, "Info", System.StringComparison.OrdinalIgnoreCase)).ToList();
        if (f.Count > 0)
        { headings.AddItem("Findings", baseLevel); var ft = doc.AddTable(f.Count + 1, 4, WordTableStyle.TableGrid); ft.Rows[0].Cells[0].AddParagraph("Severity"); ft.Rows[0].Cells[1].AddParagraph("Code"); ft.Rows[0].Cells[2].AddParagraph("Target"); ft.Rows[0].Cells[3].AddParagraph("Message"); for (int i=0;i<f.Count;i++){ var a=f[i]; ft.Rows[i+1].Cells[0].AddParagraph(a.Severity); ft.Rows[i+1].Cells[1].AddParagraph(a.Code); ft.Rows[i+1].Cells[2].AddParagraph(a.Target); ft.Rows[i+1].Cells[3].AddParagraph(a.Message);} }
    }
}
