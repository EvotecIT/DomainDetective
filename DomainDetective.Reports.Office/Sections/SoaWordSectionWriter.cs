using System;
using System.Linq;
using System.Collections.Generic;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

public static class SoaWordSectionWriter
{
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.SoaInfo soa, string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (soa == null) throw new ArgumentNullException(nameof(soa));

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("SOA parameters and serial format.");
        var t = doc.AddTable(9, 2, WordTableStyle.TableGrid);
        t.Rows[0].Cells[0].AddParagraph("Record Present");
        t.Rows[0].Cells[1].AddParagraph(soa.RecordExists ? "Yes" : "No");
        t.Rows[1].Cells[0].AddParagraph("Primary NS");
        t.Rows[1].Cells[1].AddParagraph(soa.PrimaryNameServer ?? string.Empty);
        t.Rows[2].Cells[0].AddParagraph("Responsible Mailbox");
        t.Rows[2].Cells[1].AddParagraph(soa.ResponsibleMailbox ?? string.Empty);
        t.Rows[3].Cells[0].AddParagraph("Serial");
        t.Rows[3].Cells[1].AddParagraph(soa.SerialNumber.ToString());
        t.Rows[4].Cells[0].AddParagraph("Serial Format");
        t.Rows[4].Cells[1].AddParagraph(soa.SerialFormatValid ? "Valid" : (soa.SerialFormatSuggestion ?? "Check"));
        t.Rows[5].Cells[0].AddParagraph("Refresh");
        t.Rows[5].Cells[1].AddParagraph(soa.Refresh.ToString());
        t.Rows[6].Cells[0].AddParagraph("Retry");
        t.Rows[6].Cells[1].AddParagraph(soa.Retry.ToString());
        t.Rows[7].Cells[0].AddParagraph("Expire");
        t.Rows[7].Cells[1].AddParagraph(soa.Expire.ToString());
        t.Rows[8].Cells[0].AddParagraph("Minimum/NegCacheTTL");
        t.Rows[8].Cells[1].AddParagraph($"{soa.Minimum}/{soa.NegativeCacheTtl}");

        // Findings
        var assessments = soa.Assessments?.ToList() ?? new List<DomainDetective.Assessment>();
        if (!showInfoFindings)
            assessments = assessments.Where(a => a.Severity != DomainDetective.AssessmentSeverity.Info).ToList();
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

        // References
        if (soa.References != null && soa.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            WordLinkHelpers.AddReferencesList(doc, soa.References);
        }
    }

    /// <summary>
    /// Projector-aware overload using SectionProjectors.SoaSection.
    /// </summary>
    public static void Write(WordDocument doc, WordList headings, int baseLevel,
        DomainDetective.Reports.SectionProjectors.SoaSection sec,
        DomainDetective.Views.SoaInfo? original,
        string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sec == null) throw new ArgumentNullException(nameof(sec));

        headings.AddItem("Summary", baseLevel);
        var rows = sec.Summary.Count > 0 ? sec.Summary : new System.Collections.Generic.List<(string,string)>();
        if (rows.Count == 0 && original != null)
        {
            rows.Add(("Primary NS", original.PrimaryNameServer ?? "-"));
            rows.Add(("Responsible", original.ResponsibleMailbox ?? "-"));
            rows.Add(("Serial", original.SerialNumber.ToString()));
            rows.Add(("Refresh", original.Refresh.ToString()));
        }
        var t = doc.AddTable(rows.Count, 2, WordTableStyle.TableGrid);
        for (int i=0;i<rows.Count;i++){ t.Rows[i].Cells[0].AddParagraph(rows[i].Item1); t.Rows[i].Cells[1].AddParagraph(rows[i].Item2); }

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
            ft.Rows[0].Cells[0].AddParagraph("Severity");
            ft.Rows[0].Cells[1].AddParagraph("Code");
            ft.Rows[0].Cells[2].AddParagraph("Target");
            ft.Rows[0].Cells[3].AddParagraph("Message");
            for (int i=0;i<f.Count;i++){ var a=f[i]; ft.Rows[i+1].Cells[0].AddParagraph(a.Severity); ft.Rows[i+1].Cells[1].AddParagraph(a.Code); ft.Rows[i+1].Cells[2].AddParagraph(a.Target); ft.Rows[i+1].Cells[3].AddParagraph(a.Message); }
        }

        if (sec.References.Count > 0)
        { headings.AddItem("References", baseLevel); WordLinkHelpers.AddReferencesList(doc, sec.References); }
    }
}
