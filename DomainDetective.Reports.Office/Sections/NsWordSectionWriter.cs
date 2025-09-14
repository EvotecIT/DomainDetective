using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

public static class NsWordSectionWriter
{
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.NsInfo ns, string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (ns == null) throw new ArgumentNullException(nameof(ns));

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("Name server configuration and delegation status.");
        var t = doc.AddTable(9, 2, WordTableStyle.TableGrid);
        t.Rows[0].Cells[0].AddParagraph("NS Present");
        t.Rows[0].Cells[1].AddParagraph(ns.NsRecordExists ? "Yes" : "No");
        t.Rows[1].Cells[0].AddParagraph("At least two NS");
        t.Rows[1].Cells[1].AddParagraph(ns.AtLeastTwoRecords ? "Yes" : "No");
        t.Rows[2].Cells[0].AddParagraph("Duplicates");
        t.Rows[2].Cells[1].AddParagraph(ns.HasDuplicates ? "Yes" : "No");
        t.Rows[3].Cells[0].AddParagraph("All NS have A/AAAA");
        t.Rows[3].Cells[1].AddParagraph(ns.AllHaveAOrAaaa ? "Yes" : "No");
        t.Rows[4].Cells[0].AddParagraph("Delegation matches");
        t.Rows[4].Cells[1].AddParagraph(ns.DelegationMatches ? "Yes" : "No");
        t.Rows[5].Cells[0].AddParagraph("Glue complete");
        t.Rows[5].Cells[1].AddParagraph(ns.GlueRecordsComplete ? "Yes" : "No");
        t.Rows[6].Cells[0].AddParagraph("Glue consistent");
        t.Rows[6].Cells[1].AddParagraph(ns.GlueRecordsConsistent ? "Yes" : "No");
        t.Rows[7].Cells[0].AddParagraph("Distinct ASNs");
        t.Rows[7].Cells[1].AddParagraph(ns.AsnDistinctCount.ToString());
        t.Rows[8].Cells[0].AddParagraph("Status");
        t.Rows[8].Cells[1].AddParagraph(ns.Status ?? string.Empty);

        // NS list
        if (ns.NsRecords != null && ns.NsRecords.Count > 0)
        {
            headings.AddItem("Name Servers", baseLevel);
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var n in ns.NsRecords) if (!string.IsNullOrWhiteSpace(n)) list.AddItem(n);
        }

        // Good posture
        if (scope != ReportScope.Minimal && ns.Positives != null && ns.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            var plist = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in ns.Positives) if (!string.IsNullOrWhiteSpace(p?.Title)) plist.AddItem(p!.Title);
        }

        var assessments = ns.Assessments?.ToList() ?? new System.Collections.Generic.List<DomainDetective.Assessment>();
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

        // References
        if (ns.References != null && ns.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var r in ns.References) if (!string.IsNullOrWhiteSpace(r)) list.AddItem(r);
        }
    }

    /// <summary>
    /// Projector-aware overload using SectionProjectors.NsSection.
    /// </summary>
    public static void Write(WordDocument doc, WordList headings, int baseLevel,
        DomainDetective.Reports.SectionProjectors.NsSection sec,
        DomainDetective.Views.NsInfo? original,
        string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sec == null) throw new ArgumentNullException(nameof(sec));

        headings.AddItem("Summary", baseLevel);
        var rows = sec.Summary.Count > 0 ? sec.Summary : new System.Collections.Generic.List<(string,string)>() { ("Status", sec.Status) };
        var t = doc.AddTable(rows.Count, 2, WordTableStyle.TableGrid);
        for (int i=0;i<rows.Count;i++){ t.Rows[i].Cells[0].AddParagraph(rows[i].Item1); t.Rows[i].Cells[1].AddParagraph(rows[i].Item2); }

        if (original != null && (original.NsRecords?.Count ?? 0) > 0)
        { headings.AddItem("Name Servers", baseLevel); var list = doc.AddList(WordListStyle.Bulleted); foreach (var n in original.NsRecords!) if (!string.IsNullOrWhiteSpace(n)) list.AddItem(n); }

        if (sec.Positives.Count > 0)
        { headings.AddItem("Good posture", baseLevel); var plist = doc.AddList(WordListStyle.Bulleted); foreach (var p in sec.Positives) plist.AddItem(p); }

        var f = sec.Findings; if (!showInfoFindings) f = f.Where(x => !string.Equals(x.Severity, "Info", System.StringComparison.OrdinalIgnoreCase)).ToList();
        if (f.Count > 0)
        { headings.AddItem("Findings", baseLevel); var ft = doc.AddTable(f.Count + 1, 4, WordTableStyle.TableGrid); ft.Rows[0].Cells[0].AddParagraph("Severity"); ft.Rows[0].Cells[1].AddParagraph("Code"); ft.Rows[0].Cells[2].AddParagraph("Target"); ft.Rows[0].Cells[3].AddParagraph("Message"); for (int i=0;i<f.Count;i++){ var a=f[i]; ft.Rows[i+1].Cells[0].AddParagraph(a.Severity); ft.Rows[i+1].Cells[1].AddParagraph(a.Code); ft.Rows[i+1].Cells[2].AddParagraph(a.Target); ft.Rows[i+1].Cells[3].AddParagraph(a.Message);} }

        if (sec.References.Count > 0)
        { headings.AddItem("References", baseLevel); var list = doc.AddList(WordListStyle.Bulleted); foreach (var r in sec.References) list.AddItem(r); }
    }
}
