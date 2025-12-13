using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

public static class RpkiWordSectionWriter
{
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.RpkiInfo rpki, string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (rpki == null) throw new ArgumentNullException(nameof(rpki));

        // Summary
        headings.AddItem("Summary", baseLevel);
        var t = doc.AddTable(4, 2, WordTableStyle.TableGrid);
        t.Rows[0].Cells[0].AddParagraph("Total IPs checked");
        t.Rows[0].Cells[1].AddParagraph(rpki.TotalChecked.ToString());
        t.Rows[1].Cells[0].AddParagraph("Valid per ROA");
        t.Rows[1].Cells[1].AddParagraph(rpki.ValidCount.ToString());
        t.Rows[2].Cells[0].AddParagraph("All valid");
        t.Rows[2].Cells[1].AddParagraph(rpki.AllValid ? "Yes" : "No");
        t.Rows[3].Cells[0].AddParagraph("Status");
        t.Rows[3].Cells[1].AddParagraph(rpki.Summary ?? rpki.Status ?? string.Empty);

        // Per-IP table
        if (rpki.Results != null && rpki.Results.Count > 0)
        {
            headings.AddItem("Per-IP Results", baseLevel);
            var rt = doc.AddTable(rpki.Results.Count + 1, 4, WordTableStyle.TableGrid);
            rt.Rows[0].Cells[0].AddParagraph("IP");
            rt.Rows[0].Cells[1].AddParagraph("Prefix");
            rt.Rows[0].Cells[2].AddParagraph("ASN");
            rt.Rows[0].Cells[3].AddParagraph("Valid");
            for (int i = 0; i < rpki.Results.Count; i++)
            {
                var r = rpki.Results[i];
                rt.Rows[i + 1].Cells[0].AddParagraph(r.IpAddress ?? string.Empty);
                rt.Rows[i + 1].Cells[1].AddParagraph(r.Prefix ?? string.Empty);
                rt.Rows[i + 1].Cells[2].AddParagraph(r.Asn.ToString());
                rt.Rows[i + 1].Cells[3].AddParagraph(r.Valid ? "Yes" : "No");
            }
        }

        // Good posture
        if (scope != ReportScope.Minimal && rpki.Positives != null && rpki.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in rpki.Positives)
            {
                if (!string.IsNullOrWhiteSpace(p?.Title)) list.AddItem(p!.Title);
            }
        }

        // Findings
        var assessments = rpki.Assessments?.ToList() ?? new System.Collections.Generic.List<DomainDetective.Assessment>();
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
        if (rpki.References != null && rpki.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            WordLinkHelpers.AddReferencesList(doc, rpki.References);
        }
    }

    /// <summary>
    /// Projector-aware overload using SectionProjectors.RpkiSection.
    /// </summary>
    public static void Write(WordDocument doc, WordList headings, int baseLevel,
        DomainDetective.Reports.SectionProjectors.RpkiSection sec,
        DomainDetective.Views.RpkiInfo? original,
        string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sec == null) throw new ArgumentNullException(nameof(sec));

        headings.AddItem("Summary", baseLevel);
        var t = doc.AddTable(sec.Summary.Count + 1, 2, WordTableStyle.TableGrid);
        int r = 0;
        foreach (var kv in sec.Summary) { t.Rows[r].Cells[0].AddParagraph(kv.Key); t.Rows[r].Cells[1].AddParagraph(kv.Value); r++; }
        t.Rows[r].Cells[0].AddParagraph("Status"); t.Rows[r].Cells[1].AddParagraph(sec.Status);

        if (original != null && (original.Results?.Count ?? 0) > 0)
        {
            headings.AddItem("Per-IP Results", baseLevel);
            var rt = doc.AddTable(original.Results.Count + 1, 4, WordTableStyle.TableGrid);
            rt.Rows[0].Cells[0].AddParagraph("IP"); rt.Rows[0].Cells[1].AddParagraph("Prefix"); rt.Rows[0].Cells[2].AddParagraph("ASN"); rt.Rows[0].Cells[3].AddParagraph("Valid");
            for (int i=0;i<original.Results.Count;i++){ var rr = original.Results[i]; rt.Rows[i+1].Cells[0].AddParagraph(rr.IpAddress ?? string.Empty); rt.Rows[i+1].Cells[1].AddParagraph(rr.Prefix ?? string.Empty); rt.Rows[i+1].Cells[2].AddParagraph(rr.Asn.ToString()); rt.Rows[i+1].Cells[3].AddParagraph(rr.Valid ? "Yes" : "No"); }
        }

        if (sec.Positives.Count > 0)
        { headings.AddItem("Good posture", baseLevel); var list = doc.AddList(WordListStyle.Bulleted); foreach (var p in sec.Positives) list.AddItem(p); }

        var f = sec.Findings; if (!showInfoFindings) f = f.Where(x => !string.Equals(x.Severity, "Info", System.StringComparison.OrdinalIgnoreCase)).ToList();
        if (f.Count > 0)
        { headings.AddItem("Findings", baseLevel); var ft = doc.AddTable(f.Count + 1, 4, WordTableStyle.TableGrid); ft.Rows[0].Cells[0].AddParagraph("Severity"); ft.Rows[0].Cells[1].AddParagraph("Code"); ft.Rows[0].Cells[2].AddParagraph("Target"); ft.Rows[0].Cells[3].AddParagraph("Message"); for (int i=0;i<f.Count;i++){ var a=f[i]; ft.Rows[i+1].Cells[0].AddParagraph(a.Severity); ft.Rows[i+1].Cells[1].AddParagraph(a.Code); ft.Rows[i+1].Cells[2].AddParagraph(a.Target); ft.Rows[i+1].Cells[3].AddParagraph(a.Message);} }

        if (sec.References.Count > 0)
        { headings.AddItem("References", baseLevel); var list = doc.AddList(WordListStyle.Bulleted); foreach (var r2 in sec.References) list.AddItem(r2); }
    }
}
