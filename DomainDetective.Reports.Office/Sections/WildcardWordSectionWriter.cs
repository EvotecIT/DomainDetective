using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

public static class WildcardWordSectionWriter
{
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.WildcardDnsInfo wc, string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (wc == null) throw new ArgumentNullException(nameof(wc));

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("Wildcard DNS detection by sampling random subdomains.");
        var t = doc.AddTable(4, 2, WordTableStyle.TableGrid);
        t.Rows[0].Cells[0].AddParagraph("Wildcard");
        t.Rows[0].Cells[1].AddParagraph(wc.CatchAll ? "Enabled" : "Disabled");
        t.Rows[1].Cells[0].AddParagraph("SOA Present");
        t.Rows[1].Cells[1].AddParagraph(wc.SoaExists ? "Yes" : "No");
        t.Rows[2].Cells[0].AddParagraph("NS Present");
        t.Rows[2].Cells[1].AddParagraph(wc.NsExists ? "Yes" : "No");
        t.Rows[3].Cells[0].AddParagraph("Status");
        t.Rows[3].Cells[1].AddParagraph(wc.Status ?? string.Empty);

        // Names tested/resolved
        if (wc.TestedNames != null && wc.TestedNames.Count > 0)
        {
            headings.AddItem("Sampled Names", baseLevel);
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var n in wc.TestedNames) if (!string.IsNullOrWhiteSpace(n)) list.AddItem(n);
        }
        if (wc.ResolvedNames != null && wc.ResolvedNames.Count > 0)
        {
            headings.AddItem("Resolved Names", baseLevel);
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var n in wc.ResolvedNames) if (!string.IsNullOrWhiteSpace(n)) list.AddItem(n);
        }
        if (wc.ResolvedAddresses != null && wc.ResolvedAddresses.Count > 0)
        {
            headings.AddItem("Resolved Addresses", baseLevel);
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var n in wc.ResolvedAddresses) if (!string.IsNullOrWhiteSpace(n)) list.AddItem(n);
        }

        // Findings
        var assessments = wc.Assessments?.ToList() ?? new System.Collections.Generic.List<DomainDetective.Assessment>();
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
        if (wc.References != null && wc.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var r in wc.References) if (!string.IsNullOrWhiteSpace(r)) list.AddItem(r);
        }
    }
}

