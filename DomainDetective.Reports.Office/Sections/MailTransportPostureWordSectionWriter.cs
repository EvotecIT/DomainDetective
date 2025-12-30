using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

public static class MailTransportPostureWordSectionWriter
{
    public static void Write(
        WordDocument doc,
        WordList headings,
        int baseLevel,
        DomainDetective.Reports.SectionProjectors.MailTransportPostureSection sec,
        string domain,
        ReportScope scope,
        bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sec == null) throw new ArgumentNullException(nameof(sec));

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph($"Roll-up of inbound mail transport security posture for {domain} (MX, TLS, MTA-STS, TLS-RPT, DANE).");

        var rows = sec.Summary.Count > 0
            ? sec.Summary
            : new System.Collections.Generic.List<(string Key, string Value)> { ("Status", sec.Status) };

        var t = doc.AddTable(rows.Count, 2, WordTableStyle.TableGrid);
        for (int i = 0; i < rows.Count; i++)
        {
            t.Rows[i].Cells[0].AddParagraph(rows[i].Key);
            t.Rows[i].Cells[1].AddParagraph(rows[i].Value);
        }

        if (scope == ReportScope.Minimal)
        {
            return;
        }

        if (sec.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            doc.AddParagraph("This domain demonstrates the following positive posture:");
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in sec.Positives.Where(x => !string.IsNullOrWhiteSpace(x)))
            {
                list.AddItem(p);
            }
        }

        var findings = sec.Findings.ToList();
        if (!showInfoFindings)
        {
            findings = findings
                .Where(x => !string.Equals(x.Severity, "Info", StringComparison.OrdinalIgnoreCase))
                .ToList();
        }

        if (findings.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            doc.AddParagraph("The following issues were detected:");

            var ft = doc.AddTable(findings.Count + 1, 4, WordTableStyle.TableGrid);
            ft.Rows[0].Cells[0].AddParagraph("Severity");
            ft.Rows[0].Cells[1].AddParagraph("Code");
            ft.Rows[0].Cells[2].AddParagraph("Target");
            ft.Rows[0].Cells[3].AddParagraph("Message");
            for (int i = 0; i < findings.Count; i++)
            {
                var a = findings[i];
                ft.Rows[i + 1].Cells[0].AddParagraph(a.Severity ?? string.Empty);
                ft.Rows[i + 1].Cells[1].AddParagraph(a.Code ?? string.Empty);
                ft.Rows[i + 1].Cells[2].AddParagraph(a.Target ?? string.Empty);
                ft.Rows[i + 1].Cells[3].AddParagraph(a.Message ?? string.Empty);
            }
        }

        if (sec.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            doc.AddParagraph("Further reading and relevant standards.");
            WordLinkHelpers.AddReferencesList(doc, sec.References);
        }
    }
}

