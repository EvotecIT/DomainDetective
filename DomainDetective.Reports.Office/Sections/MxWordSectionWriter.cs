using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Writes MX section content into a Word document.
/// </summary>
public static class MxWordSectionWriter
{
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.MxInfo mx, string domain, ReportScope scope, bool showInfoFindings, bool includeNarrative = true)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (mx == null) throw new ArgumentNullException(nameof(mx));

        if (includeNarrative)
        {
            // Use generic MX narrative (static) for intro/why
            var nar = DomainDetective.Narratives.MxNarrative.Build(mx.Raw);
            if (!string.IsNullOrWhiteSpace(nar.Introduction)) { headings.AddItem("Introduction", baseLevel); doc.AddParagraph(nar.Introduction); }
            if (!string.IsNullOrWhiteSpace(nar.WhyItMatters)) { headings.AddItem("Why this matters", baseLevel); doc.AddParagraph(nar.WhyItMatters); }
        }

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("MX posture and integrity signals.");
        var t = doc.AddTable(11, 2, WordTableStyle.TableGrid);
        t.Rows[0].Cells[0].Paragraphs[0].Text = "MX Records";
        t.Rows[0].Cells[1].Paragraphs[0].Text = (mx.MxRecords?.Count ?? 0).ToString();
        t.Rows[1].Cells[0].Paragraphs[0].Text = "Priorities In Order";
        t.Rows[1].Cells[1].Paragraphs[0].Text = mx.PrioritiesInOrder ? "Yes" : "No";
        t.Rows[2].Cells[0].Paragraphs[0].Text = "Backup Servers";
        t.Rows[2].Cells[1].Paragraphs[0].Text = mx.HasBackupServers ? "Yes" : "No";
        t.Rows[3].Cells[0].Paragraphs[0].Text = "IPv6 Supported";
        t.Rows[3].Cells[1].Paragraphs[0].Text = mx.Ipv6Supported ? "Yes" : "No";
        t.Rows[4].Cells[0].Paragraphs[0].Text = "TTL Uniform";
        t.Rows[4].Cells[1].Paragraphs[0].Text = mx.MxTtlUniform ? "Yes" : "No";
        t.Rows[5].Cells[0].Paragraphs[0].Text = "RRset Consistent Across NS";
        t.Rows[5].Cells[1].Paragraphs[0].Text = mx.MxRrsetConsistentAcrossNs ? "Yes" : "No";
        t.Rows[6].Cells[0].Paragraphs[0].Text = "Targets Consistent Across NS";
        t.Rows[6].Cells[1].Paragraphs[0].Text = mx.TargetAddressConsistentAcrossNs ? "Yes" : "No";
        t.Rows[7].Cells[0].Paragraphs[0].Text = "Null MX";
        t.Rows[7].Cells[1].Paragraphs[0].Text = mx.HasNullMx ? "Yes" : "No";
        t.Rows[8].Cells[0].Paragraphs[0].Text = "Status";
        t.Rows[8].Cells[1].Paragraphs[0].Text = mx.Status ?? string.Empty;
        t.Rows[9].Cells[0].Paragraphs[0].Text = "Primary Provider";
        t.Rows[9].Cells[1].Paragraphs[0].Text = mx.ProviderPrimary ?? string.Empty;
        t.Rows[10].Cells[0].Paragraphs[0].Text = "Gateways";
        t.Rows[10].Cells[1].Paragraphs[0].Text = (mx.ProviderGateways != null && mx.ProviderGateways.Count > 0)
            ? string.Join(", ", mx.ProviderGateways)
            : string.Empty;

        if (scope == ReportScope.Minimal) return;

        // Good posture
        if (scope != ReportScope.Minimal && mx.Positives != null && mx.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            doc.AddParagraph("This domain demonstrates the following positive posture:");
            var plist = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in mx.Positives)
            {
                if (!string.IsNullOrWhiteSpace(p?.Title)) plist.AddItem(p!.Title);
            }
        }

        var assessments = (mx.Assessments ?? Array.Empty<DomainDetective.Assessment>()).ToList();
        if (!showInfoFindings) assessments = assessments.Where(a => a.Severity != DomainDetective.AssessmentSeverity.Info).ToList();
        if (assessments.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            doc.AddParagraph("The following issues were detected:");
            var ft = doc.AddTable(assessments.Count + 1, 4, WordTableStyle.TableGrid);
            ft.Rows[0].Cells[0].Paragraphs[0].Text = "Severity";
            ft.Rows[0].Cells[1].Paragraphs[0].Text = "Code";
            ft.Rows[0].Cells[2].Paragraphs[0].Text = "Target";
            ft.Rows[0].Cells[3].Paragraphs[0].Text = "Message";
            for (int i = 0; i < assessments.Count; i++)
            {
                var a = assessments[i];
                ft.Rows[i + 1].Cells[0].Paragraphs[0].Text = a.Severity.ToString();
                ft.Rows[i + 1].Cells[1].Paragraphs[0].Text = a.Code ?? string.Empty;
                ft.Rows[i + 1].Cells[2].Paragraphs[0].Text = a.Target ?? string.Empty;
                ft.Rows[i + 1].Cells[3].Paragraphs[0].Text = a.Message;
            }
        }

        // Evidence: list MX RRs
        if (mx.MxRecords != null && mx.MxRecords.Count > 0)
        {
            headings.AddItem("Evidence", baseLevel);
            doc.AddParagraph("MX records discovered for this domain:");
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var rr in mx.MxRecords) list.AddItem(rr);
        }

        // Provider Help: official docs for detected provider(s)
        try { ProviderHelpWordSectionWriter.Write(doc, headings, baseLevel, mx.ProviderHelp ?? Array.Empty<DomainDetective.Views.ProviderHelpLinks>()); } catch { }

        // References
        if (mx.References != null && mx.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            doc.AddParagraph("Further reading and relevant standards.");
            var rlist = doc.AddList(WordListStyle.Bulleted);
            foreach (var r in mx.References) if (!string.IsNullOrWhiteSpace(r)) rlist.AddItem(r);
        }
    }
}
