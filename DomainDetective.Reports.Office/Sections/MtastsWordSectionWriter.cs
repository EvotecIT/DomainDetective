using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Writes MTA-STS section content into a Word document.
/// </summary>
public static class MtastsWordSectionWriter
{
    /// <summary>
    /// Writes the MTA-STS section.
    /// </summary>
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.MtastsInfo mtasts, string domain, ReportScope scope, bool showInfoFindings, bool includeNarrative = true)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (mtasts == null) throw new ArgumentNullException(nameof(mtasts));

        if (includeNarrative)
        {
            var nar = DomainDetective.Narratives.MtaStsNarrative.Build(mtasts.Raw, mtasts.Assessments);
            if (!string.IsNullOrWhiteSpace(nar.Introduction)) { headings.AddItem("Introduction", baseLevel); doc.AddParagraph(nar.Introduction); }
            if (!string.IsNullOrWhiteSpace(nar.WhyItMatters)) { headings.AddItem("Why this matters", baseLevel); doc.AddParagraph(nar.WhyItMatters); }
        }

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("MTA-STS DNS and policy file status.");
        var t = doc.AddTable(8, 2, WordTableStyle.TableGrid);
        t.Rows[0].Cells[0].Paragraphs[0].Text = "DNS Policy TXT";
        t.Rows[0].Cells[1].Paragraphs[0].Text = mtasts.DnsRecordPresent ? (mtasts.DnsRecordValid ? "Present (valid)" : "Present (invalid)") : "Missing";
        t.Rows[1].Cells[0].Paragraphs[0].Text = "DNS TTL (s)";
        t.Rows[1].Cells[1].Paragraphs[0].Text = mtasts.DnsRecordTtl?.ToString() ?? "-";
        t.Rows[2].Cells[0].Paragraphs[0].Text = "Policy File";
        t.Rows[2].Cells[1].Paragraphs[0].Text = mtasts.PolicyPresent ? (mtasts.PolicyValid ? "Present (valid)" : "Present (invalid)") : "Missing";
        t.Rows[3].Cells[0].Paragraphs[0].Text = "Mode";
        t.Rows[3].Cells[1].Paragraphs[0].Text = mtasts.Mode ?? string.Empty;
        t.Rows[4].Cells[0].Paragraphs[0].Text = "Max-Age";
        t.Rows[4].Cells[1].Paragraphs[0].Text = mtasts.MaxAge.ToString();
        t.Rows[5].Cells[0].Paragraphs[0].Text = "MX Present";
        t.Rows[5].Cells[1].Paragraphs[0].Text = mtasts.HasMx ? "Yes" : "No";
        t.Rows[6].Cells[0].Paragraphs[0].Text = "MX Aligned";
        t.Rows[6].Cells[1].Paragraphs[0].Text = mtasts.MxAligned ? "Yes" : "No";
        t.Rows[7].Cells[0].Paragraphs[0].Text = "Status";
        t.Rows[7].Cells[1].Paragraphs[0].Text = mtasts.Status ?? string.Empty;

        if (scope == ReportScope.Minimal) return;

        var missing = mtasts.MissingMxFromPolicy ?? Array.Empty<string>();
        if (missing.Length > 0)
        {
            headings.AddItem("Highlights", baseLevel);
            var p = doc.AddParagraph("MX missing from policy:");
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var s in missing) list.AddItem(s);
        }

        // Good posture
        if (scope != ReportScope.Minimal && mtasts.Positives != null && mtasts.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            doc.AddParagraph("This domain demonstrates the following positive posture:");
            var plist = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in mtasts.Positives)
            {
                if (!string.IsNullOrWhiteSpace(p?.Title)) plist.AddItem(p!.Title);
            }
        }

        var assessments = (mtasts.Assessments ?? Array.Empty<DomainDetective.Assessment>()).ToList();
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

        // References
        if (mtasts.References != null && mtasts.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            doc.AddParagraph("Further reading and relevant standards.");
            WordLinkHelpers.AddReferencesList(doc, mtasts.References);
        }
    }

    /// <summary>
    /// Projector-aware overload using SectionProjectors.MtastsSection.
    /// </summary>
    public static void Write(WordDocument doc, WordList headings, int baseLevel,
        DomainDetective.Reports.SectionProjectors.MtastsSection sec,
        DomainDetective.Views.MtastsInfo? original,
        string domain, ReportScope scope, bool showInfoFindings, bool includeNarrative = true)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sec == null) throw new ArgumentNullException(nameof(sec));

        if (includeNarrative && original != null)
        {
            var nar = DomainDetective.Narratives.MtaStsNarrative.Build(original.Raw, original.Assessments);
            if (!string.IsNullOrWhiteSpace(nar.Introduction)) { headings.AddItem("Introduction", baseLevel); doc.AddParagraph(nar.Introduction); }
            if (!string.IsNullOrWhiteSpace(nar.WhyItMatters)) { headings.AddItem("Why this matters", baseLevel); doc.AddParagraph(nar.WhyItMatters); }
        }

        headings.AddItem("Summary", baseLevel);
        var rows = sec.Summary.Count > 0 ? sec.Summary : new System.Collections.Generic.List<(string Key,string Value)>()
        { ("Status", sec.Status), ("Mode", sec.Mode), ("DNS Present", sec.DnsRecordPresent?"Yes":"No"), ("Policy Valid", sec.PolicyValid?"Yes":"No"), ("MX Aligned", sec.MxAligned?"Yes":"No") };
        var t = doc.AddTable(rows.Count, 2, WordTableStyle.TableGrid);
        for (int i=0;i<rows.Count;i++){ t.Rows[i].Cells[0].AddParagraph(rows[i].Key); t.Rows[i].Cells[1].AddParagraph(rows[i].Value); }

        if (sec.Positives.Count > 0)
        { headings.AddItem("Good posture", baseLevel); var list = doc.AddList(WordListStyle.Bulleted); foreach (var p in sec.Positives) list.AddItem(p); }

        var f = sec.Findings; if (!showInfoFindings) f = f.Where(x => !string.Equals(x.Severity, "Info", StringComparison.OrdinalIgnoreCase)).ToList();
        if (f.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            var ft = doc.AddTable(f.Count + 1, 4, WordTableStyle.TableGrid);
            ft.Rows[0].Cells[0].AddParagraph("Severity"); ft.Rows[0].Cells[1].AddParagraph("Code"); ft.Rows[0].Cells[2].AddParagraph("Target"); ft.Rows[0].Cells[3].AddParagraph("Message");
            for (int i=0;i<f.Count;i++){ var a=f[i]; ft.Rows[i+1].Cells[0].AddParagraph(a.Severity); ft.Rows[i+1].Cells[1].AddParagraph(a.Code); ft.Rows[i+1].Cells[2].AddParagraph(a.Target); ft.Rows[i+1].Cells[3].AddParagraph(a.Message);}        
        }

        if (original != null && (original.MissingMxFromPolicy?.Length ?? 0) > 0)
        {
            headings.AddItem("Highlights", baseLevel);
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var s in original.MissingMxFromPolicy!) list.AddItem($"Missing from policy: {s}");
        }

        if (sec.References.Count > 0)
        { headings.AddItem("References", baseLevel); WordLinkHelpers.AddReferencesList(doc, sec.References); }
    }
}
