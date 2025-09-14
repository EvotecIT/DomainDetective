using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Writes DNSSEC section content into a Word document.
/// </summary>
public static class DnssecWordSectionWriter
{
    /// <summary>
    /// Writes the DNSSEC section.
    /// </summary>
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.DnssecStatusInfo ds, string domain, ReportScope scope, bool showInfoFindings, bool includeNarrative = true)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (ds == null) throw new ArgumentNullException(nameof(ds));

        if (includeNarrative)
        {
            var nar = DomainDetective.Narratives.DnssecNarrative.Build(ds.Raw, ds.Assessments);
            if (!string.IsNullOrWhiteSpace(nar.Introduction)) { headings.AddItem("Introduction", baseLevel); doc.AddParagraph(nar.Introduction); }
            if (!string.IsNullOrWhiteSpace(nar.WhyItMatters)) { headings.AddItem("Why this matters", baseLevel); doc.AddParagraph(nar.WhyItMatters); }
        }

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("DNSSEC chain, DS/DNSKEY status, and trust anchor hints.");
        var t = doc.AddTable(6, 2, WordTableStyle.TableGrid);
        t.Rows[0].Cells[0].Paragraphs[0].Text = "DNSKEY AD";
        t.Rows[0].Cells[1].Paragraphs[0].Text = ds.AuthenticData ? "Yes" : "No";
        t.Rows[1].Cells[0].Paragraphs[0].Text = "DS AD";
        t.Rows[1].Cells[1].Paragraphs[0].Text = ds.DsAuthenticData ? "Yes" : "No";
        t.Rows[2].Cells[0].Paragraphs[0].Text = "DS ↔ DNSKEY";
        t.Rows[2].Cells[1].Paragraphs[0].Text = ds.DsMatch ? "Match" : "Check";
        t.Rows[3].Cells[0].Paragraphs[0].Text = "Chain of Trust";
        t.Rows[3].Cells[1].Paragraphs[0].Text = ds.ChainValid ? "Valid" : "Invalid";
        t.Rows[4].Cells[0].Paragraphs[0].Text = "Root Anchor";
        t.Rows[4].Cells[1].Paragraphs[0].Text = ds.RootAnchorExpiration.HasValue
            ? ((ds.RootAnchorExpiration.Value - DateTimeOffset.UtcNow).TotalDays >= 0 ? $"Expires in {Math.Ceiling((ds.RootAnchorExpiration.Value - DateTimeOffset.UtcNow).TotalDays):F0} days" : "Expired")
            : "Unknown";
        t.Rows[5].Cells[0].Paragraphs[0].Text = "Status";
        t.Rows[5].Cells[1].Paragraphs[0].Text = ds.Status ?? string.Empty;

        if (scope == ReportScope.Minimal) return;

        // Good posture
        if (ds.Positives != null && ds.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            doc.AddParagraph("This domain demonstrates the following positive posture:");
            var plist = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in ds.Positives)
            {
                if (!string.IsNullOrWhiteSpace(p?.Title)) plist.AddItem(p!.Title);
            }
        }

        // Findings
        var assessments = (ds.Assessments ?? Array.Empty<DomainDetective.Assessment>()).ToList();
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
        if (ds.References != null && ds.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            doc.AddParagraph("Further reading and relevant standards.");
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var r in ds.References) if (!string.IsNullOrWhiteSpace(r)) list.AddItem(r);
        }
    }

    /// <summary>
    /// Projector-aware overload using SectionProjectors.DnssecSection.
    /// </summary>
    public static void Write(WordDocument doc, WordList headings, int baseLevel,
        DomainDetective.Reports.SectionProjectors.DnssecSection sec,
        DomainDetective.Views.DnssecStatusInfo? original,
        string domain, ReportScope scope, bool showInfoFindings, bool includeNarrative = true)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sec == null) throw new ArgumentNullException(nameof(sec));

        if (includeNarrative && original != null)
        {
            var nar = DomainDetective.Narratives.DnssecNarrative.Build(original.Raw, original.Assessments);
            if (!string.IsNullOrWhiteSpace(nar.Introduction)) { headings.AddItem("Introduction", baseLevel); doc.AddParagraph(nar.Introduction); }
            if (!string.IsNullOrWhiteSpace(nar.WhyItMatters)) { headings.AddItem("Why this matters", baseLevel); doc.AddParagraph(nar.WhyItMatters); }
        }

        headings.AddItem("Summary", baseLevel);
        var rows = sec.Summary.Count > 0 ? sec.Summary : new System.Collections.Generic.List<(string,string)>()
        { ("DS Match", sec.HasDs?"Yes":"No"), ("Chain Valid", sec.Validates?"Yes":"No"), ("Status", sec.Status) };
        var t = doc.AddTable(rows.Count, 2, WordTableStyle.TableGrid);
        for (int i=0;i<rows.Count;i++){ t.Rows[i].Cells[0].Paragraphs[0].Text = rows[i].Item1; t.Rows[i].Cells[1].Paragraphs[0].Text = rows[i].Item2; }

        if (sec.Positives.Count > 0)
        { headings.AddItem("Good posture", baseLevel); var list = doc.AddList(WordListStyle.Bulleted); foreach (var p in sec.Positives) list.AddItem(p); }

        var f = sec.Findings; if (!showInfoFindings) f = f.Where(x => !string.Equals(x.Severity, "Info", System.StringComparison.OrdinalIgnoreCase)).ToList();
        if (f.Count > 0)
        { headings.AddItem("Findings", baseLevel); var ft = doc.AddTable(f.Count + 1, 4, WordTableStyle.TableGrid); ft.Rows[0].Cells[0].AddParagraph("Severity"); ft.Rows[0].Cells[1].AddParagraph("Code"); ft.Rows[0].Cells[2].AddParagraph("Target"); ft.Rows[0].Cells[3].AddParagraph("Message"); for (int i=0;i<f.Count;i++){ var a=f[i]; ft.Rows[i+1].Cells[0].AddParagraph(a.Severity); ft.Rows[i+1].Cells[1].AddParagraph(a.Code); ft.Rows[i+1].Cells[2].AddParagraph(a.Target); ft.Rows[i+1].Cells[3].AddParagraph(a.Message);} }

        if (sec.References.Count > 0)
        { headings.AddItem("References", baseLevel); var list = doc.AddList(WordListStyle.Bulleted); foreach (var r in sec.References) list.AddItem(r); }
    }
}
