using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

public static class CaaWordSectionWriter
{
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.CaaInfo caa, string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (caa == null) throw new ArgumentNullException(nameof(caa));

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("Certification Authority Authorization policy summary.");
        var t = doc.AddTable(6, 2, WordTableStyle.TableGrid);
        t.Rows[0].Cells[0].AddParagraph("Valid Records");
        t.Rows[0].Cells[1].AddParagraph(caa.ValidRecords.ToString());
        t.Rows[1].Cells[0].AddParagraph("Invalid Records");
        t.Rows[1].Cells[1].AddParagraph(caa.InvalidRecords.ToString());
        t.Rows[2].Cells[0].AddParagraph("Conflicting");
        t.Rows[2].Cells[1].AddParagraph(caa.Conflicting ? "Yes" : "No");
        t.Rows[3].Cells[0].AddParagraph("Duplicate Issuers");
        t.Rows[3].Cells[1].AddParagraph(caa.HasDuplicateIssuers ? "Yes" : "No");
        t.Rows[4].Cells[0].AddParagraph("Status");
        t.Rows[4].Cells[1].AddParagraph(caa.Status ?? string.Empty);
        t.Rows[5].Cells[0].AddParagraph("Inline Summary");
        t.Rows[5].Cells[1].AddParagraph(caa.Summary ?? string.Empty);

        // Issuers / report mailboxes
        if (caa.CanIssueCertificatesForDomain != null && caa.CanIssueCertificatesForDomain.Count > 0)
        {
            headings.AddItem("Authorized Issuers", baseLevel);
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var v in caa.CanIssueCertificatesForDomain) if (!string.IsNullOrWhiteSpace(v)) list.AddItem(v);
        }
        if (caa.CanIssueWildcardCertificatesForDomain != null && caa.CanIssueWildcardCertificatesForDomain.Count > 0)
        {
            headings.AddItem("Wildcard Issuers", baseLevel);
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var v in caa.CanIssueWildcardCertificatesForDomain) if (!string.IsNullOrWhiteSpace(v)) list.AddItem(v);
        }
        if (caa.ReportViolationEmail != null && caa.ReportViolationEmail.Count > 0)
        {
            headings.AddItem("Report-Only Email", baseLevel);
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var v in caa.ReportViolationEmail) if (!string.IsNullOrWhiteSpace(v)) list.AddItem(v);
        }

        // Findings
        var assessments = caa.Assessments?.ToList() ?? new System.Collections.Generic.List<DomainDetective.Assessment>();
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
        if (caa.References != null && caa.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            WordLinkHelpers.AddReferencesList(doc, caa.References);
        }
    }

    /// <summary>
    /// Projector-aware overload using SectionProjectors.CaaSection.
    /// </summary>
    public static void Write(WordDocument doc, WordList headings, int baseLevel,
        DomainDetective.Reports.SectionProjectors.CaaSection sec,
        DomainDetective.Views.CaaInfo? original,
        string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sec == null) throw new ArgumentNullException(nameof(sec));

        headings.AddItem("Summary", baseLevel);
        var rows = sec.Summary.Count > 0 ? sec.Summary : new System.Collections.Generic.List<(string,string)>() { ("Status", sec.Status) };
        var t = doc.AddTable(rows.Count, 2, WordTableStyle.TableGrid);
        for (int i=0;i<rows.Count;i++){ t.Rows[i].Cells[0].AddParagraph(rows[i].Item1); t.Rows[i].Cells[1].AddParagraph(rows[i].Item2); }

        if (sec.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            doc.AddParagraph("This domain demonstrates the following positive posture:");
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in sec.Positives) list.AddItem(p);
        }

        if (original != null)
        {
            if ((original.CanIssueCertificatesForDomain?.Count ?? 0) > 0)
            { headings.AddItem("Authorized Issuers", baseLevel); var list = doc.AddList(WordListStyle.Bulleted); foreach (var v in original.CanIssueCertificatesForDomain!) if (!string.IsNullOrWhiteSpace(v)) list.AddItem(v); }
            if ((original.CanIssueWildcardCertificatesForDomain?.Count ?? 0) > 0)
            { headings.AddItem("Wildcard Issuers", baseLevel); var list = doc.AddList(WordListStyle.Bulleted); foreach (var v in original.CanIssueWildcardCertificatesForDomain!) if (!string.IsNullOrWhiteSpace(v)) list.AddItem(v); }
            if ((original.ReportViolationEmail?.Count ?? 0) > 0)
            { headings.AddItem("Report-Only Email", baseLevel); var list = doc.AddList(WordListStyle.Bulleted); foreach (var v in original.ReportViolationEmail!) if (!string.IsNullOrWhiteSpace(v)) list.AddItem(v); }
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
