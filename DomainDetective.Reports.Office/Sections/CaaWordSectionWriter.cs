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
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var r in caa.References) if (!string.IsNullOrWhiteSpace(r)) list.AddItem(r);
        }
    }
}

