using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Reports;
using OfficeIMO.Word;
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;

namespace DomainDetective.Reports.Office;

internal static class AssessmentEvidenceOfficeSections {
    internal static void WriteWord(WordDocument document, WordList headings, IEnumerable<AssessmentEvidenceInfo> sections, bool showInfoFindings) {
        foreach (var section in sections) {
            headings.AddItem("Assessment findings and actions — " + MessageHeaderReport.VisibleText(section.Subject));
            document.AddParagraph("Findings from every completed check are prioritized below, followed by the supplied actions and verification steps. Technical records appear in the detailed sections when requested.");
            foreach (var finding in section.Assessments.Where(finding => showInfoFindings || finding.Severity != AssessmentSeverity.Info)) {
                document.AddParagraph(MessageHeaderReport.VisibleText($"{finding.Severity} · {finding.Category} · {finding.Target} [{finding.Code}]")).SetBold();
                document.AddParagraph(MessageHeaderReport.VisibleText(finding.Message));
            }
            headings.AddItem("Recommended actions", 1);
            foreach (var action in section.Recommendations) {
                document.AddParagraph(MessageHeaderReport.VisibleText(action.Title)).SetBold();
                if (!string.IsNullOrWhiteSpace(action.Why)) { document.AddParagraph(MessageHeaderReport.VisibleText(action.Why)); }
                if (!string.IsNullOrWhiteSpace(action.How)) { document.AddParagraph("Action: " + MessageHeaderReport.VisibleText(action.How)); }
                if (!string.IsNullOrWhiteSpace(action.Verify)) { document.AddParagraph("Verify: " + MessageHeaderReport.VisibleText(action.Verify)); }
            }
        }
    }

    internal static void WriteExcel(ExcelDocument document, IReadOnlyList<AssessmentEvidenceInfo> sections, bool showInfoFindings) {
        if (sections.Count == 0) { return; }
        var composer = new SheetComposer(document, "Findings");
        composer.Title("Assessment findings");
        ExcelReportLayout.Section(composer, "Coverage");
        ExcelReportLayout.Paragraph(composer, "This evidence appendix retains findings from every supplied assessment view, including checks without dedicated technical sections. Use the overview and action plan first. Long values continue in ordered Text part rows.");
        var rows = sections.SelectMany(section => section.Assessments.Where(a => showInfoFindings || a.Severity != AssessmentSeverity.Info).Select(a => new[] {
            MessageHeaderReport.VisibleText(section.Subject), a.Severity.ToString(), MessageHeaderReport.VisibleText(a.Category),
            MessageHeaderReport.VisibleText(a.Target), MessageHeaderReport.VisibleText(a.Message), MessageHeaderReport.VisibleText(a.Code)
        })).ToArray();
        var range = ExcelReportText.Table(composer, new[] { "Subject", "Severity", "Category", "Target", "Finding", "Code" }, rows, new[] { 18d, 12d, 18d, 24d, 80d, 35d }, "Findings");
        composer.Sheet.MergeRange("A1:F1");
        composer.Sheet.CellFontSize(1, 1, 18);
        composer.Sheet.SetRowHeight(1, 32);
        composer.Sheet.SetGridlinesVisible(false);
        composer.Sheet.CellWrapText(1, 1);
        composer.Finish(autoFitColumns: false, autoFitRows: false);
    }
}
