using System;
using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Excel;

namespace DomainDetective.Reports.Office;

public static partial class MessageHeaderOfficeReport {
    private static void WriteOverviewSheet(ExcelDocument document, IReadOnlyList<MessageEvidenceReport> messages) {
        document.Properties.Title = "Email Message Analysis";
        document.Properties.Creator = "DomainDetective";
        document.ApplicationProperties.Company = "Evotec";
        document.ApplicationProperties.ApplicationName = "OfficeIMO.Excel";
        var composer = document.AddSheet("Overview", ExcelSheetNameValidationMode.Sanitize).Report();
        composer.Title("Email Message Analysis", $"Generated {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC");
        var briefs = messages.Select(message => message.Brief).ToArray();
        composer.KpiRow(new (string, object?)[] {
            ("Messages", messages.Count),
            ("Errors", briefs.Sum(brief => brief.Findings.Count(a => a.Severity == AssessmentSeverity.Error))),
            ("Warnings", briefs.Sum(brief => brief.Findings.Count(a => a.Severity == AssessmentSeverity.Warning)))
        }, perRow: 3);
        ExcelReportLayout.Section(composer, "How to read this report");
        ExcelReportLayout.Paragraph(composer, "Review the brief and next steps first. Navigation links to supporting evidence sheets; filter their Input column to follow a specific message. Receiver-reported passes are distinct from cryptographic verification.");
        for (var i = 0; i < messages.Count; i++) {
            var message = messages[i];
            var brief = briefs[i];
            ExcelReportLayout.Section(composer, "Message " + (i + 1) + " — " + brief.SubjectLabel);
            ExcelReportLayout.Paragraph(composer, message.ContextLabel);
            ExcelReportLayout.Paragraph(composer, brief.Summary);
            ExcelReportLayout.Section(composer, "What the evidence establishes");
            foreach (var line in brief.Evidence) { ExcelReportLayout.Paragraph(composer, line); }
            ExcelReportLayout.Section(composer, "Priority findings");
            if (brief.Findings.Count == 0) { ExcelReportLayout.Paragraph(composer, "No warning or error assessments were raised."); }
            foreach (var finding in brief.Findings) {
                ExcelReportLayout.Paragraph(composer, MessageHeaderReport.VisibleText($"{finding.Severity}: {finding.Message} [{finding.Code}]"));
            }
            ExcelReportLayout.Section(composer, "Recommended next steps");
            foreach (var action in brief.Actions) {
                ExcelReportLayout.Paragraph(composer, MessageHeaderReport.VisibleText(action.Title));
                if (!string.IsNullOrWhiteSpace(action.Why)) { ExcelReportLayout.Paragraph(composer, "Why: " + MessageHeaderReport.VisibleText(action.Why)); }
                if (!string.IsNullOrWhiteSpace(action.How)) { ExcelReportLayout.Paragraph(composer, "Action: " + MessageHeaderReport.VisibleText(action.How)); }
                if (!string.IsNullOrWhiteSpace(action.Verify)) { ExcelReportLayout.Paragraph(composer, "Verify: " + MessageHeaderReport.VisibleText(action.Verify)); }
            }
            if (brief.Actions.Count == 0) { ExcelReportLayout.Paragraph(composer, "Retain the original MIME message and corroborate receiver claims before making a trust decision."); }
        }
        var sheet = composer.Sheet;
        for (var column = 1; column <= 6; column++) { sheet.SetColumnWidth(column, ExcelColumnWidth.Characters(18)); }
        for (var row = 1; row < composer.CurrentRow; row++) {
            sheet.Cell(row, 1).SetWrapText();
            sheet.Cell(row, 1).SetVerticalAlignment(ExcelVerticalAlignment.Top);
        }
        sheet.SetRowHeight(1, ExcelColumnWidth.Length(OfficeLength.Points(36)));
        sheet.SetRowHeight(2, ExcelColumnWidth.Length(OfficeLength.Points(25)));
        sheet.Range("A1:F1").Merge();
        sheet.Range("A2:F2").Merge();
        sheet.Cell(1, 1).SetFontSize(OfficeLength.Points(20));
        sheet.View.Freeze(topRows: 3);
        sheet.View.ShowGridlines = false;
        sheet.PageSetup.ApplyLayout(new ExcelPrintLayoutOptions { Preset = ExcelPrintLayoutPreset.Report, PrintArea = "A1:F" + (composer.CurrentRow - 1), FitToHeight = 0, Orientation = OfficeIMO.OfficePageOrientation.Portrait });
    }
}
