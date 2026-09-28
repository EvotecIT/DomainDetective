using System;
using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;

namespace DomainDetective.Reports.Office;

public static partial class MessageHeaderOfficeReport {
    private static void WriteOverviewSheet(ExcelDocument document, IReadOnlyList<MessageHeaderAnalysis> messages) {
        document.AsFluent().Info(i => i.Title("Email Message Analysis").Author("DomainDetective").Company("Evotec").Application("OfficeIMO.Excel")).End();
        var composer = new SheetComposer(document, "Overview");
        composer.Title("Email Message Analysis", $"Generated {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC");
        var briefs = messages.Select(MessageHeaderReportBrief.Build).ToArray();
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
            ExcelReportLayout.Paragraph(composer, MessageHeaderReport.VisibleText(message.From) + " → " + MessageHeaderReport.VisibleText(message.To));
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
        for (var column = 1; column <= 6; column++) { sheet.SetColumnWidth(column, 18); }
        for (var row = 1; row < composer.CurrentRow; row++) {
            sheet.CellWrapText(row, 1);
            sheet.CellVerticalAlign(row, 1, ExcelVerticalAlignment.Top);
        }
        sheet.SetRowHeight(1, 36);
        sheet.SetRowHeight(2, 25);
        sheet.MergeRange("A1:F1");
        sheet.MergeRange("A2:F2");
        sheet.CellFontSize(1, 1, 20);
        sheet.Freeze(topRows: 3);
        sheet.SetGridlinesVisible(false);
        sheet.ApplyPrintLayout(new ExcelPrintLayoutOptions { Preset = ExcelPrintLayoutPreset.Report, PrintArea = "A1:F" + (composer.CurrentRow - 1), FitToHeight = 0, Orientation = OfficeIMO.OfficePageOrientation.Portrait });
    }
}
