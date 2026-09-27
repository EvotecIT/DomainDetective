using System;
using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;

namespace DomainDetective.Reports.Office;

public static partial class ExcelCompositionReport {
    private static void BuildRecommendationsSheet(ExcelDocument doc, IReadOnlyList<object> items) {
        var recSheet = new SheetComposer(doc, "Recommendations");
        recSheet.Title("Action Plan", "Use the reason, corrective action and verification guidance to plan changes from the supplied assessment evidence.");
        var recRows = new List<string[]>();
        foreach (var evidence in AssessmentEvidenceInfo.Collect(items)) {
            foreach (var action in evidence.Recommendations) {
                recRows.Add(new[] { evidence.Subject, action.Code ?? "General", action.Title ?? action.Code ?? string.Empty, action.Why ?? string.Empty, action.How ?? string.Empty, action.Verify ?? string.Empty }.Select(MessageHeaderReport.VisibleText).ToArray());
            }
        }
        if (recRows.Count == 0) recRows.Add(new[] { "—", "—", "No recommendations", "No actionable recommendations are present in the supplied views.", "Retain the assessment evidence.", "Confirm the scope of checks performed." });
        var recRange = ExcelReportText.Table(recSheet, new[] { "Domain", "Code", "Title", "Why", "Action", "Verify" }, recRows.ToArray(), new[] { 18d, 16d, 30d, 45d, 55d, 45d });
        recSheet.Sheet.MergeRange("A1:F1");
        recSheet.Sheet.MergeRange("A2:F2");
        recSheet.Sheet.CellFontSize(1, 1, 20);
        recSheet.Sheet.CellWrapText(2, 1);
        recSheet.Sheet.SetRowHeight(1, 36);
        recSheet.Sheet.SetRowHeight(2, 32);
        recSheet.Sheet.SetGridlinesVisible(false);
        recSheet.Finish(autoFitColumns: false, autoFitRows: false);

    }
}
