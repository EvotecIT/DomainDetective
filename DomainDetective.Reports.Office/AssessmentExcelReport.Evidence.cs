using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using OfficeIMO.Excel;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Reports.Office;

public static partial class AssessmentExcelReport {
    /// <summary>
    /// One sheet for every captured fact, raw record, list and table, grouped by domain and check. Each check opens with
    /// a shaded heading row and its rows sit in an outline group under it. Tables keep their own column headings.
    /// Presentation-ready evidence is used as is: reading Sources again would resurrect hidden Known flags, conditional
    /// facts and unattributed values that the assessment reader has already resolved.
    /// </summary>
    /// <returns>The heading row of each check that has evidence, for links from the Checks sheet.</returns>
    private static Dictionary<CheckAssessment, int> WriteEvidence(ExcelSheet sheet, DomainAssessmentReport report) {
        var rows = new Dictionary<CheckAssessment, int>();
        bool several = Several(report);
        Title(sheet, "Evidence · " + Scope(report), "Captured facts, published records, lists and tables, grouped by check.");
        int width = 3;
        foreach (CheckEvidence table in report.Domains.SelectMany(static d => d.Checks).SelectMany(static c => c.Evidence)
            .Where(static e => e.Kind == CheckEvidenceKind.Table)) {
            width = System.Math.Max(width, table.Columns.Count + 1);
        }
        int row = 3;
        foreach (DomainAssessment domain in report.Domains) {
            foreach (CheckAssessment check in domain.Checks) {
                if (check.Facts.Count == 0 && check.Evidence.Count == 0) { continue; }
                int heading = row += 2;
                rows[check] = heading;
                WriteCell(sheet, heading, 1, (several ? domain.Domain + " · " : string.Empty) + check.Title).SetBold().SetFontSize(OfficeLength.Points(10));
                WriteCell(sheet, heading, 2, Wording.AreaLabel(check.Area)).SetColor(OfficeColor.Parse(Muted));
                WriteCell(sheet, heading, 3, Wording.OutcomeLabel(check.Outcome)).SetColor(OfficeColor.Parse(OutcomeColor(check.Outcome))).SetBold();
                for (int column = 1; column <= width; column++) {
                    sheet.Cell(heading, column).SetFillColor(OfficeColor.Parse(Surface));
                    sheet.Cell(heading, column).SetBorder(ExcelCellBorders.Top, ExcelBorderStyle.Thin, OfficeColor.Parse(Ink));
                }
                for (int index = 0; index < check.Facts.Count; index++) {
                    CheckFact fact = check.Facts[index];
                    WriteRow(sheet, ++row, index == 0 ? "Facts" : null, fact.Label, fact.Value);
                    Label(sheet, row);
                    sheet.Cell(row, 3).SetWrapText();
                }
                foreach (CheckEvidence evidence in check.Evidence) {
                    if (evidence.Kind == CheckEvidenceKind.Code) {
                        WriteRow(sheet, ++row, evidence.Title, "Record", evidence.Text ?? string.Empty);
                        Label(sheet, row);
                        sheet.Cell(row, 3).SetFontFamily(Mono).SetWrapText();
                    } else if (evidence.Kind == CheckEvidenceKind.List) {
                        for (int index = 0; index < evidence.Items.Count; index++) {
                            WriteRow(sheet, ++row, index == 0 ? evidence.Title : null, (index + 1).ToString(CultureInfo.InvariantCulture), evidence.Items[index]);
                            Label(sheet, row);
                            sheet.Cell(row, 3).SetWrapText();
                        }
                    } else if (evidence.Kind == CheckEvidenceKind.Table) {
                        WriteRow(sheet, ++row, new object?[] { evidence.Title }.Concat(evidence.Columns.Cast<object?>()).ToArray());
                        for (int column = 1; column <= evidence.Columns.Count + 1; column++) {
                            sheet.Cell(row, column).SetBold();
                            sheet.Cell(row, column).SetColor(OfficeColor.Parse(Muted));
                            sheet.Cell(row, column).SetBorder(ExcelCellBorders.Bottom, ExcelBorderStyle.Thin, OfficeColor.Parse(Rule));
                        }
                        foreach (List<string> cells in evidence.Rows) {
                            WriteRow(sheet, ++row, new object?[] { null }.Concat(cells.Cast<object?>()).ToArray());
                            if (cells.Count > 1) { sheet.Cell(row, 3).SetWrapText(); }
                        }
                    }
                    if (evidence.Omitted > 0) {
                        WriteCell(sheet, ++row, 2, evidence.Omitted.ToString("N0", CultureInfo.InvariantCulture)
                            + (evidence.Kind == CheckEvidenceKind.Table ? " rows" : " items")
                            + " omitted from the assessment model; not available in this export.").SetColor(OfficeColor.Parse(Muted));
                    }
                }
                if (row > heading) { sheet.GroupRows(heading + 1, row, 1); }
            }
        }
        if (rows.Count == 0) { WriteCell(sheet, 5, 1, "No evidence was captured."); }
        sheet.SetOutlineSummary(summaryBelow: false);
        sheet.SetColumnWidth(1, ExcelColumnWidth.Characters(24));
        sheet.SetColumnWidth(2, ExcelColumnWidth.Characters(30));
        sheet.SetColumnWidth(3, ExcelColumnWidth.Characters(60));
        for (int column = 4; column <= width; column++) { sheet.SetColumnWidth(column, ExcelColumnWidth.Characters(22)); }
        // Evidence tables can be wider than a page; print them at full size rather than shrink them unreadable.
        Paper(sheet, 3, 0, Tabs[2], fitWidth: false);
        return rows;
    }

    private static void Label(ExcelSheet sheet, int row) {
        sheet.Cell(row, 1).SetColor(OfficeColor.Parse(Muted));
        sheet.Cell(row, 2).SetColor(OfficeColor.Parse(Muted));
    }
}
