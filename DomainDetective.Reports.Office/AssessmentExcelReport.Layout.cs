using System;
using System.Globalization;
using OfficeIMO.Excel;

namespace DomainDetective.Reports.Office;

public static partial class AssessmentExcelReport {
    private const string Ink = "202428";
    private const string Muted = "687078";
    private const string High = "B91C1C";
    private const string Elevated = "B45309";
    private const string Good = "15803D";
    private const string Informational = "0369A1";

    private static string OutcomeColor(CheckOutcome outcome) => outcome switch {
        CheckOutcome.Error => High,
        CheckOutcome.Warning => Elevated,
        CheckOutcome.Incomplete => Muted,
        CheckOutcome.Pass => Good,
        _ => Informational
    };

    /// <summary>Uses typed cell values, so DNS text beginning with '=' is never treated as a formula.</summary>
    private static void WriteRow(ExcelSheet sheet, int row, params object?[] values) {
        for (int index = 0; index < values.Length; index++) {
            int column = index + 1;
            sheet.Cell(row, column).SetValue(values[index] ?? string.Empty);
            sheet.Cell(row, column).SetFontFamily("Aptos");
            sheet.Cell(row, column).SetFontSize(OfficeLength.Points(9));
            sheet.Cell(row, column).SetColor(OfficeColor.Parse(Ink));
            sheet.Cell(row, column).SetWrapText();
            sheet.Cell(row, column).SetVerticalAlignment(ExcelVerticalAlignment.Top);
        }
    }

    private static void WriteHeader(ExcelSheet sheet, int row, params string[] headers) {
        WriteRow(sheet, row, headers);
        for (int column = 1; column <= headers.Length; column++) { sheet.Cell(row, column).SetBold(); }
    }

    /// <summary>Formats a plain range rather than a styled Excel table, keeping every cell free of fills and merges.</summary>
    private static void FinishSheet(ExcelSheet sheet, int headerRow, int lastRow, int columns,
        params (int Column, double Width)[] wrappedColumns) {
        sheet.View.Freeze(topRows: headerRow);
        sheet.Range("A" + headerRow.ToString(CultureInfo.InvariantCulture) + ":" + ColumnName(columns)
            + Math.Max(headerRow, lastRow).ToString(CultureInfo.InvariantCulture)).AutoFilter();
        sheet.AutoFitColumns();
        // Prose and raw records must wrap instead of making the workbook hundreds of characters wide.
        foreach (var column in wrappedColumns) { sheet.SetColumnWidth(column.Column, ExcelColumnWidth.Characters(column.Width)); }
        sheet.AutoFitRows();
        sheet.PageSetup.Orientation = OfficeIMO.OfficePageOrientation.Landscape;
        sheet.PageSetup.FitToWidth = 1;
        sheet.PageSetup.FitToHeight = 0;
    }

    private static string ColumnName(int column) {
        string name = string.Empty;
        while (column > 0) {
            column--;
            name = (char)('A' + column % 26) + name;
            column /= 26;
        }
        return name;
    }
}
