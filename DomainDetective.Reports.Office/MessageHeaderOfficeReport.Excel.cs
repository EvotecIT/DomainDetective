using System;
using System.Data;
using System.Linq;
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;

namespace DomainDetective.Reports.Office;

public static partial class MessageHeaderOfficeReport {
    private static void WriteEvidenceSheet(ExcelDocument document, string name, string title, string[] columns, string[][] rows) {
        (columns, rows) = ExcelReportText.Expand(columns, rows, columns.Select(column => Math.Max(128, (int)(ColumnWidth(column) - 4) * 20)).ToArray());
        var composer = new SheetComposer(document, name);
        var sheet = composer.Sheet;
        composer.Title(title == "Message" ? "Email Message Analysis" : title);
        composer.Paragraph("Reported claims and cryptographic verification remain separate. Filter by Input to compare messages. Text part labels identify ordered continuations of long values.");
        composer.Spacer();
        using var data = new DataTable();
        foreach (var column in columns) { data.Columns.Add(column, typeof(string)); }
        foreach (var row in rows) { data.Rows.Add(row.Cast<object>().ToArray()); }
        var headerRow = composer.CurrentRow;
        composer.TableFrom(data, style: ExcelTableStyle.TableStyleMedium2, freezeHeaderRow: true);
        var widths = columns.Select(ColumnWidth).ToArray();
        for (var column = 0; column < columns.Length; column++) {
            sheet.SetColumnWidth(column + 1, widths[column]);
            for (var row = headerRow; row <= headerRow + rows.Length; row++) {
                sheet.CellWrapText(row, column + 1);
                sheet.CellVerticalAlign(row, column + 1, ExcelVerticalAlignment.Top);
                sheet.CellFontSize(row, column + 1, 11);
            }
        }
        sheet.MergeRange("A1:" + ColumnName(columns.Length) + "1");
        sheet.MergeRange("A3:" + ColumnName(columns.Length) + "3");
        sheet.CellFontSize(1, 1, 20);
        sheet.CellFontColor(1, 1, "FFFFFF");
        for (var column = 1; column <= columns.Length; column++) { sheet.CellBackground(1, column, "152B45"); }
        sheet.CellFontColor(3, 1, "526579");
        sheet.CellWrapText(3, 1);
        sheet.SetRowHeight(1, 36);
        sheet.SetRowHeight(3, 32);
        sheet.SetRowHeight(headerRow, 32);
        for (var row = 0; row < rows.Length; row++) {
            var lines = rows[row].Select((value, column) => Math.Max(1, (int)Math.Ceiling(value.Length / Math.Max(1, widths[column] - 4)))).Max();
            sheet.SetRowHeight(headerRow + row + 1, Math.Min(409, Math.Max(26, lines * 16 + 10)));
        }
        sheet.Freeze(topRows: headerRow, leftCols: 1);
        sheet.SetGridlinesVisible(false);
        sheet.ApplyPrintLayout(new ExcelPrintLayoutOptions {
            Preset = ExcelPrintLayoutPreset.Report,
            PrintArea = "A1:" + ColumnName(columns.Length) + (headerRow + rows.Length),
            FitToHeight = 0,
            RepeatFirstRow = headerRow,
            RepeatLastRow = headerRow
        });
    }

    private static double ColumnWidth(string column) => column == "Input" || column == "Record" || column == "Text part" ? 12
        : column == "Value" || column == "Message" || column == "Explanation" || column == "Authentication claims" ? 95
        : column == "Properties" || column == "Signed headers" ? 65
        : column == "Field" || column == "Code" ? 38
        : column == "Outcome" || column == "Provenance" || column == "DNS used" || column == "Private IP" ? 20
        : 28;

    private static string ColumnName(int column) {
        var name = string.Empty;
        while (column > 0) { column--; name = (char)('A' + column % 26) + name; column /= 26; }
        return name;
    }
}
