using System;
using OfficeIMO.Excel;

namespace DomainDetective.Reports.Office;

/// <summary>Report-specific text bands shared by Office spreadsheet writers.</summary>
internal static class ExcelReportLayout {
    internal static void Paragraph(ExcelReportBuilder composer, string text, int columns = 6) {
        if (string.IsNullOrEmpty(text)) { return; }
        foreach (var part in ExcelReportText.Parts(text)) {
            var row = composer.CurrentRow;
            composer.Paragraph(part);
            StyleBand(composer, row, part, columns, false);
        }
    }

    internal static void Section(ExcelReportBuilder composer, string text, int columns = 6) {
        foreach (var part in ExcelReportText.Parts(text)) {
            var row = composer.CurrentRow;
            composer.Section(part);
            StyleBand(composer, row, part, columns, true);
        }
    }

    private static void StyleBand(ExcelReportBuilder composer, int row, string text, int columns, bool section) {
        if (columns < 1 || columns > 26) { throw new ArgumentOutOfRangeException(nameof(columns)); }
        composer.Sheet.Range("A" + row + ":" + (char)('A' + columns - 1) + row).Merge();
        composer.Sheet.Cell(row, 1).SetWrapText();
        composer.Sheet.SetRowHeight(row, ExcelColumnWidth.Length(OfficeLength.Points(Math.Min(409, Math.Max(section ? 30 : 28, Math.Ceiling(text.Length / 112.0) * 16 + 12)))));
    }
}
