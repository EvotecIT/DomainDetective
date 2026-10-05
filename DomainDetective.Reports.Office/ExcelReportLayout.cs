using System;
using OfficeIMO.Excel.Fluent;

namespace DomainDetective.Reports.Office;

/// <summary>Report-specific text bands shared by Office spreadsheet writers.</summary>
internal static class ExcelReportLayout {
    internal static void Paragraph(SheetComposer composer, string text, int columns = 6) {
        if (string.IsNullOrEmpty(text)) { return; }
        foreach (var part in ExcelReportText.Parts(text)) {
            var row = composer.CurrentRow;
            composer.Paragraph(part);
            StyleBand(composer, row, part, columns, false);
        }
    }

    internal static void Section(SheetComposer composer, string text, int columns = 6) {
        foreach (var part in ExcelReportText.Parts(text)) {
            var row = composer.CurrentRow;
            composer.Section(part);
            StyleBand(composer, row, part, columns, true);
        }
    }

    private static void StyleBand(SheetComposer composer, int row, string text, int columns, bool section) {
        if (columns < 1 || columns > 26) { throw new ArgumentOutOfRangeException(nameof(columns)); }
        composer.Sheet.MergeRange("A" + row + ":" + (char)('A' + columns - 1) + row);
        composer.Sheet.CellWrapText(row, 1);
        composer.Sheet.SetRowHeight(row, Math.Min(409, Math.Max(section ? 30 : 28, Math.Ceiling(text.Length / 112.0) * 16 + 12)));
    }
}
