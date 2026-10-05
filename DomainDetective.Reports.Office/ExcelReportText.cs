using System;
using System.Collections.Generic;
using System.Linq;
using System.Data;
using OfficeIMO.Excel.Fluent;

namespace DomainDetective.Reports.Office;

/// <summary>Preserves report text in bounded, ordered pieces instead of truncating Excel cells.</summary>
internal static class ExcelReportText {
    internal static string[] Parts(string value, int maximum = 2000) {
        var parts = new List<string>();
        if (value.Length == 0) { return new[] { string.Empty }; }
        for (var offset = 0; offset < value.Length;) {
            var length = Math.Min(maximum, value.Length - offset);
            if (offset + length < value.Length && char.IsHighSurrogate(value[offset + length - 1]) && char.IsLowSurrogate(value[offset + length])) { length--; }
            parts.Add(value.Substring(offset, length));
            offset += length;
        }
        return parts.ToArray();
    }

    internal static string Table(SheetComposer composer, string[] columns, string[][] rows, double[] widths, string? title = null) {
        var expanded = rows.Any(row => row.Where((text, index) => text.Length > Math.Max(128, (widths[index] - 4) * 18)).Any());
        (columns, rows) = Expand(columns, rows, widths.Select(width => Math.Max(128, (int)(width - 4) * 18)).ToArray());
        if (expanded) { var adjusted = widths.ToList(); adjusted.Insert(1, 12); widths = adjusted.ToArray(); }
        using var data = new DataTable();
        foreach (var column in columns) { data.Columns.Add(column, typeof(string)); }
        foreach (var row in rows) { data.Rows.Add(row.Cast<object>().ToArray()); }
        var range = composer.TableFrom(data, title: title, freezeHeaderRow: true);
        var headerRow = int.Parse(new string(range.Split(':')[0].Where(char.IsDigit).ToArray()), System.Globalization.CultureInfo.InvariantCulture);
        for (var column = 0; column < columns.Length; column++) {
            composer.Sheet.SetColumnWidth(column + 1, widths[column]);
            for (var row = headerRow; row <= headerRow + rows.Length; row++) {
                composer.Sheet.CellWrapText(row, column + 1);
                composer.Sheet.CellVerticalAlign(row, column + 1, OfficeIMO.Excel.ExcelVerticalAlignment.Top);
            }
        }
        composer.Sheet.SetRowHeight(headerRow, 32);
        for (var row = 0; row < rows.Length; row++) {
            var lines = rows[row].Select((value, column) => Math.Max(1, (int)Math.Ceiling(value.Length / Math.Max(1, widths[column] - 4)))).Max();
            composer.Sheet.SetRowHeight(headerRow + row + 1, Math.Min(409, Math.Max(28, lines * 16 + 12)));
        }
        return range;
    }

    internal static (string[] Columns, string[][] Rows) Expand(string[] columns, string[][] rows, int[] limits) {
        if (!rows.Any(row => row.Where((text, index) => text.Length > limits[index]).Any())) { return (columns, rows); }
        var result = new List<string[]>();
        foreach (var row in rows) {
            var parts = row.Select((text, index) => Parts(text, limits[index])).ToArray();
            var count = parts.Max(values => values.Length);
            for (var part = 0; part < count; part++) {
                var values = parts.Select(values => values.Length == 1 ? values[0] : part < values.Length ? values[part] : string.Empty).ToList();
                values.Insert(1, (part + 1).ToString(System.Globalization.CultureInfo.InvariantCulture) + "/" + count);
                result.Add(values.ToArray());
            }
        }
        var labels = columns.ToList();
        labels.Insert(1, "Text part");
        return (labels.ToArray(), result.ToArray());
    }
}
