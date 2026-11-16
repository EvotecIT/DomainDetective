using System;
using System.Collections.Generic;
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
    private const string Accent = "0F766E";
    private const string Surface = "F5F6F7";
    private const string Rule = "D9DDE1";
    private const string Mono = "Consolas";
    // Table headers and bands: a low-saturation slate, so pale bands stay quiet behind status fills.
    private const string TableAccent = "334155";

    // Pale fills behind the same tone text the HTML report uses. Incomplete evidence stays neutral grey.
    private const string HighFill = "FDE8E8";
    private const string ElevatedFill = "FEF3C7";
    private const string GoodFill = "E3F4E8";
    private const string NeutralFill = "EEF0F2";
    private const string InformationalFill = "E0F0FA";

    /// <summary>
    /// Workbook theme: report ink and muted text, slate as accent 1 (table headers and bands), status tones as
    /// the other accents, and Aptos for text.
    /// </summary>
    private static readonly OfficeIMO.OfficeTheme Theme = OfficeIMO.OfficeTheme.Minimal.WithName("DomainDetective")
        .WithPalette(new OfficeIMO.OfficeThemePalette(OfficeColor.Parse("FFFFFF"), OfficeColor.Parse(Ink), OfficeColor.Parse(Muted),
            OfficeColor.Parse(TableAccent), OfficeColor.Parse(Elevated), OfficeColor.Parse(Good), OfficeColor.Parse(High),
            OfficeColor.Parse(Informational), OfficeColor.Parse("64748B"), OfficeColor.Parse(Good), OfficeColor.Parse(Elevated), OfficeColor.Parse(High)))
        .WithFonts(new OfficeIMO.OfficeThemeFonts(new OfficeIMO.OfficeThemeFont("Aptos Display", new[] { "Aptos", "Calibri" }), new OfficeIMO.OfficeThemeFont("Aptos", new[] { "Calibri" })));

    private static readonly string[] Tabs = { Accent, "334155", "94A3B8" };

    private static string OutcomeColor(CheckOutcome outcome) => outcome switch {
        CheckOutcome.Error => High,
        CheckOutcome.Warning => Elevated,
        CheckOutcome.Incomplete => Muted,
        CheckOutcome.Pass => Good,
        _ => Informational
    };

    private static string FillFor(string tone) => tone switch {
        High => HighFill,
        Elevated => ElevatedFill,
        Good => GoodFill,
        Informational => InformationalFill,
        _ => NeutralFill
    };

    /// <summary>Uses typed cell values, so DNS text beginning with '=' is never treated as a formula. Null leaves a blank cell.</summary>
    private static void WriteRow(ExcelSheet sheet, int row, params object?[] values) {
        for (int index = 0; index < values.Length; index++) {
            if (values[index] == null) { continue; }
            WriteCell(sheet, row, index + 1, values[index]!);
        }
    }

    private static ExcelCell WriteCell(ExcelSheet sheet, int row, int column, object value) {
        ExcelCell cell = sheet.Cell(row, column);
        cell.SetValue(value);
        cell.SetFontFamily("Aptos");
        cell.SetFontSize(OfficeLength.Points(9));
        cell.SetColor(OfficeColor.Parse(Ink));
        cell.SetVerticalAlignment(ExcelVerticalAlignment.Top);
        return cell;
    }

    private static void WriteHeader(ExcelSheet sheet, int row, params string[] headers) {
        WriteRow(sheet, row, headers);
        for (int column = 1; column <= headers.Length; column++) {
            sheet.Cell(row, column).SetBold();
            sheet.Cell(row, column).SetVerticalAlignment(ExcelVerticalAlignment.Bottom);
        }
    }

    /// <summary>A status cell: tone text on a pale fill of the same tone, so the state survives filtering and sorting.</summary>
    private static void Tone(ExcelSheet sheet, int row, int column, string tone) {
        sheet.Cell(row, column).SetColor(OfficeColor.Parse(tone));
        sheet.Cell(row, column).SetFillColor(OfficeColor.Parse(FillFor(tone)));
        sheet.Cell(row, column).SetBold();
    }

    private static void Wrap(ExcelSheet sheet, int firstRow, int lastRow, params int[] columns) {
        foreach (int column in columns) {
            for (int row = firstRow; row <= lastRow; row++) { sheet.Cell(row, column).SetWrapText(); }
        }
    }

    private static void MonoColumn(ExcelSheet sheet, int firstRow, int lastRow, int column) {
        for (int row = firstRow; row <= lastRow; row++) { sheet.Cell(row, column).SetFontFamily(Mono); }
    }

    /// <summary>Sheet title band: a large title and one muted line under it. Text overflows; nothing is merged.</summary>
    private static void Title(ExcelSheet sheet, string title, string? subtitle) {
        WriteCell(sheet, 1, 1, title).SetBold().SetFontSize(OfficeLength.Points(14));
        sheet.Cell(1, 1).SetVerticalAlignment(ExcelVerticalAlignment.Center);
        sheet.SetRowHeight(1, ExcelColumnWidth.Length(OfficeLength.Points(24)));
        if (!string.IsNullOrEmpty(subtitle)) { WriteCell(sheet, 2, 1, subtitle!).SetColor(OfficeColor.Parse(Muted)); }
    }

    /// <summary>
    /// Turns a written range into a native Excel table with banded rows and a filter, freezes the header and leading
    /// columns, and sets deliberate widths. Columns without a width keep Excel's default.
    /// </summary>
    private static void Table(ExcelSheet sheet, string name, int headerRow, int lastRow, int columns, params double[] widths) {
        lastRow = Math.Max(lastRow, headerRow + 1);
        string range = "A" + Text(headerRow) + ":" + ColumnName(columns) + Text(lastRow);
        sheet.AddTable(range, true, name, ExcelTableStyle.TableStyleMedium2, includeAutoFilter: true);
        for (int column = 1; column <= columns; column++) {
            // The table style draws the teal header band; white text keeps it readable.
            sheet.Cell(headerRow, column).SetColor(OfficeColor.Parse("FFFFFF"));
        }
        for (int index = 0; index < widths.Length && index < columns; index++) {
            if (widths[index] > 0) { sheet.SetColumnWidth(index + 1, ExcelColumnWidth.Characters(widths[index])); }
        }
    }

    private static void Paper(ExcelSheet sheet, int frozenRows, int frozenColumns, string tab, bool fitWidth = true) {
        if (frozenRows > 0 || frozenColumns > 0) { sheet.View.Freeze(topRows: frozenRows, leftColumns: frozenColumns); }
        sheet.SetTabColor(OfficeColor.Parse(tab));
        sheet.PageSetup.Orientation = OfficeIMO.OfficePageOrientation.Landscape;
        if (fitWidth) {
            sheet.PageSetup.FitToWidth = 1;
            sheet.PageSetup.FitToHeight = 0;
        }
    }

    private static void Link(ExcelSheet sheet, int row, int column, string sheetName, int targetRow, string display) {
        sheet.SetInternalLink(row, column, "'" + sheetName.Replace("'", "''") + "'!A" + Text(targetRow), display, style: true,
            tooltip: "Evidence for " + display);
        ExcelCell cell = sheet.Cell(row, column);
        cell.SetFontFamily("Aptos");
        cell.SetFontSize(OfficeLength.Points(9));
        cell.SetColor(OfficeColor.Parse(Accent));
        cell.SetVerticalAlignment(ExcelVerticalAlignment.Top);
    }

    /// <summary>Score bars on a fixed 0–100 scale, so a 50 reads as half a bar whatever else is on the sheet.</summary>
    private static void ScoreBars(ExcelSheet sheet, string column, int firstRow, int lastRow) {
        if (lastRow < firstRow) { return; }
        ExcelConditionalFormattingInfo rule = sheet.Range(column + Text(firstRow) + ":" + column + Text(lastRow))
            .ConditionalFormat().DataBar(OfficeColor.Parse("5EAAA8"));
        rule.DataBarThresholds = new[] {
            new ExcelConditionalFormatThreshold { Type = "num", Value = "0" },
            new ExcelConditionalFormatThreshold { Type = "num", Value = "100" }
        };
        sheet.UpdateConditionalFormattingRule(rule);
    }

    private static void Center(ExcelSheet sheet, int firstRow, int lastRow, params int[] columns) {
        foreach (int column in columns) {
            for (int row = firstRow; row <= lastRow; row++) { sheet.Cell(row, column).SetHorizontalAlignment(ExcelHorizontalAlignment.Center); }
        }
    }

    private static string Text(int value) => value.ToString(CultureInfo.InvariantCulture);

    private static string ColumnName(int column) {
        string name = string.Empty;
        while (column > 0) {
            column--;
            name = (char)('A' + column % 26) + name;
            column /= 26;
        }
        return name;
    }

    private static object?[] Row(bool withDomain, string domain, params object?[] values) {
        if (!withDomain) { return values; }
        var all = new List<object?>(values.Length + 1) { domain };
        all.AddRange(values);
        return all.ToArray();
    }
}
