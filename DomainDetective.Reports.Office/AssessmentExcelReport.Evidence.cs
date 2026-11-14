using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using OfficeIMO.Excel;

namespace DomainDetective.Reports.Office;

public static partial class AssessmentExcelReport {
    /// <summary>
    /// Groups presentation-ready tables by check key. Reading Sources again would resurrect hidden Known flags,
    /// conditional facts and unattributed values that the assessment reader has already resolved.
    /// </summary>
    private static void WriteEvidence(ExcelDocument workbook, DomainAssessmentReport report) {
        var tables = report.Domains.SelectMany(d => d.Checks.SelectMany(c => c.Evidence
            .Where(static e => e.Kind == CheckEvidenceKind.Table)
            .Select(e => (Domain: d.Domain, Check: c, Evidence: e))));
        foreach (var group in tables.GroupBy(static row => row.Check.Key, StringComparer.Ordinal)) {
            // OfficeIMO cleans forbidden characters, shortens to 31 characters and adds case-insensitive (2), (3)
            // suffixes in encounter order; keep those generic naming rules in the workbook owner.
            ExcelSheet sheet = workbook.AddWorksheet("Evidence · " + group.First().Check.Title, ExcelSheetNameValidationMode.Sanitize);
            // A check can have several evidence tables with different schemas. Union their labelled columns while
            // retaining the table title on each row, including nested evidence's parent-row attribution.
            var columns = new List<(string Label, int Occurrence)>();
            foreach (var table in group) {
                foreach (var column in EvidenceColumns(table.Evidence)) {
                    if (!columns.Contains(column)) { columns.Add(column); }
                }
            }
            string[] headers = new[] { "Domain", "Evidence" }.Concat(columns.Select(static c =>
                (c.Label is "Domain" or "Evidence" or "Export note" ? "Evidence: " : string.Empty) + c.Label
                + (c.Occurrence > 1 ? " (" + c.Occurrence.ToString(CultureInfo.InvariantCulture) + ")" : string.Empty)))
                .Concat(new[] { "Export note" }).ToArray();
            WriteHeader(sheet, 1, headers);
            int row = 1;
            foreach (var table in group) {
                List<(string Label, int Occurrence)> sourceColumns = EvidenceColumns(table.Evidence);
                foreach (List<string> cells in table.Evidence.Rows) {
                    object?[] values = new object?[headers.Length];
                    values[0] = table.Domain;
                    values[1] = table.Evidence.Title;
                    for (int index = 0; index < sourceColumns.Count; index++) {
                        values[2 + columns.IndexOf(sourceColumns[index])] = index < cells.Count ? cells[index] : string.Empty;
                    }
                    WriteRow(sheet, ++row, values);
                    sheet.CellFontName(row, 1, "Consolas");
                }
                if (table.Evidence.Omitted > 0) {
                    object?[] values = new object?[headers.Length];
                    values[0] = table.Domain;
                    values[1] = table.Evidence.Title;
                    values[values.Length - 1] = table.Evidence.Omitted.ToString("N0", CultureInfo.InvariantCulture)
                        + " rows omitted from the assessment model; not available in this export.";
                    WriteRow(sheet, ++row, values);
                    sheet.CellFontColor(row, headers.Length, Muted);
                }
            }
            FinishSheet(sheet, 1, row, headers.Length);
        }
    }

    private static List<(string Label, int Occurrence)> EvidenceColumns(CheckEvidence evidence) {
        var result = new List<(string Label, int Occurrence)>();
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (string label in evidence.Columns) {
            counts.TryGetValue(label, out int previous);
            counts[label] = previous + 1;
            result.Add((label, previous + 1));
        }
        return result;
    }
}
