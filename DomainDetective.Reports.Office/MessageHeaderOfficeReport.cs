using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using OfficeIMO.Word;
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;

namespace DomainDetective.Reports.Office;

/// <summary>Word and Excel writers for the shared message-evidence report.</summary>
public static partial class MessageHeaderOfficeReport {
    /// <summary>Writes message evidence as a Word document.</summary>
    public static void GenerateWord(string path, IReadOnlyList<MessageHeaderAnalysis> messages) {
        Validate(path, messages);
        using var document = WordDocument.Create(path);
        document.AddParagraph("Email Message Analysis").SetBold().SetFontSize(24);
        document.AddParagraph("Receiver claims, gateway provenance, and cryptographic verification are separate evidence.").SetFontSize(11);
        for (var i = 0; i < messages.Count; i++) {
            document.AddParagraph("Message " + (i + 1)).SetBold().SetFontSize(18);
            foreach (var section in MessageHeaderReport.Build(messages[i]).Where(section => section.Rows.Count > 0)) {
                document.AddParagraph(section.Title).SetBold().SetFontSize(14);
                // Wide evidence grids are rendered as individual records, retaining readable type.
                var records = section.Columns.Count == 2
                    ? new[] { section.Rows }
                    : section.Rows.Select(row => (IReadOnlyList<IReadOnlyList<string>>)section.Columns.Select((label, index) => (IReadOnlyList<string>)new[] { label, row[index] }).ToArray()).ToArray();
                var recordIndex = 0;
                foreach (var rows in records) {
                    if (records.Length > 1) { document.AddParagraph("Record " + (++recordIndex)).SetBold().SetFontSize(11); }
                    var table = document.AddTable(rows.Count + 1, 2, WordTableStyle.TableGrid);
                    table.SetWidthPercentage(100);
                    table.SetColumnWidthsPercentage(30, 70);
                    table.RepeatHeaderRowAtTheTopOfEachPage = true;
                    table.AllowRowToBreakAcrossPages = true;
                    for (var column = 0; column < 2; column++) {
                        var cell = table.Rows[0].Cells[column];
                        cell.ShadingFillColorHex = "E6EDF5";
                        cell.Paragraphs[0].Text = column == 0 ? "Field" : "Evidence";
                        cell.Paragraphs[0].Bold = true;
                    }
                    for (var row = 0; row < rows.Count; row++) {
                        for (var column = 0; column < 2; column++) {
                            var cell = table.Rows[row + 1].Cells[column];
                            cell.ShadingFillColorHex = row % 2 == 0 ? "F4F7FA" : "FFFFFF";
                            cell.Paragraphs[0].Text = rows[row][column];
                            cell.Paragraphs[0].FontSize = 10;
                            cell.Paragraphs[0].Bold = column == 0;
                        }
                    }
                    document.AddParagraph(string.Empty);
                }
            }
        }
        document.Save();
    }

    /// <summary>Writes readable overview and evidence worksheets with explicit string cells.</summary>
    public static void GenerateExcel(string path, IReadOnlyList<MessageHeaderAnalysis> messages) {
        Validate(path, messages);
        using var document = ExcelDocument.Create(path);
        var evidence = messages.Select(MessageHeaderReport.Build).ToArray();
        foreach (var title in evidence.SelectMany(sections => sections).Select(section => section.Title).Distinct()) {
            var sections = evidence.Select((values, index) => new { Section = values.First(section => section.Title == title), Message = index + 1 }).ToArray();
            if (sections.All(value => value.Section.Rows.Count == 0)) { continue; }
            var columns = new[] { "Input" }.Concat(sections[0].Section.Columns).ToArray();
            var rows = sections.SelectMany(value => value.Section.Rows.Select(row => new[] { value.Message.ToString(System.Globalization.CultureInfo.InvariantCulture) }.Concat(row).ToArray())).ToArray();
            if (columns.Length > 8) {
                // Keep large route and signature records readable on screen and in print.
                rows = sections.SelectMany(value => value.Section.Rows.SelectMany((row, record) => value.Section.Columns.Select((field, column) => new[] {
                    value.Message.ToString(System.Globalization.CultureInfo.InvariantCulture), (record + 1).ToString(System.Globalization.CultureInfo.InvariantCulture), field, row[column]
                }))).ToArray();
                columns = new[] { "Input", "Record", "Field", "Value" };
            }
            WriteEvidenceSheet(document, title == "Message" ? "Overview" : title, title, columns, rows);
        }
        document.Save();
    }

    private static void Validate(string path, IReadOnlyList<MessageHeaderAnalysis> messages) {
        if (messages == null || messages.Count == 0) { throw new ArgumentException("No messages to report.", nameof(messages)); }
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)) ?? ".");
    }
}
