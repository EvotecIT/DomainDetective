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
        WordReportCommon.ApplyBuiltInProperties(document, "Email Message Analysis", "Authentication and delivery evidence", "mail,headers,authentication", "Email", "DomainDetective");
        WordReportCommon.AddHeader(document, "DomainDetective", "Email Message Analysis");
        WordReportCommon.AddFooter(document, "Authentication claims and verification are separate evidence");
        document.Settings.UpdateFieldsOnOpen = true;
        document.AddParagraph("Email Message Analysis").SetBold().SetFontSize(24);
        document.AddParagraph($"{messages.Count} message(s) · Generated {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC").SetFontSize(11);
        var headings = document.AddTableOfContentList(WordListStyle.Headings111);
        headings.AddItem("Executive brief");
        document.AddParagraph("Start with the conclusions and next steps below. The evidence appendix preserves receiver claims, route records and original header fields for investigation.");
        for (var i = 0; i < messages.Count; i++) {
            var message = messages[i];
            var brief = MessageHeaderReportBrief.Build(message);
            headings.AddItem("Message " + (i + 1) + " — " + brief.SubjectLabel, 1);
            document.AddParagraph(MessageHeaderReport.VisibleText(message.From) + " → " + MessageHeaderReport.VisibleText(message.To)).SetItalic();
            document.AddParagraph(brief.Summary).SetBold();
            headings.AddItem("What the evidence establishes", 2);
            AddBriefList(document, brief.Evidence);
            headings.AddItem("Priority findings", 2);
            AddBriefList(document, brief.Findings.Select(a => MessageHeaderReport.VisibleText($"{a.Severity}: {a.Message} [{a.Code}]")), "No warning or error assessments were raised.");
            headings.AddItem("Recommended next steps", 2);
            foreach (var action in brief.Actions) {
                var actionHeading = document.AddParagraph(MessageHeaderReport.VisibleText(action.Title)).SetBold();
                actionHeading.KeepWithNext = true;
                if (!string.IsNullOrWhiteSpace(action.Why)) { document.AddParagraph(MessageHeaderReport.VisibleText(action.Why)); }
                if (!string.IsNullOrWhiteSpace(action.How)) { document.AddParagraph("Action: " + MessageHeaderReport.VisibleText(action.How)); }
                if (!string.IsNullOrWhiteSpace(action.Verify)) { document.AddParagraph("Verify: " + MessageHeaderReport.VisibleText(action.Verify)); }
            }
            if (brief.Actions.Count == 0) { document.AddParagraph("Retain the original MIME message and corroborate receiver claims before making a trust decision."); }
        }
        document.AddPageBreak();
        headings.AddItem("Evidence appendix");
        for (var i = 0; i < messages.Count; i++) {
            headings.AddItem("Message " + (i + 1), 1);
            foreach (var section in MessageHeaderReport.Build(messages[i]).Where(section => section.Rows.Count > 0)) {
                headings.AddItem(section.Title, 2);
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
        WriteOverviewSheet(document, messages);
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
            WriteEvidenceSheet(document, title == "Message" ? "Message details" : title, title, columns, rows);
        }
        document.AddTableOfContents(sheetName: "Navigation", placeFirst: false);
        var navigation = document.Sheets.First(sheet => sheet.Name == "Navigation");
        navigation.Freeze(topRows: 3);
        navigation.SetGridlinesVisible(false);
        document.Save();
    }

    private static void AddBriefList(WordDocument document, IEnumerable<string> values, string? empty = null) {
        var entries = values.ToArray();
        if (entries.Length == 0) { if (empty != null) { document.AddParagraph(empty); } return; }
        var list = document.AddList(WordListStyle.Bulleted);
        foreach (var value in entries) { list.AddItem(value); }
    }

    private static void Validate(string path, IReadOnlyList<MessageHeaderAnalysis> messages) {
        if (messages == null || messages.Count == 0) { throw new ArgumentException("No messages to report.", nameof(messages)); }
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)) ?? ".");
    }
}
