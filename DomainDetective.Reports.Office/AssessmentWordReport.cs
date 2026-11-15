using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using OfficeIMO.Word;
using OfficeIMO;
using OfficeIMO.Word.Pdf;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Reports.Office;

/// <summary>Creates paper reports directly from the shared domain assessment model.</summary>
public static partial class AssessmentWordReport {
    private const string High = "B91C1C";
    private const string Elevated = "A16207";
    private const string Good = "15803D";
    private const string Neutral = "687078";
    private const string Mono = "Consolas";

    /// <summary>Writes an assessment DOCX file, creating its destination directory when necessary.</summary>
    public static void Generate(string path, DomainAssessmentReport report, AssessmentWordOptions? options = null) {
        string destination = PreparePath(path);
        using WordDocument document = Build(report, options);
        document.Save(destination);
    }

    /// <summary>Builds the report in memory. The caller owns and must dispose the returned document.</summary>
    public static WordDocument Build(DomainAssessmentReport report, AssessmentWordOptions? options = null) {
        if (report == null) { throw new ArgumentNullException(nameof(report)); }
        options ??= new AssessmentWordOptions();
        if (options.FixFirstCount < 0) { throw new ArgumentOutOfRangeException(nameof(options.FixFirstCount)); }
        var style = new WordPaperStyle {
            Accent = "0F766E", TableFontSizePoints = 9,
            TableCellVerticalPadding = 15, TableCellHorizontalPadding = 70, TableParagraphSpacingPoints = 0,
            TableLineSpacingPoints = 11
        };
        WordDocument document = WordDocument.Create();
        try {
            document.PageSettings.PageSize = options.PageSize;
            document.PageOrientation = OfficePageOrientation.Portrait;
            document.Margins.TopCentimeters = 1.8;
            document.Margins.BottomCentimeters = 1.8;
            document.Margins.LeftCentimeters = 1.8;
            document.Margins.RightCentimeters = 1.8;
            document.Settings.FontFamily = style.FontFamily;
            AddChrome(document, style, report);
            WriteCover(document, style, report);
            // Keep the opening summary, contents and actions in normal page flow.
            if (options.IncludeTableOfContents && report.Domains.Count > 1) {
                // OfficeIMO resolves TOC destinations against final PDF pagination.
                WordTableOfContent contents = document.AddTableOfContent(minLevel: 1, maxLevel: 1);
                contents.Text = "Contents";
                StyleHeading(contents.TitleParagraph!, style, 2);
            }
            WriteActions(document, style, report, options);
            WriteAreas(document, style, report);
            if (report.Domains.Count > 1) { WriteControls(document, style, report); }
            foreach (DomainAssessment domain in report.Domains) { WriteDomain(document, style, domain, options); }
            WriteAppendix(document, style, report, options);
            document.TableOfContent?.RefreshEntries();
            return document;
        } catch {
            document.Dispose();
            throw;
        }
    }

    /// <summary>Builds the same paper document and converts it through OfficeIMO's Word-to-PDF engine.</summary>
    /// <remarks>TOC numbers are resolved by the converter's final layout, rather than estimated by this report.</remarks>
    public static void GeneratePdf(string path, DomainAssessmentReport report, AssessmentWordOptions? options = null, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        string destination = PreparePath(path);
        using WordDocument document = Build(report, options);
        document.SaveAsPdf(destination, options?.PdfOptions, cancellationToken);
    }

    /// <summary>Writes selected Word and PDF files from one document build, with a result for each destination.</summary>
    /// <remarks>PDF uses the same Word document and OfficeIMO converter as <see cref="GeneratePdf"/>.</remarks>
    public static IReadOnlyList<ReportResult> GenerateReports(IReadOnlyDictionary<ReportFormat, string> outputs,
        DomainAssessmentReport report, AssessmentWordOptions? options = null, CancellationToken cancellationToken = default)
        => WordReportExport.Generate(outputs, () => Build(report, options), options?.PdfOptions, cancellationToken);

    private static string PreparePath(string path) {
        if (string.IsNullOrWhiteSpace(path)) { throw new ArgumentException("An output path is required.", nameof(path)); }
        string destination = Path.GetFullPath(path);
        string? directory = Path.GetDirectoryName(destination);
        if (directory != null) { Directory.CreateDirectory(directory); }
        return destination;
    }

    private static string Scope(DomainAssessmentReport report) => report.Domains.Count == 1
        ? report.Domains[0].Domain : Number(report.Domains.Count) + " domains";

    private static string Number(int value) => value.ToString(CultureInfo.InvariantCulture);
    private static string Score(int? value) => value.HasValue ? Number(value.Value) : "Not scored";
    private static string Identifier(string value) => WordPaperText.WithIdentifierBreaks(value, '.', '-');
    private static string OutcomeTone(CheckOutcome outcome) => outcome switch {
        CheckOutcome.Error => High,
        CheckOutcome.Warning => Elevated,
        CheckOutcome.Pass => Good,
        _ => Neutral
    };
    private static string ScoreTone(int? score) => score switch {
        null => Neutral,
        >= 90 => Good,
        >= 75 => Elevated,
        _ => High
    };

    private static WordParagraph Body(WordDocument document, WordPaperStyle style, string text, bool bold = false) {
        WordParagraph paragraph = document.AddParagraph(text);
        paragraph.FontFamily = style.FontFamily;
        paragraph.FontSizePoints = 10.5;
        paragraph.ColorHex = style.Ink;
        paragraph.Bold = bold;
        paragraph.LineSpacingBeforePoints = 0;
        paragraph.LineSpacingAfterPoints = 4;
        return paragraph;
    }

    private static WordParagraph Heading(WordDocument document, WordPaperStyle style, string text, int level, bool newPage = false) {
        WordParagraph paragraph = Body(document, style, text, true);
        StyleHeading(paragraph, style, level, newPage);
        return paragraph;
    }

    private static void StyleHeading(WordParagraph paragraph, WordPaperStyle style, int level, bool newPage = false) {
        paragraph.Bold = true;
        paragraph.ColorHex = style.Ink;
        paragraph.Style = level == 1 ? WordParagraphStyles.Heading1 : level == 2 ? WordParagraphStyles.Heading2 : WordParagraphStyles.Heading3;
        paragraph.FontFamily = style.DisplayFontFamily;
        paragraph.FontSize = level == 1 ? 18 : level == 2 ? 12 : 11;
        paragraph.KeepWithNext = true;
        paragraph.PageBreakBefore = newPage;
        paragraph.LineSpacingBeforePoints = level == 1 ? 10 : 6;
        paragraph.LineSpacingAfterPoints = 4;
    }

    private static WordTable Table(WordDocument document, WordPaperStyle style, string[] headers, IEnumerable<string[]> values, params int[] widths) {
        string[][] rows = values.ToArray();
        WordTable table = document.AddTable(rows.Length + 1, headers.Length, WordTableStyle.TableNormal);
        for (int column = 0; column < headers.Length; column++) {
            style.SetCellText(table.Rows[0].Cells[column], headers[column]);
        }
        for (int row = 0; row < rows.Length; row++) {
            for (int column = 0; column < headers.Length; column++) {
                style.SetCellText(table.Rows[row + 1].Cells[column], column < rows[row].Length ? rows[row][column] : string.Empty);
            }
        }
        style.ApplyTable(table, allowRowSplit: true);
        SizeTable(table);
        style.FitTableColumnsToHeaders(table, widths);
        return table;
    }

    private static void SizeTable(WordTable table) {
        foreach (WordTableRow row in table.Rows) {
            foreach (WordTableCell cell in row.Cells) {
                foreach (WordParagraph paragraph in cell.Paragraphs) { paragraph.FontSize = 9; }
            }
        }
    }

    private static void MonoCell(WordTableCell cell) {
        foreach (WordParagraph paragraph in cell.Paragraphs) {
            paragraph.Text = Identifier(paragraph.Text);
            paragraph.FontFamily = Mono;
        }
    }

    private static void IdentifierValueCell(WordTableCell cell) {
        string text = string.Concat(cell.Paragraphs.Select(p => p.Text));
        if (IsIdentifierValue(text)) { MonoCell(cell); }
    }

    private static bool IsIdentifierValue(string text) {
        if (string.IsNullOrWhiteSpace(text) || text.Any(char.IsWhiteSpace)) { return false; }
        if (text.IndexOf('@') > 0) { return true; }
        if (Uri.TryCreate(text, UriKind.Absolute, out Uri? uri) && uri.Host.Length > 0) { return true; }
        if (text.IndexOf(':') >= 0 && System.Net.IPAddress.TryParse(text, out _)) { return true; }
        if (text.Count(c => c == '.') == 3 && System.Net.IPAddress.TryParse(text, out _)) { return true; }
        if (text.Length >= 16 && text.All(c => Uri.IsHexDigit(c) || c == ':' || c == '-')) { return true; }
        // A DNS name must have a textual final label; decimal key numbers stay in the body font.
        int dot = text.LastIndexOf('.');
        return dot > 0 && text.Substring(dot + 1).Any(char.IsLetter)
            && Uri.CheckHostName(text) == UriHostNameType.Dns;
    }

    private static WordParagraph Note(WordDocument document, WordPaperStyle style, string text) {
        WordParagraph paragraph = style.AddNote(document, text);
        paragraph.LineSpacingBeforePoints = 2;
        paragraph.LineSpacingAfterPoints = 2;
        return paragraph;
    }

    private static void AddChrome(WordDocument document, WordPaperStyle style, DomainAssessmentReport report) {
        document.AddHeadersAndFooters();
        document.DifferentFirstPage = true;
        document.HeaderFirstOrCreate.AddParagraph(string.Empty);
        WordParagraph header = document.HeaderDefaultOrCreate.AddParagraph(Identifier(Scope(report)) + " · " + Wording.FormatTime(report.GeneratedAtUtc));
        header.FontFamily = style.FontFamily;
        header.FontSize = 8;
        header.ColorHex = style.Muted;
        foreach (WordFooter footer in new[] { document.FooterDefaultOrCreate, document.FooterFirstOrCreate }) {
            WordParagraph paragraph = footer.AddParagraph("DomainDetective · " + report.Title + " · Page ");
            paragraph.AddPageNumber(includeTotalPages: true, separator: " of ");
            paragraph.FontFamily = style.FontFamily;
            paragraph.FontSize = 8;
            paragraph.ColorHex = style.Muted;
            paragraph.ParagraphAlignment = WordParagraphAlignment.Center;
        }
    }
}
