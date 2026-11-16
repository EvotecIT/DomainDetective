using System.IO.Compression;
using System.Net;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using DomainDetective.Reports;
using DomainDetective.Reports.Html;
using DomainDetective.Reports.Markdown;
using DomainDetective.Reports.Office;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Tests.Reports;

public partial class TestAssessmentExports {
    private static readonly XNamespace Word = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
    private static readonly XNamespace Excel = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";

    [Fact]
    public void AllFourFormatsUseIdenticalVerdictActionsAndAreaWording() {
        InDirectory(directory => {
            var report = AssessmentExportFixture.Create(2);
            report.Domains[0].Checks[0].Findings.Add(new CheckFinding { Severity = AssessmentSeverity.Warning, Message = "A second policy finding." });
            report.Domains[0].Checks[0].WarningCount++;
            string html = WebUtility.HtmlDecode(AssessmentHtmlReport.Render(report));
            string markdown = AssessmentMarkdownReport.Render(report);
            string wordPath = Path.Combine(directory, "assessment.docx"), excelPath = Path.Combine(directory, "assessment.xlsx");
            AssessmentWordReport.Generate(wordPath, report);
            AssessmentExcelReport.Generate(excelPath, report);
            using var word = ZipFile.OpenRead(wordPath);
            using var excel = ZipFile.OpenRead(excelPath);
            string wordText = WordText(Load(word, "word/document.xml"));
            string excelText = WorkbookText(excel);
            string[] outputs = { html, wordText, excelText, markdown };
            foreach (string output in outputs) {
                Assert.Contains(Wording.ReportVerdict(report), output);
                Assert.Contains(Wording.ReportVerdictDetail(report), output);
                foreach (var action in Wording.DoFirst(report)) {
                    Assert.Contains(action.Check.Title, output);
                    Assert.Contains(Wording.DoFirstMessage(action.Check), output);
                    Assert.Contains(Wording.DoFirstSource(action.Check), output);
                }
                // HTML gives each area a counts line instead of the paper note.
                foreach (var group in report.Domains.SelectMany(d => d.Checks).GroupBy(c => c.Area)) {
                    Assert.Contains(ReferenceEquals(output, html) ? Wording.AreaCounts(group.ToList()) : Wording.AreaNote(report, group.ToList()), output);
                }
            }
            // Security exposure is ordered before certificate renewal in every action list.
            foreach (string output in outputs) {
                int start = output.IndexOf("Do these first", StringComparison.Ordinal);
                int policy = output.IndexOf("The published policy permits spoofed mail.", start, StringComparison.Ordinal);
                int renewal = output.IndexOf("The certificate expires in 12 days.", start, StringComparison.Ordinal);
                Assert.True(policy >= start && renewal > policy);
            }
        });
    }

    [Fact]
    public void IncompleteChecksStayNeutralAndUnscoredInArtifacts() {
        InDirectory(directory => {
            var report = AssessmentExportFixture.Create();
            var check = report.Domains[0].Checks.Single(c => c.Key == "cert");
            check.Outcome = CheckOutcome.Incomplete; check.EvidenceComplete = false; check.Score = null;
            check.Findings.Clear(); check.WarningCount = 0;
            report.Score = null; report.Domains[0].Score = null;
            report.Domains[0].Areas.Single(a => a.Area == check.Area).Score = null;
            string wordPath = Path.Combine(directory, "assessment.docx"), excelPath = Path.Combine(directory, "assessment.xlsx");
            AssessmentWordReport.Generate(wordPath, report);
            AssessmentExcelReport.Generate(excelPath, report);
            using var word = ZipFile.OpenRead(wordPath);
            using var excel = ZipFile.OpenRead(excelPath);
            XDocument body = Load(word, "word/document.xml");
            Assert.Contains("Not scored", WordText(body));
            var incompleteRuns = body.Descendants(Word + "r").Where(r => r.Elements(Word + "t").Any(t => t.Value == "Incomplete")).ToList();
            Assert.NotEmpty(incompleteRuns);
            Assert.All(incompleteRuns, r => Assert.Equal("687078", (string?)r.Element(Word + "rPr")?.Element(Word + "color")?.Attribute(Word + "val")));
            var strings = SpreadsheetStrings(excel);
            var styles = Load(excel, "xl/styles.xml");
            var fonts = styles.Root!.Element(Excel + "fonts")!.Elements().ToArray();
            var formats = styles.Root!.Element(Excel + "cellXfs")!.Elements().ToArray();
            int neutralCells = 0;
            foreach (var sheet in excel.Entries.Where(e => e.FullName.StartsWith("xl/worksheets/sheet", StringComparison.Ordinal) && e.FullName.EndsWith(".xml", StringComparison.Ordinal))) {
                using var stream = sheet.Open(); var xml = XDocument.Load(stream);
                foreach (var cell in xml.Descendants(Excel + "c")) {
                    string value = CellText(cell, strings);
                    if (value is not ("Incomplete" or "Not scored")) { continue; }
                    int index = (int?)cell.Attribute("s") ?? 0;
                    var font = fonts[(int)formats[index].Attribute("fontId")!];
                    Assert.Equal("FF687078", ((string?)font.Element(Excel + "color")?.Attribute("rgb"))?.ToUpperInvariant());
                    neutralCells++;
                }
            }
            Assert.True(neutralCells >= 3);
            Assert.Contains("Not scored", AssessmentMarkdownReport.Render(report));
            Assert.Contains("Incomplete", AssessmentMarkdownReport.Render(report));
            Assert.Contains("No grade yet: 1 scored check could not be judged.", WebUtility.HtmlDecode(AssessmentHtmlReport.Render(report)));
        });
    }

    [Fact]
    public void IncompleteCaaLookupChipUsesNeutralTone() {
        var report = AssessmentExportFixture.Create();
        var caa = report.Domains[0].Checks.Single(check => check.Check == HealthCheckType.CAA);
        caa.EvidenceComplete = false;
        caa.Outcome = CheckOutcome.Incomplete;
        caa.Score = null;
        string html = AssessmentHtmlReport.Render(report);
        var chip = Regex.Match(html, @"data-sev=""(?<tone>[^""]+)""[^>]*>(?:(?!data-sev=).)*?Policy lookup incomplete", RegexOptions.Singleline);
        Assert.True(chip.Success, "The incomplete CAA acquisition state must remain visible.");
        Assert.Equal("skipped", chip.Groups["tone"].Value);
    }

    [Fact]
    public void WorkbookPreservesEvidenceAndUsesPaperTablesWithoutFillsOrMerges() {
        InDirectory(directory => {
            var report = AssessmentExportFixture.Create(2);
            report.Domains[0].Checks.Single(c => c.Key == "mx").Evidence[0].Rows[0][0] = "=1+1";
            string path = Path.Combine(directory, "assessment.xlsx");
            AssessmentExcelReport.Generate(path, report);
            using var archive = ZipFile.OpenRead(path);
            var strings = SpreadsheetStrings(archive);
            string text = string.Join("\n", strings);
            Assert.Contains("=1+1", text);
            Assert.Contains(report.Domains[1].Domain, text);
            foreach (var entry in archive.Entries.Where(e => e.FullName.StartsWith("xl/worksheets/sheet", StringComparison.Ordinal) && e.FullName.EndsWith(".xml", StringComparison.Ordinal))) {
                using var stream = entry.Open(); var sheet = XDocument.Load(stream);
                Assert.Empty(sheet.Descendants(Excel + "mergeCell"));
                Assert.Empty(sheet.Descendants(Excel + "f"));
                Assert.NotEmpty(sheet.Descendants(Excel + "pane"));
                Assert.NotEmpty(sheet.Descendants(Excel + "autoFilter"));
            }
            var styles = Load(archive, "xl/styles.xml");
            Assert.DoesNotContain(styles.Descendants(Excel + "patternFill"), p => (string?)p.Attribute("patternType") == "solid");
            var book = Load(archive, "xl/workbook.xml");
            var names = book.Descendants(Excel + "sheet").Select(s => (string)s.Attribute("name")!).ToList();
            Assert.Equal(new[] { "Summary", "Do these first", "Checks", "Findings" }, names.Take(4));
            Assert.Equal(8, names.Count);
            var summary = Load(archive, "xl/worksheets/sheet1.xml");
            Assert.Contains(summary.Descendants(Excel + "col"), column =>
                (int?)column.Attribute("min") == 1 && (double?)column.Attribute("width") == 28);
            Assert.Equal("1", (string?)summary.Root!.Element(Excel + "pageSetup")?.Attribute("fitToWidth"));
        });
    }

    [Fact]
    public void WordIdentifiersUseInvisibleBreaksAndPdfConversionProducesPages() {
        InDirectory(directory => {
            var report = AssessmentExportFixture.Create();
            string path = Path.Combine(directory, "assessment.docx"), pdf = Path.Combine(directory, "assessment.pdf");
            var results = AssessmentWordReport.GenerateReports(new Dictionary<ReportFormat, string> {
                [ReportFormat.Word] = path, [ReportFormat.Pdf] = pdf
            }, report);
            Assert.Equal(2, results.Count);
            Assert.All(results, result => Assert.True(result.Success, result.ErrorMessage));
            using var archive = ZipFile.OpenRead(path);
            string raw = Load(archive, "word/document.xml").ToString();
            Assert.Contains("\u200B", raw);
            Assert.Contains("example.test", WordText(Load(archive, "word/document.xml")));
            Assert.DoesNotContain("example. test", raw);
            byte[] bytes = File.ReadAllBytes(pdf);
            Assert.True(bytes.Length > 1000);
            Assert.Equal("%PDF-", System.Text.Encoding.ASCII.GetString(bytes, 0, 5));
            using var parsed = OfficeIMO.Pdf.PdfDocument.Load(new MemoryStream(bytes));
            // A single domain has no contents page: cover, overview, its chapter and the appendix.
            Assert.InRange(parsed.Pages.Count, 4, 6);
            Assert.DoesNotContain(parsed.Pages, p => p.ExtractText().Contains("Contents"));
        });
    }

    [Fact]
    public void ContentsPageNumbersMatchThePdfForSeveralDomains() {
        InDirectory(directory => {
            var report = AssessmentExportFixture.Create(2);
            string path = Path.Combine(directory, "assessment.docx"), pdf = Path.Combine(directory, "assessment.pdf");
            var results = AssessmentWordReport.GenerateReports(new Dictionary<ReportFormat, string> {
                [ReportFormat.Word] = path, [ReportFormat.Pdf] = pdf
            }, report);
            Assert.All(results, result => Assert.True(result.Success, result.ErrorMessage));
            using var parsed = OfficeIMO.Pdf.PdfDocument.Load(pdf);
            string[] pages = parsed.Pages.Select(p => p.ExtractText().Replace("\u200B", "")).ToArray();
            DomainAssessment first = report.Domains[0];
            string chapterTitle = first.Domain + " · " + first.Grade + " · " + first.Score;
            int chapterPage = Array.FindIndex(pages, text => text.Contains(chapterTitle) && !text.Contains("Contents")) + 1;
            Assert.True(chapterPage > 1);
            string contents = Assert.Single(pages, text => text.Contains("Contents"));
            var destination = Regex.Match(contents, Regex.Escape(chapterTitle) + @"[.\s]+(?<page>\d+)");
            Assert.True(destination.Success, contents);
            Assert.Equal(chapterPage, int.Parse(destination.Groups["page"].Value));
        });
    }

    private static void InDirectory(Action<string> action) {
        string path = Path.Combine(Path.GetTempPath(), "dd-assessment-exports-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        try { action(path); } finally { Directory.Delete(path, true); }
    }

    private static XDocument Load(ZipArchive archive, string path) {
        using var stream = archive.GetEntry(path)!.Open(); return XDocument.Load(stream);
    }

    private static string WordText(XDocument xml) => string.Join("\n", xml.Descendants(Word + "p")
        .Select(p => string.Concat(p.Descendants(Word + "t").Select(t => t.Value)))).Replace("\u200B", "");

    private static string[] SpreadsheetStrings(ZipArchive archive) {
        if (archive.GetEntry("xl/sharedStrings.xml") == null) { return Array.Empty<string>(); }
        return Load(archive, "xl/sharedStrings.xml").Root!.Elements(Excel + "si").Select(s => s.Value).ToArray();
    }

    private static string CellText(XElement cell, string[] strings) => (string?)cell.Attribute("t") == "s"
        ? strings[int.Parse(cell.Element(Excel + "v")!.Value)] : cell.Element(Excel + "is")?.Value ?? cell.Element(Excel + "v")?.Value ?? string.Empty;

    private static string WorkbookText(ZipArchive archive) {
        string[] strings = SpreadsheetStrings(archive);
        XNamespace relationships = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
        XNamespace package = "http://schemas.openxmlformats.org/package/2006/relationships";
        var links = Load(archive, "xl/_rels/workbook.xml.rels").Descendants(package + "Relationship")
            .ToDictionary(r => (string)r.Attribute("Id")!, r => (string)r.Attribute("Target")!);
        var rows = new List<string>();
        foreach (var sheet in Load(archive, "xl/workbook.xml").Descendants(Excel + "sheet")) {
            rows.Add((string)sheet.Attribute("name")!);
            string target = links[(string)sheet.Attribute(relationships + "id")!];
            string path = target.StartsWith("/", StringComparison.Ordinal) ? target.TrimStart('/') : "xl/" + target;
            foreach (var row in Load(archive, path).Descendants(Excel + "row")) {
                rows.Add(string.Join("\n", row.Elements(Excel + "c").Select(c => CellText(c, strings))));
            }
        }
        return string.Join("\n", rows);
    }
}
