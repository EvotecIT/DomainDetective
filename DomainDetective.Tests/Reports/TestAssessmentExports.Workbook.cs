using System.IO.Compression;
using System.Xml.Linq;
using DomainDetective.Reports;
using DomainDetective.Reports.Office;

namespace DomainDetective.Tests.Reports;

public partial class TestAssessmentExports {
    [Fact]
    public void WorkbookUsesNativeTablesAndKeepsDnsTextAsData() {
        InDirectory(directory => {
            var report = AssessmentExportFixture.Create(2);
            report.Domains[0].Checks.Single(c => c.Key == "mx").Evidence[0].Rows[0][0] = "=1+1";
            string path = Path.Combine(directory, "assessment.xlsx");
            AssessmentExcelReport.Generate(path, report);
            using var archive = ZipFile.OpenRead(path);
            Assert.Contains("=1+1", string.Join("\n", SpreadsheetStrings(archive)));
            Assert.Equal(new[] { "Summary", "Do these first", "Checks", "Findings", "Evidence" }, SheetNames(archive));
            foreach (string name in SheetNames(archive)) {
                XDocument sheet = Sheet(archive, name);
                Assert.Empty(sheet.Descendants(Excel + "mergeCell"));
                Assert.Empty(sheet.Descendants(Excel + "f"));
                Assert.NotNull(sheet.Descendants(Excel + "tabColor").SingleOrDefault());
                // Evidence prints at full size; the other sheets fit one page wide.
                if (name != "Evidence") { Assert.Equal("1", (string?)sheet.Root!.Element(Excel + "pageSetup")?.Attribute("fitToWidth")); }
            }
            // Every list is a native table with banded rows; filters belong to the tables, not to the sheets.
            var tables = archive.Entries.Where(e => e.FullName.StartsWith("xl/tables/", StringComparison.Ordinal)).Select(e => {
                using var stream = e.Open(); return XDocument.Load(stream).Root!;
            }).ToList();
            Assert.Contains(tables, t => (string?)t.Attribute("name") == "Checks");
            Assert.All(tables, t => Assert.Equal("1", (string?)t.Element(Excel + "tableStyleInfo")!.Attribute("showRowStripes")));
            Assert.All(tables, t => Assert.NotNull(t.Element(Excel + "autoFilter")));
            // Data sheets freeze their header and the identifying columns.
            XElement pane = Sheet(archive, "Checks").Descendants(Excel + "pane").Single();
            Assert.Equal("2", (string?)pane.Attribute("xSplit"));
            Assert.Equal("4", (string?)pane.Attribute("ySplit"));
        });
    }

    [Fact]
    public void SingleDomainChecksDropTheDomainColumnAndLeaveUnscoredCellsEmpty() {
        InDirectory(directory => {
            var report = AssessmentExportFixture.Create();
            var cert = report.Domains[0].Checks.Single(c => c.Key == "cert");
            cert.Outcome = CheckOutcome.Incomplete; cert.EvidenceComplete = false; cert.Score = null;
            string path = Path.Combine(directory, "assessment.xlsx");
            AssessmentExcelReport.Generate(path, report);
            using var archive = ZipFile.OpenRead(path);
            string[] strings = SpreadsheetStrings(archive);
            XDocument sheet = Sheet(archive, "Checks");
            Assert.Contains("Checks · example.test", CellTexts(sheet, strings, 1));
            string[] header = CellTexts(sheet, strings, 4);
            Assert.Equal(new[] { "Check", "Area", "Outcome", "Score", "What was found" }, header);
            Assert.DoesNotContain("Not scored", string.Join("\n", strings));
            // Scores are numbers with a data bar; the incomplete and informational checks have no score cell at all.
            var rows = sheet.Descendants(Excel + "row").Where(r => (int)r.Attribute("r")! > 4).ToList();
            XElement certRow = rows.Single(r => CellTexts(r, strings).Contains("Certificate"));
            Assert.DoesNotContain(certRow.Elements(Excel + "c"), c => ((string)c.Attribute("r")!).StartsWith("D", StringComparison.Ordinal) && c.Element(Excel + "v") != null);
            XElement dmarcRow = rows.Single(r => CellTexts(r, strings).Contains("DMARC"));
            XElement score = dmarcRow.Elements(Excel + "c").Single(c => ((string)c.Attribute("r")!).StartsWith("D", StringComparison.Ordinal));
            Assert.True((string?)score.Attribute("t") is null or "n");
            Assert.Equal("40", score.Element(Excel + "v")!.Value);
            Assert.NotEmpty(sheet.Descendants(Excel + "dataBar"));
            // Key number and the top finding share one plain-words column.
            Assert.Contains("Policy: none · The published policy permits spoofed mail.", CellTexts(dmarcRow, strings));
        });
    }

    [Fact]
    public void EvidenceSharesOneSheetGroupedByCheckAndChecksLinkToIt() {
        InDirectory(directory => {
            var report = AssessmentExportFixture.Create();
            var checks = report.Domains[0].Checks;
            checks.Single(c => c.Key == "ns").Title = "Bad:/\\?*[]Title";
            string path = Path.Combine(directory, "assessment.xlsx");
            AssessmentExcelReport.Generate(path, report);
            using var archive = ZipFile.OpenRead(path);
            // Long, duplicate or invalid check titles no longer create sheets.
            Assert.Equal(new[] { "Summary", "Do these first", "Checks", "Findings", "Evidence" }, SheetNames(archive));
            string[] strings = SpreadsheetStrings(archive);
            XDocument evidence = Sheet(archive, "Evidence");
            var rows = evidence.Descendants(Excel + "row").ToList();
            int heading = (int)rows.Single(r => CellTexts(r, strings).FirstOrDefault() == "MX").Attribute("r")!;
            // The check's rows are an outline group under its heading row: facts, then the table with its own columns.
            var group = rows.Where(r => (int)r.Attribute("r")! > heading).TakeWhile(r => (string?)r.Attribute("outlineLevel") == "1").ToList();
            Assert.Contains(group, r => CellTexts(r, strings).SequenceEqual(new[] { "Hosts", "Name", "Result" }));
            Assert.Contains(group, r => CellTexts(r, strings).Contains("primary-identifier.example.test"));
            Assert.Contains(rows, r => CellTexts(r, strings).FirstOrDefault() == "Bad:/\\?*[]Title");
            // The check name on the Checks sheet links to the heading row.
            XDocument checkSheet = Sheet(archive, "Checks");
            XElement link = checkSheet.Descendants(Excel + "hyperlink").Single(h => CellTexts(checkSheet, strings, Row((string)h.Attribute("ref")!))
                .Contains("MX"));
            Assert.Matches("^'?Evidence'?!A" + heading + "$", (string?)link.Attribute("location") ?? string.Empty);
        });
    }

    [Fact]
    public void SummaryScoresAreasWithCoverageInsteadOfHidingThem() {
        InDirectory(directory => {
            var report = AssessmentExportFixture.Create();
            var cert = report.Domains[0].Checks.Single(c => c.Key == "cert");
            cert.Outcome = CheckOutcome.Incomplete; cert.EvidenceComplete = false; cert.Score = null;
            var mail = report.Domains[0].Checks.Single(c => c.Key == "mx");
            mail.Outcome = CheckOutcome.Incomplete; mail.EvidenceComplete = false; mail.Score = null;
            string path = Path.Combine(directory, "assessment.xlsx");
            AssessmentExcelReport.Generate(path, report);
            using var archive = ZipFile.OpenRead(path);
            string[] strings = SpreadsheetStrings(archive);
            XDocument summary = Sheet(archive, "Summary");
            var rows = summary.Descendants(Excel + "row").ToList();
            // Mail keeps a score over the checks that could be judged, with the judged share beside it.
            XElement mailRow = rows.First(r => CellTexts(r, strings).FirstOrDefault() == "Mail");
            var cells = mailRow.Elements(Excel + "c").ToList();
            int? expected = DomainAssessmentCatalog.CombinedScore(report.Domains[0].Checks.Where(c => c.Area == AnalysisArea.Mail));
            Assert.Equal(expected!.Value.ToString(System.Globalization.CultureInfo.InvariantCulture), cells.Single(c => ((string)c.Attribute("r")!).StartsWith("C", StringComparison.Ordinal)).Element(Excel + "v")!.Value);
            double judged = double.Parse(cells.Single(c => ((string)c.Attribute("r")!).StartsWith("D", StringComparison.Ordinal)).Element(Excel + "v")!.Value, System.Globalization.CultureInfo.InvariantCulture);
            Assert.InRange(judged, 0.5, 0.99);
            // Web holds only the incomplete certificate, so nothing there could be judged and the score stays blank.
            XElement webRow = rows.First(r => CellTexts(r, strings).FirstOrDefault() == "Web");
            Assert.DoesNotContain(webRow.Elements(Excel + "c"), c => ((string)c.Attribute("r")!).StartsWith("C", StringComparison.Ordinal) && c.Element(Excel + "v") != null);
            Assert.Contains(archive.Entries, e => e.FullName.IndexOf("/charts/chart", StringComparison.Ordinal) >= 0);
        });
    }

    [Fact]
    public void WordAreasPrintTheJudgedShareAndKeepNotScoredForEmptyAreas() {
        InDirectory(directory => {
            var report = AssessmentExportFixture.Create();
            var cert = report.Domains[0].Checks.Single(c => c.Key == "cert");
            cert.Outcome = CheckOutcome.Incomplete; cert.EvidenceComplete = false; cert.Score = null;
            var mx = report.Domains[0].Checks.Single(c => c.Key == "mx");
            mx.Outcome = CheckOutcome.Incomplete; mx.EvidenceComplete = false; mx.Score = null;
            string path = Path.Combine(directory, "assessment.docx");
            AssessmentWordReport.Generate(path, report);
            using var archive = ZipFile.OpenRead(path);
            XDocument document = Load(archive, "word/document.xml");
            var areas = document.Descendants(Word + "tbl").Single(table => table.Elements(Word + "tr").First().Elements(Word + "tc")
                .Select(ParagraphText).SequenceEqual(new[] { "Area", "Status", "Score", "Checks", "Passing", "Needs attention" }));
            string Score(string area) => ParagraphText(areas.Elements(Word + "tr").First(row => row.Elements(Word + "tc").Count() == 6
                && ParagraphText(row.Elements(Word + "tc").First()) == area).Elements(Word + "tc").ElementAt(2));
            var checks = report.Domains[0].Checks.Where(c => c.Area == AnalysisArea.Mail).ToList();
            string percent = ((int)Math.Round(DomainAssessmentCatalog.ScoreCoverage(checks)!.Value * 100, MidpointRounding.AwayFromZero)) + "%";
            Assert.Equal(DomainAssessmentCatalog.CombinedScore(checks) + " · " + percent + " of checks judged", Score("Mail"));
            Assert.Equal("Not scored", Score("Web"));
            Assert.Equal("100", Score("DNS"));
        });
    }

    private static string[] SheetNames(ZipArchive archive) => Load(archive, "xl/workbook.xml").Descendants(Excel + "sheet")
        .Select(static sheet => (string)sheet.Attribute("name")!).ToArray();

    private static XDocument Sheet(ZipArchive archive, string name) {
        XNamespace relationships = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
        XNamespace package = "http://schemas.openxmlformats.org/package/2006/relationships";
        string id = (string)Load(archive, "xl/workbook.xml").Descendants(Excel + "sheet")
            .Single(sheet => (string)sheet.Attribute("name")! == name).Attribute(relationships + "id")!;
        string target = (string)Load(archive, "xl/_rels/workbook.xml.rels").Descendants(package + "Relationship")
            .Single(r => (string)r.Attribute("Id")! == id).Attribute("Target")!;
        return Load(archive, target.StartsWith("/", StringComparison.Ordinal) ? target.TrimStart('/') : "xl/" + target);
    }

    private static string[] CellTexts(XElement row, string[] strings) => row.Elements(Excel + "c")
        .Select(c => CellText(c, strings)).Where(text => text.Length > 0).ToArray();

    private static string[] CellTexts(XDocument sheet, string[] strings, int row) {
        XElement? element = sheet.Descendants(Excel + "row").SingleOrDefault(r => (int)r.Attribute("r")! == row);
        return element == null ? Array.Empty<string>() : CellTexts(element, strings);
    }

    private static int Row(string reference) => int.Parse(new string(reference.Where(char.IsDigit).ToArray()), System.Globalization.CultureInfo.InvariantCulture);
}
