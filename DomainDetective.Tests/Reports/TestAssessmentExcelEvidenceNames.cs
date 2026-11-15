using System.IO.Compression;
using System.Xml.Linq;
using DomainDetective.Reports;
using DomainDetective.Reports.Office;

namespace DomainDetective.Tests.Reports;

public class TestAssessmentExcelEvidenceNames {
    private static readonly XNamespace Excel = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";

    [Fact]
    public void EvidenceSheetNamesUseCheckTitlesAndLeaveOtherSheetsUnchanged() {
        InDirectory(directory => {
            string path = Path.Combine(directory, "names.xlsx");
            AssessmentExcelReport.Generate(path, AssessmentExportFixture.Create(2));
            Assert.Equal(new[] {
                "Summary", "Do these first", "Checks", "Findings", "Evidence", "Evidence · DKIM", "Evidence · MX", "Evidence · NS"
            }, SheetNames(path));
            AssertPaperTables(path);
        });
    }

    [Fact]
    public void LongDuplicateAndInvalidEvidenceTitlesProduceDeterministicValidNames() {
        InDirectory(directory => {
            var report = AssessmentExportFixture.Create();
            var checks = report.Domains[0].Checks;
            checks.Single(c => c.Key == "dkim").Title = new string('L', 40);
            checks.Single(c => c.Key == "mx").Title = new string('L', 40);
            checks.Single(c => c.Key == "ns").Title = "Bad:/\\?*[]Title";
            var extra = checks.Single(c => c.Key == "dnsbl");
            extra.Title = "bad:/\\?*[]title";
            extra.Evidence.Add(new CheckEvidence {
                Title = "Listings", Kind = CheckEvidenceKind.Table,
                Columns = { "Name" }, Rows = { new List<string> { "example.test" } }
            });

            string first = Path.Combine(directory, "first.xlsx"), second = Path.Combine(directory, "second.xlsx");
            AssessmentExcelReport.Generate(first, report);
            AssessmentExcelReport.Generate(second, report);
            string[] names = SheetNames(first);
            Assert.Equal(new[] {
                "Summary", "Do these first", "Checks", "Findings", "Evidence",
                "Evidence · " + new string('L', 20), "Evidence · " + new string('L', 16) + " (2)",
                "Evidence · Bad_Title", "Evidence · bad_title (2)"
            }, names);
            Assert.Equal(names, SheetNames(second));
            Assert.Equal(names.Length, names.Distinct(StringComparer.OrdinalIgnoreCase).Count());
            Assert.All(names, name => {
                Assert.InRange(name.Length, 1, 31);
                Assert.DoesNotContain(name, static character => ":\\/?*[]".IndexOf(character) >= 0);
            });
            AssertPaperTables(first);
            AssertPaperTables(second);
        });
    }

    private static string[] SheetNames(string path) {
        using var archive = ZipFile.OpenRead(path);
        using var stream = archive.GetEntry("xl/workbook.xml")!.Open();
        return XDocument.Load(stream).Descendants(Excel + "sheet").Select(static sheet => (string)sheet.Attribute("name")!).ToArray();
    }

    private static void AssertPaperTables(string path) {
        using var archive = ZipFile.OpenRead(path);
        foreach (var entry in archive.Entries.Where(static entry => entry.FullName.StartsWith("xl/worksheets/sheet", StringComparison.Ordinal)
            && entry.FullName.EndsWith(".xml", StringComparison.Ordinal))) {
            using var stream = entry.Open();
            Assert.Empty(XDocument.Load(stream).Descendants(Excel + "mergeCell"));
        }
        using var styles = archive.GetEntry("xl/styles.xml")!.Open();
        Assert.DoesNotContain(XDocument.Load(styles).Descendants(Excel + "patternFill"),
            static fill => (string?)fill.Attribute("patternType") == "solid");
    }

    private static void InDirectory(Action<string> action) {
        string root = Path.Combine(Path.GetTempPath(), "dd-evidence-names-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try { action(root); } finally { Directory.Delete(root, true); }
    }
}
