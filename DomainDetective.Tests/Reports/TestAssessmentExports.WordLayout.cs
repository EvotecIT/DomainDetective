using System.IO.Compression;
using System.Xml.Linq;
using DomainDetective.Reports;
using DomainDetective.Reports.Office;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Tests.Reports;

public partial class TestAssessmentExports {
    [Fact]
    public void WordContentsPrecedesFlowingOverviewAndRetainsHeadingStyle() {
        InDirectory(directory => {
            string path = Path.Combine(directory, "assessment.docx");
            var report = AssessmentExportFixture.Create(2);
            AssessmentWordReport.Generate(path, report);
            using var archive = ZipFile.OpenRead(path);
            XDocument document = Load(archive, "word/document.xml");
            string text = WordText(document);
            Assert.True(text.IndexOf("Contents", StringComparison.Ordinal) < text.IndexOf("Do these first", StringComparison.Ordinal));
            XElement contents = Paragraph(document, "Contents");
            Assert.Equal("Heading2", (string?)contents.Element(Word + "pPr")?.Element(Word + "pStyle")?.Attribute(Word + "val"));
            foreach (string title in new[] { "Contents", "Do these first", "Area by area", "Controls" }) {
                XElement heading = Paragraph(document, title);
                Assert.DoesNotContain(heading.Element(Word + "pPr")!.Elements(Word + "pageBreakBefore"),
                    element => (string?)element.Attribute(Word + "val") is not ("false" or "0"));
            }
            string cover = text.Substring(0, text.IndexOf("Contents", StringComparison.Ordinal));
            Assert.DoesNotContain(Wording.ScoreNote(report), cover);
            Assert.Contains(Wording.ScoreNote(report), text.Substring(text.IndexOf("How scoring works", StringComparison.Ordinal)));
        });
    }

    [Fact]
    public void WordSummaryCoversCertificatesAndKeepsInformationalCountsAndAreaOrder() {
        InDirectory(directory => {
            string path = Path.Combine(directory, "assessment.docx");
            var report = AssessmentExportFixture.Create(3);
            AssessmentWordReport.Generate(path, report);
            using var archive = ZipFile.OpenRead(path);
            XDocument document = Load(archive, "word/document.xml");
            var tables = document.Descendants(Word + "tbl").ToArray();
            var controls = tables.Single(table => table.Elements(Word + "tr").First().Elements(Word + "tc")
                .Select(ParagraphText).Contains("Domain") && table.Elements(Word + "tr").First().Elements(Word + "tc")
                .Select(ParagraphText).Contains("Certificate"));
            string[] headings = controls.Elements(Word + "tr").First().Elements(Word + "tc").Select(ParagraphText).ToArray();
            int certificate = Array.IndexOf(headings, "Certificate");
            Assert.True(certificate >= 0, "Controls must include Certificate.");
            Assert.All(controls.Elements(Word + "tr").Skip(1), row =>
                Assert.Equal("Warning", ParagraphText(row.Elements(Word + "tc").ElementAt(certificate))));
            var areas = tables.Single(table => table.Elements(Word + "tr").First().Elements(Word + "tc")
                .Select(ParagraphText).SequenceEqual(new[] { "Area", "Status", "Score", "Checks", "Passing", "Needs attention" }));
            var other = areas.Elements(Word + "tr").Single(row => row.Elements(Word + "tc").Count() == 6
                && ParagraphText(row.Elements(Word + "tc").First()) == "Other");
            Assert.Equal("0", ParagraphText(other.Elements(Word + "tc").ElementAt(4)));
            var appendix = tables.Single(table => table.Elements(Word + "tr").First().Elements(Word + "tc")
                .Select(ParagraphText).Take(3).SequenceEqual(new[] { "Domain", "Area", "Check" }));
            var areaOrder = appendix.Elements(Word + "tr").Skip(1)
                .Where(row => ParagraphText(row.Elements(Word + "tc").First()) == report.Domains[0].Domain)
                .Select(row => ParagraphText(row.Elements(Word + "tc").ElementAt(1))).Distinct();
            Assert.Equal(new[] { "Mail", "DNS", "Web", "Security", "Other" }, areaOrder);
        });
    }

    [Fact]
    public void WordActionsUseTitleMetaMessageAndKeyNumbersUseBodyFont() {
        InDirectory(directory => {
            string path = Path.Combine(directory, "assessment.docx");
            var report = AssessmentExportFixture.Create();
            var check = report.Domains[0].Checks[0];
            check.WarningCount = 3;
            AssessmentWordReport.Generate(path, report);
            using var archive = ZipFile.OpenRead(path);
            XDocument document = Load(archive, "word/document.xml");
            XElement action = document.Descendants(Word + "tr").First(row =>
                row.Elements(Word + "tc").Count() == 2 && row.Elements(Word + "tc").Last().Elements(Word + "p").Count() == 3
                && row.Elements(Word + "tc").Last().Elements(Word + "p").First().Value == "DMARC");
            XElement[] paragraphs = action.Elements(Word + "tc").Last().Elements(Word + "p").ToArray();
            Assert.NotNull(paragraphs[0].Descendants(Word + "b").FirstOrDefault());
            Assert.Equal("example.test · Mail · and 3 more findings", ParagraphText(paragraphs[1]));
            Assert.All(paragraphs[1].Descendants(Word + "r").Where(run => run.Element(Word + "t") != null),
                run => Assert.Equal("687078", (string?)run.Element(Word + "rPr")?.Element(Word + "color")?.Attribute(Word + "val")));
            Assert.Equal("120", (string?)paragraphs[2].Element(Word + "pPr")?.Element(Word + "spacing")?.Attribute(Word + "after"));
            foreach (string metric in new[] { "Policy: none", "Days remaining: 12" }) {
                var runs = document.Descendants(Word + "r").Where(run => run.Elements(Word + "t").Any(t => t.Value == metric)).ToList();
                Assert.NotEmpty(runs);
                Assert.All(runs, run => Assert.Equal("Aptos", (string?)run.Element(Word + "rPr")?.Element(Word + "rFonts")?.Attribute(Word + "ascii")));
            }
            XElement appendix = document.Descendants(Word + "tbl").Single(table =>
                table.Elements(Word + "tr").First().Descendants(Word + "t").Any(t => t.Value == "Warnings"));
            string[] headers = appendix.Elements(Word + "tr").First().Elements(Word + "tc").Select(ParagraphText).ToArray();
            Assert.Contains("Key number", headers);
            Assert.DoesNotContain("Key numbers", headers);
            Assert.Equal(10, headers.Length);
        });
    }

    private static XElement Paragraph(XDocument document, string text) => document.Descendants(Word + "p")
        .Single(paragraph => ParagraphText(paragraph) == text);

    private static string ParagraphText(XElement element) => string.Concat(element.Descendants(Word + "t").Select(t => t.Value)).Replace("\u200B", "");
}
