using System.IO.Compression;
using System.Xml.Linq;
using DomainDetective.Reports.Office;

namespace DomainDetective.Tests.Reports;

public class TestMessageExcelBoundaries {
    [Fact]
    public void OversizedEvidenceIsPreservedAcrossBoundedTextParts() {
        var directory = Path.Combine(Path.GetTempPath(), "dd-excel-parts-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try {
            var value = new string('a', 40000) + "😀" + new string('b', 40000);
            var message = new MessageHeaderAnalysis();
            message.Parse("From: sender@example.org\r\nSubject: " + new string('s', 40000) + "\r\nX-Large: " + value + "\r\n");
            var path = Path.Combine(directory, "large.xlsx");
            MessageHeaderOfficeReport.GenerateExcel(path, new[] { message });
            using var archive = ZipFile.OpenRead(path);
            using var stringStream = archive.GetEntry("xl/sharedStrings.xml")!.Open();
            var strings = XDocument.Load(stringStream).Root!.Elements().Select(e => e.Value).ToArray();
            Assert.All(strings, text => Assert.InRange(text.Length, 0, 32767));
            using var workbookStream = archive.GetEntry("xl/workbook.xml")!.Open();
            var sheets = XDocument.Load(workbookStream).Descendants().Where(e => e.Name.LocalName == "sheet").ToArray();
            var index = Array.FindIndex(sheets, s => s.Attribute("name")!.Value == "All header fields") + 1;
            using var sheetStream = archive.GetEntry("xl/worksheets/sheet" + index + ".xml")!.Open();
            var worksheet = XDocument.Load(sheetStream);
            string Text(XElement cell) {
                var data = cell.Elements().FirstOrDefault(e => e.Name.LocalName == "v")?.Value ?? string.Empty;
                return cell.Attribute("t")?.Value == "s" ? strings[int.Parse(data)] : data;
            }
            var parts = worksheet.Descendants().Where(e => e.Name.LocalName == "row")
                .Select(row => row.Elements().Where(e => e.Name.LocalName == "c").Select(Text).ToArray())
                .Where(cells => cells.Contains("X-Large")).Select(cells => cells.Last()).ToArray();
            Assert.True(parts.Length > 1);
            Assert.Equal(value, string.Concat(parts));
        } finally { Directory.Delete(directory, true); }
    }
}
