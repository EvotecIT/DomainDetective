using System.IO.Compression;
using System.Xml.Linq;
using DomainDetective.Reports;
using DomainDetective.Reports.Html;
using DomainDetective.Reports.Markdown;
using DomainDetective.Reports.Office;

namespace DomainDetective.Tests.Reports;

public class TestMessageHeaderReports {
    [Fact]
    public void EvidenceAppearsInEveryFormatWithoutExecutingHeaderContent() {
        var directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "dd-message-reports-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try {
            var message = new MessageHeaderAnalysis();
            message.Parse("From: sender@example.com\r\nTo: recipient@example.net\r\nSubject: =HYPERLINK(\"https://invalid.example\") <img src=x onerror=alert(1)>\r\nAuthentication-Results: mx.example; dkim=pass header.d=example.com; spf=pass smtp.mailfrom=example.com\r\nX-MS-Exchange-Organization-AuthAs: Internal\r\nX-Note: direction\u202Econtrol\r\n", new MessageHeaderAnalysisOptions { TrustedAuthServIds = new[] { "mx.example" } });
            var messages = new[] { message };
            var htmlPath = System.IO.Path.Combine(directory, "message.html");
            var mdHtmlPath = System.IO.Path.Combine(directory, "message-markdown.html");
            var mdPath = System.IO.Path.Combine(directory, "message.md");
            var wordPath = System.IO.Path.Combine(directory, "message.docx");
            var excelPath = System.IO.Path.Combine(directory, "message.xlsx");
            MessageHeaderHtmlReport.Generate(htmlPath, messages);
            MessageHeaderMarkdownReport.Generate(mdHtmlPath, messages, html: true);
            MessageHeaderMarkdownReport.Generate(mdPath, messages);
            MessageHeaderOfficeReport.GenerateWord(wordPath, messages);
            MessageHeaderOfficeReport.GenerateExcel(excelPath, messages);
            foreach (var path in new[] { htmlPath, mdHtmlPath }) {
                var html = File.ReadAllText(path);
                Assert.Contains("sender@example.com", html);
                Assert.Contains("mx.example", html);
                Assert.Contains("Configured", html);
                Assert.Contains("Not performed", html);
                Assert.Contains("[U+202E]", html);
                Assert.DoesNotContain("<img src=x", html);
                Assert.DoesNotContain("\u202E", html, StringComparison.Ordinal);
            }
            Assert.Contains("mx.example", File.ReadAllText(mdPath));
            Assert.Contains("sender@example.com", MessageHeaderReport.ToText(message));
            foreach (var path in new[] { wordPath, excelPath }) {
                using var archive = ZipFile.OpenRead(path);
                var text = string.Join(" ", archive.Entries.Where(entry => entry.FullName.EndsWith(".xml", StringComparison.Ordinal)).Select(entry => {
                    using var stream = entry.Open();
                    return XDocument.Load(stream).Root?.Value ?? string.Empty;
                }));
                Assert.Contains("sender@example.com", text);
                Assert.Contains("mx.example", text);
                Assert.Contains("Configured", text);
                Assert.Contains("[U+202E]", text);
                if (path == excelPath) {
                    var workbookEntry = archive.GetEntry("xl/workbook.xml")!;
                    using (var workbookStream = workbookEntry.Open()) {
                        var workbook = XDocument.Load(workbookStream);
                        Assert.Equal("Overview", workbook.Descendants().First(node => node.Name.LocalName == "sheet").Attribute("name")?.Value);
                        var names = workbook.Descendants().Where(node => node.Name.LocalName == "sheet").Select(node => node.Attribute("name")!.Value).ToArray();
                        Assert.All(names, name => Assert.InRange(name.Length, 1, 31));
                        Assert.Equal(names.Length, names.Distinct(StringComparer.OrdinalIgnoreCase).Count());
                        Assert.Contains(names, name => name.StartsWith("Receiver-reported", StringComparison.Ordinal));
                        Assert.Contains(names, name => name.StartsWith("Exchange", StringComparison.Ordinal));
                    }
                    foreach (var entry in archive.Entries.Where(entry => entry.FullName.StartsWith("xl/worksheets/", StringComparison.Ordinal) && entry.FullName.EndsWith(".xml", StringComparison.Ordinal))) {
                        using var stream = entry.Open();
                        var worksheet = XDocument.Load(stream);
                        Assert.DoesNotContain(worksheet.Descendants(), node => node.Name.LocalName == "f");
                        Assert.Contains(worksheet.Descendants(), node => node.Name.LocalName == "pane" && node.Attribute("state")?.Value == "frozen");
                        Assert.Contains(worksheet.Descendants(), node => node.Name.LocalName == "col" && double.Parse(node.Attribute("width")!.Value, System.Globalization.CultureInfo.InvariantCulture) >= 60);
                        Assert.Contains(worksheet.Descendants(), node => node.Name.LocalName == "row" && node.Attribute("ht") != null);
                    }
                }
            }
        } finally { Directory.Delete(directory, recursive: true); }
    }
}
