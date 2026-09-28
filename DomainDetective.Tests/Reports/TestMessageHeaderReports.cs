using System.IO.Compression;
using System.Xml.Linq;
using DomainDetective.Reports;
using DomainDetective.Reports.Html;
using DomainDetective.Reports.Markdown;
using DomainDetective.Reports.Office;

namespace DomainDetective.Tests.Reports;

public class TestMessageHeaderReports {
    [Theory]
    [InlineData(MessageSignatureStatus.Invalid, "Cryptographic verification failed")]
    [InlineData(MessageSignatureStatus.Inconclusive, "Cryptographic verification could not reach a conclusion")]
    [InlineData(MessageSignatureStatus.NotPerformed, "Cryptographic verification was not performed")]
    public void VerificationFailureAppearsInReportFindingsAndCounts(MessageSignatureStatus status, string summaryText) {
        var message = new MessageHeaderAnalysis();
        message.Parse("From: sender@example.org\r\nSubject: verification case\r\n");
        message.SignatureVerification.Add(new MessageSignatureVerification { Method = "DKIM", Status = status, Explanation = "Test verification outcome." });
        var brief = MessageHeaderReportBrief.Build(message);
        Assert.Contains(summaryText, brief.Summary);
        Assert.DoesNotContain("No warning or error assessments were raised", brief.Summary);
        Assert.Contains(brief.Findings, finding => finding.Code == "HEADERS.Verify." + status);
        Assert.Contains("HEADERS.Verify." + status, MessageHeaderReport.ToText(message));
        Assert.Contains(brief.Actions, action => action.Title == "Investigate signature verification results");
    }

    [Fact]
    public void PlainTextEvidenceIncludesColumnLabels() {
        var message = new MessageHeaderAnalysis();
        message.Parse("From: sender@example.org\r\nReceived: from sender.example by mx.example with ESMTP; Wed, 17 Jun 2026 12:00:00 +0000\r\n");
        var text = MessageHeaderReport.ToText(message);
        Assert.True(text.IndexOf("Message analysis", StringComparison.Ordinal) < text.IndexOf("Evidence appendix", StringComparison.Ordinal));
        Assert.Contains("Recommended next steps", text);
        Assert.Contains("Header index | From | IP | By | Protocol | TLS | Cipher | Reported time | Delay", text);
    }

    [Fact]
    public void HostOnlyReceivedHopDoesNotClaimPublicIpEvidence() {
        var message = new MessageHeaderAnalysis();
        message.Parse("Received: from sender.example by mx.example; Wed, 17 Jun 2026 12:00:00 +0000\r\n");
        var route = Assert.Single(MessageHeaderReport.Build(message), section => section.Title == "Received path (delivery order)");
        var row = Assert.Single(route.Rows);
        Assert.Equal(string.Empty, row[2]);
        Assert.Equal(string.Empty, row[11]);
    }

    [Fact]
    public void OfficeOverviewCountsLocalVerificationOutcomes() {
        var directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "dd-verification-report-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try {
            var message = new MessageHeaderAnalysis();
            message.Parse("From: sender@example.org\r\nSubject: verification case\r\n");
            message.SignatureVerification.Add(new MessageSignatureVerification { Method = "DKIM", Status = MessageSignatureStatus.Invalid, Explanation = "Signature mismatch." });
            message.SignatureVerification.Add(new MessageSignatureVerification { Method = "ARC", Status = MessageSignatureStatus.Inconclusive, Explanation = "Key unavailable." });
            message.SignatureVerification.Add(new MessageSignatureVerification { Method = "DKIM", Status = MessageSignatureStatus.NotPerformed, Explanation = "Signature limit reached." });
            var excelPath = System.IO.Path.Combine(directory, "verification.xlsx");
            var wordPath = System.IO.Path.Combine(directory, "verification.docx");
            MessageHeaderOfficeReport.GenerateExcel(excelPath, new[] { message });
            MessageHeaderOfficeReport.GenerateWord(wordPath, new[] { message });
            using (var archive = ZipFile.OpenRead(excelPath)) {
                using var stream = archive.GetEntry("xl/worksheets/sheet1.xml")!.Open();
                var sheet = XDocument.Load(stream);
                string Cell(string reference) => sheet.Descendants().First(node => node.Name.LocalName == "c" && node.Attribute("r")?.Value == reference)
                    .Elements().First(node => node.Name.LocalName == "v").Value;
                Assert.Equal("1", Cell("B5"));
                Assert.Equal("2", Cell("C5"));
            }
            using (var archive = ZipFile.OpenRead(wordPath)) {
                using var stream = archive.GetEntry("word/document.xml")!.Open();
                var text = XDocument.Load(stream).Root!.Value;
                Assert.Contains("HEADERS.Verify.Invalid", text);
                Assert.Contains("HEADERS.Verify.Inconclusive", text);
                Assert.Contains("HEADERS.Verify.NotPerformed", text);
            }
        } finally { Directory.Delete(directory, recursive: true); }
    }

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
                Assert.Contains("What the evidence establishes", text);
                Assert.Contains("Recommended next steps", text);
                Assert.Contains("does not establish", text);
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
                        if (entry.FullName != "xl/worksheets/sheet1.xml" && !worksheet.Descendants().Any(node => node.Name.LocalName == "hyperlinks")) {
                            Assert.Contains(worksheet.Descendants(), node => node.Name.LocalName == "col" && double.Parse(node.Attribute("width")!.Value, System.Globalization.CultureInfo.InvariantCulture) >= 60);
                            Assert.Contains(worksheet.Descendants(), node => node.Name.LocalName == "row" && node.Attribute("ht") != null);
                        }
                    }
                }
            }
        } finally { Directory.Delete(directory, recursive: true); }
    }
}
