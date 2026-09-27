using System.IO.Compression;
using System.Xml.Linq;
using DomainDetective.Reports;

namespace DomainDetective.Tests.Reports;

public class TestHealthCheckDocumentReports {
    [Theory]
    [InlineData(ReportFormat.Word, "docx")]
    [InlineData(ReportFormat.Excel, "xlsx")]
    [InlineData(ReportFormat.Markdown, "md")]
    [InlineData(ReportFormat.MarkdownHtml, "html")]
    public async Task GeneralDocumentExportsIncludePerformedChecksAndActionGuidance(ReportFormat format, string extension) {
        var directory = Path.Combine(Path.GetTempPath(), "dd-document-design-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try {
            var health = new DomainHealthCheck();
            health.SpfAnalysis.Subject = "example.org";
            health.SpfAnalysis.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Warning, Code = SpfCodes.QueryFailed, Message = "SPF DNS query failed", Category = "SPF", Target = "example.org" });
            health.DmarcAnalysis.Subject = "example.org";
            health.DmarcAnalysis.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Error, Code = "DMARC.TEST", Message = "Distinct DMARC fixture finding", Category = "DMARC", Target = "example.org" });
            health.CertificateAnalysis.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Error, Code = "CERT.TEST", Message = "Certificate fixture finding outside dedicated composition sections", Category = "Certificate", Target = "example.org" });
            health.AgentReadinessAnalysis.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Error, Code = "AGENT.TEST", Message = "Agent readiness fixture finding", Category = "AgentReadiness", Target = "example.org" });
            health.SitemapAnalysis.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Error, Code = "SITEMAP.TEST", Message = "Sitemap fixture finding", Category = "Sitemap", Target = "example.org" });
            var errors = new List<string>();
            var items = HealthCheckReportItems.BuildItems(health, "example.org", null, true, errors);
            Assert.Empty(errors);
            var summary = Assert.Single(ExecutiveSummaryBuilder.Build(items, DomainOrder.Alphabetical));
            Assert.Equal(1, summary.Warnings);
            Assert.Equal(4, summary.Errors);
            var path = Path.Combine(directory, "assessment." + extension);
            var result = await new ReportDispatcher().GenerateAsync(health, new ReportOptions { Format = format, OutputPath = path }, "example.org");
            Assert.True(result.Success, result.ErrorMessage);
            var text = File.ReadAllText(result.FilePath);
            if (format == ReportFormat.Word || format == ReportFormat.Excel) {
                using var archive = ZipFile.OpenRead(result.FilePath);
                if (format == ReportFormat.Excel) {
                    XNamespace main = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
                    XNamespace relationships = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
                    XNamespace packageRelationships = "http://schemas.openxmlformats.org/package/2006/relationships";
                    using var workbookStream = archive.GetEntry("xl/workbook.xml")!.Open();
                    var workbook = XDocument.Load(workbookStream);
                    var findingSheet = workbook.Descendants(main + "sheet").Single(sheet => sheet.Attribute("name")!.Value == "Findings");
                    using var relationStream = archive.GetEntry("xl/_rels/workbook.xml.rels")!.Open();
                    var relation = XDocument.Load(relationStream).Descendants(packageRelationships + "Relationship").Single(item => item.Attribute("Id")!.Value == findingSheet.Attribute(relationships + "id")!.Value);
                    var target = relation.Attribute("Target")!.Value;
                    using var findingStream = archive.GetEntry(target.StartsWith("/") ? target.TrimStart('/') : "xl/" + target)!.Open();
                    var findingXml = XDocument.Load(findingStream);
                    using var stringStream = archive.GetEntry("xl/sharedStrings.xml")!.Open();
                    var strings = XDocument.Load(stringStream).Root!.Elements().Select(item => item.Value).ToArray();
                    var findingText = string.Join(" ", findingXml.Descendants(main + "c").Where(cell => cell.Attribute("t")?.Value == "s").Select(cell => strings[int.Parse(cell.Element(main + "v")!.Value)]));
                    Assert.Contains("SPF DNS query failed", findingText);
                    Assert.Contains("Distinct DMARC fixture finding", findingText);
                    Assert.Contains("Certificate fixture finding", findingText);
                    Assert.Contains("Agent readiness fixture finding", findingText);
                    Assert.Contains("Sitemap fixture finding", findingText);
                    foreach (var sheet in archive.Entries.Where(entry => entry.FullName.StartsWith("xl/worksheets/sheet") && entry.FullName.EndsWith(".xml"))) {
                        using var stream = sheet.Open();
                        Assert.Equal("1", XDocument.Load(stream).Root!.Element(main + "pageSetup")?.Attribute("fitToWidth")?.Value);
                    }
                }
                text = string.Join(" ", archive.Entries.Where(e => e.FullName.EndsWith(".xml", StringComparison.Ordinal)).Select(e => {
                    using var stream = e.Open();
                    return XDocument.Load(stream).Root?.Value ?? string.Empty;
                }));
            }
            Assert.Contains("example.org", text);
            Assert.Contains("Agent readiness fixture finding", text);
            Assert.Contains("Sitemap fixture finding", text);
            Assert.Contains("SPF", text);
            Assert.Contains("DMARC", text);
            Assert.Contains("Distinct DMARC fixture finding", text);
            Assert.Contains("Certificate fixture finding outside dedicated composition sections", text);
            Assert.Contains(RecommendationCatalog.For(health.SpfAnalysis.Assessments[0]).Title, text);
            Assert.DoesNotContain("Mail Classification", text);
        } finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public async Task UnperformedChecksDoNotProduceAnApparentlyHealthyReport() {
        var result = await HealthCheckCompositionReport.GenerateAsync(new DomainHealthCheck(), new ReportOptions { Format = ReportFormat.Word, OutputPath = Path.Combine(Path.GetTempPath(), "unperformed-" + Guid.NewGuid().ToString("N") + ".docx") });
        Assert.False(result.Success);
        Assert.Contains("No completed", result.ErrorMessage);
    }

    [Fact]
    public void BriefPrioritizesProblemsAndKeepsVerificationUnknown() {
        var message = new MessageHeaderAnalysis();
        message.Parse("From: sender@example.org\r\nSubject: test\r\nAuthentication-Results: mx.example; dkim=pass header.d=example.org\r\n");
        message.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Warning, Message = "warning fixture" });
        message.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Error, Message = "error fixture" });
        var brief = MessageHeaderReportBrief.Build(message);
        Assert.Equal(AssessmentSeverity.Error, brief.Findings[0].Severity);
        Assert.DoesNotContain(brief.Findings, a => a.Severity == AssessmentSeverity.Info);
        Assert.Contains(brief.Evidence, line => line.Contains("not performed", StringComparison.Ordinal));
        Assert.Contains(brief.Evidence, line => line.Contains("receiver claims", StringComparison.Ordinal));
    }
}
