using System.IO.Compression;
using System.Xml.Linq;
using DomainDetective.Reports;
using DomainDetective.Reports.Markdown;
using DomainDetective.Reports.Office;
using DomainDetective.Views;

namespace DomainDetective.Tests.Reports;

public class TestReportCoverage {
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HtmlCompositionRetainsOrdinaryViewInfoOnlyWhenRequested(bool showInfo) {
        var path = Path.Combine(Path.GetTempPath(), "dd-html-view-info-" + Guid.NewGuid().ToString("N") + ".html");
        try {
            var view = new IpEnrichmentInfo {
                Subject = "example.org", Rows = Array.Empty<IpEnrichmentRow>(),
                AsnCounts = new Dictionary<int, int>(), CountryCounts = new Dictionary<string, int>(),
                Assessments = new[] {
                    new Assessment { Severity = AssessmentSeverity.Info, Code = "IP.INFO.TEST", Message = "ordinary-info-marker", Category = "IP", Target = "example.org" },
                    new Assessment { Severity = AssessmentSeverity.Warning, Code = "IP.WARN.TEST", Message = "ordinary-warning-marker", Category = "IP", Target = "example.org" }
                }
            };
            var result = await CompositionExportService.ExportAsync(new CompositionExportRequest {
                Items = new object[] { view }, Formats = new[] { ReportFormat.Html },
                ExportPath = path, ShowInfoFindings = showInfo, AutoCollectTtl = false
            });
            Assert.True(Assert.Single(result.Reports).Success, result.Reports[0].ErrorMessage);
            var html = File.ReadAllText(path);
            Assert.Contains("ordinary-warning-marker", html);
            if (showInfo) { Assert.Contains("ordinary-info-marker", html); }
            else { Assert.DoesNotContain("ordinary-info-marker", html); }
        } finally { File.Delete(path); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HtmlCompositionHonorsInformationalFindingVisibility(bool showInfo) {
        var path = Path.Combine(Path.GetTempPath(), "dd-html-info-" + Guid.NewGuid().ToString("N") + ".html");
        try {
            var findings = new[] {
                new Assessment { Severity = AssessmentSeverity.Info, Code = "INFO.TEST", Message = "info-evidence-marker", Category = "Test", Target = "example.org" },
                new Assessment { Severity = AssessmentSeverity.Warning, Code = "WARN.TEST", Message = "warning-evidence-marker", Category = "Test", Target = "example.org" }
            };
            var result = await CompositionExportService.ExportAsync(new CompositionExportRequest {
                Items = new object[] {
                    new SpfRecordInfo { Subject = "example.org", Assessments = findings },
                    new AssessmentEvidenceInfo("example.org", findings)
                },
                Formats = new[] { ReportFormat.Html }, ExportPath = path, ShowInfoFindings = showInfo, AutoCollectTtl = false
            });
            Assert.True(Assert.Single(result.Reports).Success, result.Reports[0].ErrorMessage);
            var html = File.ReadAllText(path);
            Assert.Contains("warning-evidence-marker", html);
            Assert.Contains("Overall Grade", html);
            Assert.True(html.IndexOf("Assessment evidence", StringComparison.Ordinal) > html.IndexOf("Overall Grade", StringComparison.Ordinal));
            if (showInfo) { Assert.Contains("info-evidence-marker", html); }
            else { Assert.DoesNotContain("info-evidence-marker", html); }
        } finally { File.Delete(path); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MarkdownRetainsFindingsForViewsWithoutDedicatedSections(bool html) {
        using var health = new DomainHealthCheck();
        health.RpkiAnalysis.Subject = "example.org";
        health.RpkiAnalysis.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Error, Code = "RPKI.TEST", Message = "Distinct RPKI finding retained", Category = "RPKI", Target = "example.org" });
        var path = Path.Combine(Path.GetTempPath(), "dd-rpki-report-" + Guid.NewGuid().ToString("N") + (html ? ".html" : ".md"));
        try {
            var result = await new ReportDispatcher().GenerateAsync(health, new ReportOptions { Format = html ? ReportFormat.MarkdownHtml : ReportFormat.Markdown, OutputPath = path }, "example.org");
            Assert.True(result.Success, result.ErrorMessage);
            var text = File.ReadAllText(result.FilePath);
            Assert.Contains("Distinct RPKI finding retained", text);
            Assert.Contains("RPKI.TEST", text);
        } finally { File.Delete(path); File.Delete(Path.ChangeExtension(path, ".md")); }
    }

    [Fact]
    public async Task AdditionalErrorCannotProduceGreenMarkdownDomainStatus() {
        using var health = new DomainHealthCheck();
        health.CertificateAnalysis.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Error, Code = "CERT.TEST", Message = "Only certificate error", Category = "Certificate", Target = "example.org" });
        var path = Path.Combine(Path.GetTempPath(), "dd-certificate-report-" + Guid.NewGuid().ToString("N") + ".md");
        try {
            var result = await new ReportDispatcher().GenerateAsync(health, new ReportOptions { Format = ReportFormat.Markdown, OutputPath = path }, "example.org");
            Assert.True(result.Success, result.ErrorMessage);
            var text = File.ReadAllText(result.FilePath);
            Assert.Contains("| Status | 🔴 Error |", text);
            Assert.Contains("| Errors | 1 |", text);
        } finally { File.Delete(path); }
    }

    [Fact]
    public void MarkdownAssessmentAppendixRetainsDiscoveryAndTransportFindings() {
        var finding = new[] { new Assessment { Severity = AssessmentSeverity.Warning, Code = "COVERAGE.TEST", Message = "Retained sibling finding", Category = "Discovery" } };
        var items = new object[] {
            new HttpInfo { Subject = "http.example", Assessments = finding },
            new CtTimelineInfo { Subject = "ct.example", Assessments = finding },
            new DnsInventoryInfo { Subject = "inventory.example", Assessments = finding },
            new DnsTraceInfo { Subject = "trace.example", Assessments = finding },
            new IpEnrichmentInfo { Subject = "ip.example", Assessments = finding }
        };
        var path = Path.Combine(Path.GetTempPath(), "dd-discovery-report-" + Guid.NewGuid().ToString("N") + ".md");
        try {
            MarkdownCompositionReport.Generate(path, items, ReportScope.Detailed);
            var text = File.ReadAllText(path);
            foreach (var subject in new[] { "http.example", "ct.example", "inventory.example", "trace.example", "ip.example" }) {
                Assert.Contains("# Assessment findings — " + subject, text);
            }
            foreach (var section in text.Split(new[] { "# Assessment findings — " }, StringSplitOptions.None).Skip(1).Take(5)) { Assert.Contains("Retained sibling finding", section); Assert.Contains("COVERAGE.TEST", section); }
        } finally { File.Delete(path); }
    }

    [Fact]
    public void ExcelActionPlanRetainsAdviceFromEverySuppliedView() {
        var advice = new[] { new RecommendationAdvice { Code = "CUSTOM.TEST", Title = "Supplied corrective action", Why = "Distinct reason", How = "Distinct corrective procedure", Verify = "Distinct verification procedure" } };
        var items = new object[] {
            new AssessmentEvidenceInfo("certificate.example", new[] { new Assessment { Code = "CERT.TEST", Severity = AssessmentSeverity.Error, Message = "Certificate corrective action" } }),
            new AgentReadinessInfo { Subject = "agent.example", Recommendations = advice },
            new SitemapInfo { Subject = "sitemap.example", Recommendations = advice },
            new TlsRptReportsTimeSeriesInfo { Subject = "history.example", Recommendations = advice }
        };
        var path = Path.Combine(Path.GetTempPath(), "dd-advice-report-" + Guid.NewGuid().ToString("N") + ".xlsx");
        try {
            ExcelCompositionReport.Generate(path, items, ReportScope.Detailed);
            using var archive = ZipFile.OpenRead(path);
            XNamespace main = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
            XNamespace rel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
            using var bookStream = archive.GetEntry("xl/workbook.xml")!.Open();
            var sheet = XDocument.Load(bookStream).Descendants(main + "sheet").Single(s => s.Attribute("name")!.Value == "Recommendations");
            using var relationStream = archive.GetEntry("xl/_rels/workbook.xml.rels")!.Open();
            var target = XDocument.Load(relationStream).Root!.Elements().Single(r => r.Attribute("Id")!.Value == sheet.Attribute(rel + "id")!.Value).Attribute("Target")!.Value;
            using var sheetStream = archive.GetEntry(target.StartsWith("/") ? target.TrimStart('/') : "xl/" + target)!.Open();
            using var stringsStream = archive.GetEntry("xl/sharedStrings.xml")!.Open();
            var strings = XDocument.Load(stringsStream).Root!.Elements().Select(s => s.Value).ToArray();
            var text = string.Join(" ", XDocument.Load(sheetStream).Descendants(main + "c").Where(c => c.Attribute("t")?.Value == "s").Select(c => strings[int.Parse(c.Element(main + "v")!.Value)]));
            foreach (var required in new[] { "Certificate corrective action", "agent.example", "sitemap.example", "history.example", "Distinct reason", "Distinct corrective procedure", "Distinct verification procedure" }) { Assert.Contains(required, text); }
            Assert.DoesNotContain("No actionable recommendations", text);
        } finally { File.Delete(path); }
    }
}
