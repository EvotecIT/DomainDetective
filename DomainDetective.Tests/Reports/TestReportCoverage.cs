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
            Assert.Contains("Only certificate error", text);
            Assert.Contains("CERT.TEST", text);
            var domain = Assert.Single(DomainAssessmentBuilder.Build(HealthCheckReportItems.BuildItems(health, "example.org", null, false, new List<string>())).Domains);
            Assert.Contains(domain.Checks, check => check.Outcome == CheckOutcome.Error && check.Findings.Any(f => f.Code == "CERT.TEST"));
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
            AssessmentMarkdownReport.Generate(path, DomainDetective.Reports.DomainAssessmentBuilder.Build(items));
            var text = File.ReadAllText(path);
            foreach (var subject in new[] { "http.example", "ct.example", "inventory.example", "trace.example", "ip.example" }) {
                Assert.Contains(subject, text);
            }
            var model = DomainAssessmentBuilder.Build(items);
            Assert.All(model.Domains, domain => Assert.Contains(domain.Checks.SelectMany(check => check.Findings), finding => finding.Code == "COVERAGE.TEST" && finding.Message == "Retained sibling finding"));
            Assert.Contains("Retained sibling finding", text);
        } finally { File.Delete(path); }
    }

    [Fact]
    public void ExcelActionPlanRetainsFindingsFromEverySuppliedView() {
        var finding = new[] { new Assessment { Code = "CUSTOM.TEST", Severity = AssessmentSeverity.Warning, Message = "Distinct corrective action" } };
        var items = new object[] {
            new AssessmentEvidenceInfo("certificate.example", new[] { new Assessment { Code = "CERT.TEST", Severity = AssessmentSeverity.Error, Message = "Certificate corrective action" } }),
            new AgentReadinessInfo { Subject = "agent.example", Assessments = finding },
            new SitemapInfo { Subject = "sitemap.example", Assessments = finding },
            new TlsRptReportsTimeSeriesInfo { Subject = "history.example", Assessments = finding }
        };
        var path = Path.Combine(Path.GetTempPath(), "dd-advice-report-" + Guid.NewGuid().ToString("N") + ".xlsx");
        try {
            AssessmentExcelReport.Generate(path, DomainAssessmentBuilder.Build(items));
            var text = ReportArtifactText.Read(path);
            foreach (var marker in new[] { "Certificate corrective action", "agent.example", "sitemap.example", "history.example", "Distinct corrective action", "CUSTOM.TEST", "CERT.TEST" }) {
                Assert.Contains(marker, text);
            }
        } finally { File.Delete(path); }
    }
}

/// <summary>Reads user-visible artifact text while ignoring identifier break opportunities.</summary>
internal static class ReportArtifactText {
    internal static string Normalize(string text) => text.Replace("\u200B", string.Empty).Replace("\u00AD", string.Empty);

    internal static string Read(string path) {
        if (Path.GetExtension(path).Equals(".pdf", StringComparison.OrdinalIgnoreCase)) {
            using var document = OfficeIMO.Pdf.PdfDocument.Load(path);
            return Normalize(System.Text.RegularExpressions.Regex.Replace(string.Join(" ", document.Pages.Select(page => page.ExtractText())), @"\s+", " "));
        }
        if (Path.GetExtension(path).Equals(".docx", StringComparison.OrdinalIgnoreCase)) {
            using var archive = ZipFile.OpenRead(path);
            using var stream = archive.GetEntry("word/document.xml")!.Open();
            XNamespace w = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
            return Normalize(string.Join(" ", XDocument.Load(stream).Descendants(w + "t").Select(t => t.Value)));
        }
        if (Path.GetExtension(path).Equals(".xlsx", StringComparison.OrdinalIgnoreCase)) {
            using var archive = ZipFile.OpenRead(path);
            XNamespace x = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
            var strings = Array.Empty<string>();
            var entry = archive.GetEntry("xl/sharedStrings.xml");
            if (entry != null) {
                using var stream = entry.Open();
                strings = XDocument.Load(stream).Descendants(x + "si").Select(t => t.Value).ToArray();
            }
            var values = new List<string>();
            foreach (var sheet in archive.Entries.Where(e => e.FullName.StartsWith("xl/worksheets/sheet", StringComparison.Ordinal) && e.FullName.EndsWith(".xml", StringComparison.Ordinal))) {
                using var stream = sheet.Open();
                foreach (var cell in XDocument.Load(stream).Descendants(x + "c")) {
                    var value = cell.Element(x + "v")?.Value ?? cell.Element(x + "is")?.Value ?? string.Empty;
                    if ((string?)cell.Attribute("t") == "s") { value = strings[int.Parse(value)]; }
                    values.Add(value);
                }
            }
            return Normalize(string.Join(" ", values));
        }
        string text = File.ReadAllText(path);
        if (Path.GetExtension(path).Equals(".md", StringComparison.OrdinalIgnoreCase)) {
            // Compare rendered text, including the exporter's numeric character references and Markdown escapes.
            text = System.Net.WebUtility.HtmlDecode(text);
            text = System.Text.RegularExpressions.Regex.Replace(text, @"\\([\\`*_{}\[\]()#+.!|>~-])", "$1");
        }
        return Normalize(text);
    }
}
