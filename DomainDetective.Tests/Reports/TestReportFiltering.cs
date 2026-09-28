using System.IO.Compression;
using System.Xml.Linq;
using DomainDetective.Reports;

namespace DomainDetective.Tests.Reports;

public class TestReportFiltering {
    [Theory]
    [InlineData(ReportScope.Minimal)]
    [InlineData(ReportScope.Detailed)]
    public void WordRetainsSuppliedActionDetails(ReportScope scope) {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".docx");
        try {
            var view = new DomainDetective.Views.SpfRecordInfo {
                Subject = "example.org", Recommendations = new[] { new RecommendationAdvice { Title = "custom-action", Why = "custom-why", How = "custom-how", Verify = "custom-verify" } }
            };
            DomainDetective.Reports.Office.WordCompositionReport.Generate(path, new object[] { view }, scope, showInfoFindings: false);
            using var zip = ZipFile.OpenRead(path);
            using var stream = zip.GetEntry("word/document.xml")!.Open();
            var text = XDocument.Load(stream).Root!.Value;
            foreach (var marker in new[] { "custom-action", "custom-why", "custom-how", "custom-verify" }) { Assert.Contains(marker, text); }
        } finally { File.Delete(path); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void WordDesiredStatePositivesFollowInfoVisibility(bool showInfo) {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".docx");
        try {
            var view = new DomainDetective.Views.DesiredStateInfo {
                Subject = "example.org",
                DesiredAssessments = new[] { new Assessment { Severity = AssessmentSeverity.Warning, Message = "desired-warning", Code = "desired-warning" } },
                Positives = new[] { new RecommendationAdvice { Title = "desired-positive-marker" } },
                BestPracticePositives = new[] { new RecommendationAdvice { Title = "best-positive-marker" } }
            };
            DomainDetective.Reports.Office.WordCompositionReport.Generate(path, new object[] { view }, ReportScope.Detailed, showInfoFindings: showInfo);
            using var zip = ZipFile.OpenRead(path);
            using var stream = zip.GetEntry("word/document.xml")!.Open();
            var text = XDocument.Load(stream).Root!.Value;
            Assert.Contains("desired-warning", text);
            foreach (var marker in new[] { "desired-positive-marker", "best-positive-marker" }) {
                if (showInfo) { Assert.Contains(marker, text); }
                else { Assert.DoesNotContain(marker, text); }
            }
        } finally { File.Delete(path); }
    }
    [Theory]
    [InlineData(ReportFormat.Excel, "xlsx", false, false)]
    [InlineData(ReportFormat.Word, "docx", false, false)]
    [InlineData(ReportFormat.Word, "docx", true, false)]
    [InlineData(ReportFormat.Word, "docx", false, true)]
    [InlineData(ReportFormat.Word, "docx", true, true)]
    [InlineData(ReportFormat.Excel, "xlsx", true, false)]
    [InlineData(ReportFormat.Markdown, "md", false, false)]
    [InlineData(ReportFormat.Markdown, "md", true, false)]
    [InlineData(ReportFormat.MarkdownHtml, "html", false, false)]
    [InlineData(ReportFormat.MarkdownHtml, "html", true, false)]
    [InlineData(ReportFormat.Excel, "xlsx", false, true)]
    [InlineData(ReportFormat.Markdown, "md", false, true)]
    [InlineData(ReportFormat.MarkdownHtml, "html", false, true)]
    [InlineData(ReportFormat.Excel, "xlsx", true, true)]
    [InlineData(ReportFormat.Markdown, "md", true, true)]
    [InlineData(ReportFormat.MarkdownHtml, "html", true, true)]
    public async Task ExportOptionsFilterFindingsAndTechnicalRecords(ReportFormat format, string extension, bool technical, bool info) {
        var directory = Path.Combine(Path.GetTempPath(), "dd-filter-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try {
            using var health = new DomainHealthCheck();
            health.SpfAnalysis.Subject = "example.org";
            typeof(SpfAnalysis).GetProperty(nameof(SpfAnalysis.SpfRecord))!.SetValue(health.SpfAnalysis, "v=spf1 include:technical-marker.example -all");
            health.SpfAnalysis.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Info, Code = "SPF.INFO.FIXTURE", Message = "informational-marker", Category = "SPF", Target = "example.org" });
            health.SpfAnalysis.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Warning, Code = SpfCodes.QueryFailed, Message = "warning-marker", Category = "SPF", Target = "example.org" });
            var path = Path.Combine(directory, "report." + extension);
            var result = await new ReportDispatcher().GenerateAsync(health, new ReportOptions { Format = format, OutputPath = path, IncludeTechnicalDetails = technical, ShowInfoFindings = info }, "example.org");
            Assert.True(result.Success, result.ErrorMessage);
            var text = File.ReadAllText(path);
            if (format == ReportFormat.Excel) {
                using var zip = ZipFile.OpenRead(path);
                using var stream = zip.GetEntry("xl/sharedStrings.xml")!.Open();
                text = XDocument.Load(stream).Root!.Value;
            }
            if (format == ReportFormat.Word) {
                using var zip = ZipFile.OpenRead(path);
                using var stream = zip.GetEntry("word/document.xml")!.Open();
                text = XDocument.Load(stream).Root!.Value;
            }
            Assert.Contains("warning-marker", text);
            if (info) { Assert.Contains("informational-marker", text); }
            else { Assert.DoesNotContain("informational-marker", text); }
            if (technical) { Assert.Contains("technical-marker", text); }
            else { Assert.DoesNotContain("technical-marker", text); }
            Assert.Equal(2, health.SpfAnalysis.Assessments.Count);
        } finally { Directory.Delete(directory, true); }
    }
}
