using System.IO.Compression;
using System.Xml.Linq;
using DomainDetective.Reports;

namespace DomainDetective.Tests.Reports;

public class TestReportFiltering {
    [Fact]
    public void WordPrintsActionTitleAndHowWhileModelPreservesFullGuidance() {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".docx");
        try {
            var view = new DomainDetective.Views.SpfRecordInfo {
                Subject = "example.org", Assessments = new[] { new Assessment { Severity = AssessmentSeverity.Warning, Code = "CUSTOM.TEST", Message = "Needs custom action" } }, Recommendations = new[] { new RecommendationAdvice { Title = "custom-action", Why = "custom-why", How = "custom-how", Verify = "custom-verify" } }
            };
            var report = DomainAssessmentBuilder.Build(new object[] { view });
            var guidance = Assert.Single(Assert.Single(Assert.Single(report.Domains).Checks).Recommendations);
            Assert.Equal("custom-action", guidance.Title);
            Assert.Equal("custom-how", guidance.How);
            Assert.Equal("custom-why", guidance.Why);
            Assert.Equal("custom-verify", guidance.Verify);
            DomainDetective.Reports.Office.AssessmentWordReport.Generate(path, report);
            using var zip = ZipFile.OpenRead(path);
            using var stream = zip.GetEntry("word/document.xml")!.Open();
            var text = ReportArtifactText.Normalize(XDocument.Load(stream).Root!.Value);
            Assert.Contains("custom-action", text);
            Assert.Contains("custom-how", text);
        } finally { File.Delete(path); }
    }

    [Theory]
    [InlineData(ReportFormat.Excel, "xlsx", false)]
    [InlineData(ReportFormat.Excel, "xlsx", true)]
    [InlineData(ReportFormat.Word, "docx", false)]
    [InlineData(ReportFormat.Word, "docx", true)]
    [InlineData(ReportFormat.Markdown, "md", false)]
    [InlineData(ReportFormat.Markdown, "md", true)]
    [InlineData(ReportFormat.MarkdownHtml, "html", false)]
    [InlineData(ReportFormat.MarkdownHtml, "html", true)]
    public async Task ExportOptionsFilterFindingsWithoutMutatingAnalysis(ReportFormat format, string extension, bool info) {
        var directory = Path.Combine(Path.GetTempPath(), "dd-filter-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try {
            using var health = new DomainHealthCheck();
            health.SpfAnalysis.Subject = "example.org";
            typeof(SpfAnalysis).GetProperty(nameof(SpfAnalysis.SpfRecord))!.SetValue(health.SpfAnalysis, "v=spf1 include:technical-marker.example -all");
            health.SpfAnalysis.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Info, Code = "SPF.INFO.FIXTURE", Message = "informational-marker", Category = "SPF", Target = "example.org" });
            health.SpfAnalysis.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Warning, Code = SpfCodes.QueryFailed, Message = "warning-marker", Category = "SPF", Target = "example.org" });
            var path = Path.Combine(directory, "report." + extension);
            var result = await new ReportDispatcher().GenerateAsync(health, new ReportOptions { Format = format, OutputPath = path, ShowInfoFindings = info }, "example.org");
            Assert.True(result.Success, result.ErrorMessage);
            var text = ReportArtifactText.Read(path);
            Assert.Contains("warning-marker", text);
            // Positive summaries can repeat an informational message; the code identifies its finding row.
            if (info) { Assert.Contains("SPF.INFO.FIXTURE", text); Assert.Contains("informational-marker", text); }
            else { Assert.DoesNotContain("SPF.INFO.FIXTURE", text); }

            Assert.Equal(2, health.SpfAnalysis.Assessments.Count);
        } finally { Directory.Delete(directory, true); }
    }
}
