using DomainDetective.Reports;
using DomainDetective.Reports.Office;

namespace DomainDetective.Tests.Reports;

public class TestAssessmentCapturedEvidence {
    [Theory]
    [InlineData(ReportFormat.Word, "docx")]
    [InlineData(ReportFormat.Pdf, "pdf")]
    [InlineData(ReportFormat.Excel, "xlsx")]
    public void ExportsRetainCapturedEvidenceWhenInformationalFindingsAreHidden(ReportFormat format, string extension) {
        string directory = Path.Combine(Path.GetTempPath(), "dd-captured-evidence-" + Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "assessment." + extension);
        var report = AssessmentExportFixture.Create();
        var check = report.Domains[0].Checks.Single(check => check.Key == "rdap");
        check.Facts.Add(new CheckFact { Label = "Tenant ID", Value = "12345678-1234-1234-1234-123456789abc" });
        check.Findings.Add(new CheckFinding { Severity = AssessmentSeverity.Info, Message = "hidden-info-marker" });
        check.Evidence.Add(new CheckEvidence { Title = "Resolved addresses", Kind = CheckEvidenceKind.List,
            Items = { "192.0.2.42", "2001:db8::42" }, Omitted = 2 });
        try {
            if (format == ReportFormat.Excel) {
                AssessmentExcelReport.Generate(path, report, new AssessmentExcelOptions { ShowInfoFindings = false });
            } else {
                var results = AssessmentWordReport.GenerateReports(new Dictionary<ReportFormat, string> { [format] = path },
                    report, new AssessmentWordOptions { ShowInfoFindings = false });
                Assert.True(Assert.Single(results).Success, results[0].ErrorMessage);
            }
            string text = ReportArtifactText.Read(path);
            Assert.Contains("12345678-1234-1234-1234-123456789abc", text);
            Assert.Contains("192.0.2.42", text);
            Assert.Contains("2001:db8::42", text);
            Assert.Matches(@"2\s+(?:additional\s+)?items\s+(?:were\s+)?omitted", text);
            Assert.Contains("v=spf1 include:_spf.example.test -all", text);
            Assert.DoesNotContain("hidden-info-marker", text);
        } finally { if (Directory.Exists(directory)) { Directory.Delete(directory, true); } }
    }
}
