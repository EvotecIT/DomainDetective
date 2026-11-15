using DomainDetective.PowerShell;
using DomainDetective.Reports;
using DomainDetective.Views;

namespace DomainDetective.Tests.Reports;

[Collection("ExportDefaults")]
public class TestPowerShellExportBatchRecovery {
    [Theory]
    [InlineData("docx")]
    [InlineData("pdf")]
    [InlineData("html")]
    public void FailedDestinationDoesNotPreventOtherFormats(string blockedExtension) {
        string directory = Path.Combine(Path.GetTempPath(), "dd-export-recovery-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        using var blocked = new FileStream(Path.Combine(directory, "report." + blockedExtension), FileMode.Create, FileAccess.ReadWrite, FileShare.None);
        try {
            var failure = Record.Exception(() => CompositionExportHelper.WriteReports(
                new object[] { new SpfRecordInfo { Subject = "example.test", SpfRecord = "v=spf1 -all" } },
                new[] { ReportFormat.Word, ReportFormat.Pdf, ReportFormat.Html }, Path.Combine(directory, "report.docx"),
                "example.test", ReportScope.Normal, "Batch recovery", false, null, out _));
            foreach (string extension in new[] { "docx", "pdf", "html" }.Where(extension => extension != blockedExtension)) {
                Assert.Contains("example.test", ReportArtifactText.Read(Path.Combine(directory, "report." + extension)));
            }
            Assert.IsType<AggregateException>(failure);
        } finally { blocked.Dispose(); Directory.Delete(directory, true); }
    }

    [Theory]
    [InlineData(ReportFormat.Word, "docx")]
    [InlineData(ReportFormat.Pdf, "pdf")]
    [InlineData(ReportFormat.Html, "html")]
    [InlineData(ReportFormat.Excel, "xlsx")]
    [InlineData(ReportFormat.Markdown, "md")]
    public void StandaloneArcRetainsStructuralEvidenceAndFindings(ReportFormat format, string extension) {
        string directory = Path.Combine(Path.GetTempPath(), "dd-arc-export-" + Guid.NewGuid().ToString("N"));
        var view = CreateArc();
        Assert.Equal("Message Headers", view.Subject);
        try {
            var paths = CompositionExportHelper.WriteReports(new object[] { view }, new[] { format },
                Path.Combine(directory, "arc." + extension), "headers.txt", ReportScope.Normal, "ARC Report", false, null, out var unsupported);
            Assert.False(unsupported);
            string text = ReportArtifactText.Read(Assert.Single(paths));
            Assert.Contains("Preserved ARC structural finding", text);
            Assert.Contains(view.ChainState, text);
            Assert.Contains("ARC-Seal count", text);
            Assert.Matches(@"ARC-Authentication-Results(?:\s+1)?\s+count", text);
            Assert.Contains("relay.example.test", text);
            Assert.Contains("not performed", text, StringComparison.OrdinalIgnoreCase);
        } finally { if (Directory.Exists(directory)) { Directory.Delete(directory, true); } }
    }

    [Fact]
    public async Task CompositionPreservesMessageAndArcEvidenceThroughOptionalRenderers() {
        string directory = Path.Combine(Path.GetTempPath(), "dd-message-composition-" + Guid.NewGuid().ToString("N"));
        var message = new MessageHeaderAnalysis();
        message.Parse("From: sender@example.test\r\nSubject: Original message retained\r\n");
        message.SignatureVerification.Add(new MessageSignatureVerification {
            Method = "DKIM", Status = MessageSignatureStatus.Invalid, Explanation = "Original verification finding"
        });
        try {
            var result = await CompositionExportService.ExportAsync(new CompositionExportRequest {
                Items = new object[] { message, CreateArc() }, AutoCollectTtl = true,
                Formats = new[] { ReportFormat.Word, ReportFormat.Pdf, ReportFormat.Json, ReportFormat.Excel, ReportFormat.Markdown, ReportFormat.Html },
                ExportPath = Path.Combine(directory, "message.docx")
            });
            Assert.Equal(6, result.Reports.Count);
            var json = Assert.Single(result.Reports, report => report.Format == ReportFormat.Json);
            Assert.False(json.Success);
            Assert.Contains("JSON message evidence", json.ErrorMessage);
            Assert.False(File.Exists(json.FilePath));
            Assert.All(result.Reports.Where(report => report.Format != ReportFormat.Json), report => {
                Assert.True(report.Success, report.ErrorMessage);
                string text = ReportArtifactText.Read(report.FilePath);
                Assert.Contains("Original message retained", text);
                Assert.Contains("Original verification finding", text);
                Assert.Contains("Preserved ARC structural finding", text);
                Assert.Contains("relay.example.test", text);
            });
        } finally { if (Directory.Exists(directory)) { Directory.Delete(directory, true); } }
    }

    [Fact]
    public async Task DomainHealthAdapterRetainsItsDomainReportWhenArcIsAlsoPopulated() {
        using var health = new DomainHealthCheck();
        health.SpfAnalysis.Subject = "example.test";
        health.SpfAnalysis.Assessments.Add(new Assessment {
            Severity = AssessmentSeverity.Warning, Code = "SPF.EXPORT", Message = "Retained domain finding"
        });
        health.ArcAnalysis.Analyze("ARC-Seal: i=1; d=relay.example.test; cv=none; b=fixture\r\n");
        string path = Path.Combine(Path.GetTempPath(), "dd-domain-with-arc-" + Guid.NewGuid().ToString("N") + ".md");
        try {
            var report = await new ReportDispatcher().GenerateAsync(health,
                new ReportOptions { Format = ReportFormat.Markdown, OutputPath = path }, "example.test");
            Assert.True(report.Success, report.ErrorMessage);
            string text = ReportArtifactText.Read(report.FilePath);
            Assert.Contains("example.test", text);
            Assert.Contains("Retained domain finding", text);
        } finally { File.Delete(path); }
    }

    private static ArcInfo CreateArc() {
        var analysis = new ARCAnalysis();
        analysis.Analyze("ARC-Seal: i=1; a=rsa-sha256; d=relay.example.test; s=arc; cv=none; b=fixture\r\n"
            + "ARC-Authentication-Results: i=1; relay.example.test; dkim=pass header.d=sender.example.test\r\n");
        analysis.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Warning, Code = "ARC.EXPORT", Message = "Preserved ARC structural finding" });
        return Converters.Convert(analysis);
    }
}
