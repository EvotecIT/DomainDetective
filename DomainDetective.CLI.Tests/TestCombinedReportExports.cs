using System.IO.Compression;
using System.Text;
using System.Threading;
using System.Xml.Linq;
using DomainDetective.CLI.Commands;
using DomainDetective.Reports;
using DomainDetective.Views;
using Spectre.Console.Cli;

namespace DomainDetective.CLI.Tests;

public sealed class TestCombinedReportExports {
    [Theory]
    [InlineData("json")]
    [InlineData("json,markdown")]
    [InlineData("markdown,json")]
    [InlineData("json,markdownhtml")]
    [InlineData("markdownhtml,json")]
    public async Task JsonKeepsRawHealthSchemaAlongsideAssessmentFormats(string requested) {
        string directory = Path.Combine(Path.GetTempPath(), "dd-cli-json-" + Guid.NewGuid().ToString("N"));
        using var health = new DomainHealthCheck();
        health.SpfAnalysis.Subject = "example.test";
        var settings = Bind<GenerateReportCommand.Settings>("example.test", "--format", requested,
            "--output", Path.Combine(directory, "assessment.json"));
        settings.OpenInBrowser = false;
        try {
            var result = await GenerateReportCommand.ExportReportsAsync(settings,
                new object[] { new SpfRecordInfo { Subject = "example.test", Check = HealthCheckType.SPF } }, healthCheck: health);
            var json = Assert.Single(result.Reports, report => report.Format == ReportFormat.Json);
            using var document = System.Text.Json.JsonDocument.Parse(File.ReadAllText(json.FilePath));
            Assert.Equal("example.test", document.RootElement.GetProperty("SpfAnalysis").GetProperty("Subject").GetString());
            Assert.False(document.RootElement.TryGetProperty("domains", out _));
            Assert.Equal(ReportFormatParser.Parse(new[] { requested }), result.Reports.Select(report => report.Format));
            if (requested.Contains("markdownhtml", StringComparison.Ordinal)) {
                var html = Assert.Single(result.Reports, report => report.Format == ReportFormat.MarkdownHtml);
                Assert.Equal(Path.Combine(directory, "assessment.markdown.html"), html.FilePath);
                Assert.True(File.Exists(Path.Combine(directory, "assessment.markdown.md")));
            }
        } finally { if (Directory.Exists(directory)) { Directory.Delete(directory, true); } }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SpectreBindsWordAndPdfRepeatedOrCommaSeparated(bool commaSeparated) {
        string[] args = commaSeparated
            ? new[] { "example.test", "--format", "word,pdf" }
            : new[] { "example.test", "--format", "word", "--format", "pdf" };
        var report = Bind<GenerateReportCommand.Settings>(args);
        Assert.Equal("example.test", report.Domain);
        Assert.Equal(new[] { ReportFormat.Word, ReportFormat.Pdf }, GenerateReportCommand.ValidatePresentation(report));
        var desired = Bind<DesiredStateCommand.Settings>(args);
        Assert.Equal(new[] { "example.test" }, desired.Domains);
        Assert.Equal(new[] { ReportFormat.Word, ReportFormat.Pdf }, ReportFormatParser.Parse(desired.Formats));
    }

    [Fact]
    public void SpectreDefaultReportIsHtmlAndAliasesDeduplicateInInputOrder() {
        Assert.Equal(ReportFormat.Html, Assert.Single(GenerateReportCommand.ValidatePresentation(Bind<GenerateReportCommand.Settings>("example.test"))));
        var settings = Bind<GenerateReportCommand.Settings>("example.test", "--report", "PDF,docx", "-f", "word,pdf");
        Assert.Equal(new[] { ReportFormat.Pdf, ReportFormat.Word }, GenerateReportCommand.ValidatePresentation(settings));
    }

    [Fact]
    public void UnknownFormatFailsBeforeExportCreatesDirectory() {
        string directory = Path.Combine(Path.GetTempPath(), "dd-cli-invalid-" + Guid.NewGuid().ToString("N"));
        var settings = Bind<GenerateReportCommand.Settings>("example.test", "--format", "word,not-a-format", "--output", Path.Combine(directory, "report.docx"));
        var error = Assert.Throws<ArgumentException>(() => GenerateReportCommand.ValidatePresentation(settings));
        Assert.Contains("not-a-format", error.Message);
        Assert.False(Directory.Exists(directory));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ProductionExportSeamsWriteDistinctWordAndPdfFromFixtureViews(bool desiredState) {
        string directory = Path.Combine(Path.GetTempPath(), "dd-cli-pdf-" + Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "assessment.docx");
        var finding = new Assessment { Code = "EXPORT.FIXTURE", Severity = AssessmentSeverity.Warning, Message = "Fixture export finding", Target = "example.test" };
        try {
            CompositionExportResult result;
            if (desiredState) {
                var settings = Bind<DesiredStateCommand.Settings>("example.test", "--format", "word,pdf", "--output", path);
                result = await DesiredStateCommand.ExportReportsAsync(settings, new object[] {
                    new DesiredStateInfo { Subject = "example.test", DesiredAssessments = new[] { finding } }
                });
            } else {
                var settings = Bind<GenerateReportCommand.Settings>("example.test", "--format", "word", "--format", "pdf", "--output", path);
                settings.OpenInBrowser = false;
                result = await GenerateReportCommand.ExportReportsAsync(settings, new object[] {
                    new SpfRecordInfo { Subject = "example.test", Check = HealthCheckType.SPF, Assessments = new[] { finding } }
                });
            }
            Assert.All(result.Reports, report => Assert.True(report.Success, report.ErrorMessage));
            var word = Assert.Single(result.Reports, report => report.Format == ReportFormat.Word);
            var pdf = Assert.Single(result.Reports, report => report.Format == ReportFormat.Pdf);
            Assert.NotEqual(word.FilePath, pdf.FilePath);
            Assert.Equal(".docx", Path.GetExtension(word.FilePath));
            Assert.Equal(".pdf", Path.GetExtension(pdf.FilePath));
            using var archive = ZipFile.OpenRead(word.FilePath);
            using var xml = archive.GetEntry("word/document.xml")!.Open();
            Assert.Contains("Fixture export finding", XDocument.Load(xml).Root!.Value);
            Assert.Equal("%PDF-", Encoding.ASCII.GetString(File.ReadAllBytes(pdf.FilePath), 0, 5));
            Assert.False(Directory.Exists(Path.Combine(directory, "artifacts")), "Exporting already-collected views must not start another analysis/artifact run.");
        } finally { if (Directory.Exists(directory)) { Directory.Delete(directory, true); } }
    }

    [Theory]
    [InlineData("light", false)]
    [InlineData("light", true)]
    [InlineData("dark", false)]
    [InlineData("dark", true)]
    public async Task CombinedExportPreservesExplicitHtmlTheme(string theme, bool reverseOrder) {
        string directory = Path.Combine(Path.GetTempPath(), "dd-cli-theme-" + Guid.NewGuid().ToString("N"));
        var formats = new[] { ReportFormat.Html, ReportFormat.Pdf, ReportFormat.Markdown, ReportFormat.MarkdownHtml };
        if (reverseOrder) { Array.Reverse(formats); }
        var finding = new Assessment { Code = "EXPORT.FIXTURE", Severity = AssessmentSeverity.Warning, Message = "Fixture export finding", Target = "example.test" };
        try {
            var settings = Bind<GenerateReportCommand.Settings>("example.test", "--format", string.Join(",", formats), "--theme", theme,
                "--output", Path.Combine(directory, "report.html"));
            settings.OpenInBrowser = false;
            var result = await GenerateReportCommand.ExportReportsAsync(settings, new object[] {
                new SpfRecordInfo { Subject = "example.test", Check = HealthCheckType.SPF, Assessments = new[] { finding } }
            });
            Assert.All(result.Reports, report => Assert.True(report.Success, report.ErrorMessage));
            Assert.Equal(formats, result.Reports.Select(report => report.Format));
            var html = Assert.Single(result.Reports, report => report.Format == ReportFormat.Html);
            var pdf = Assert.Single(result.Reports, report => report.Format == ReportFormat.Pdf);
            var markdown = Assert.Single(result.Reports, report => report.Format == ReportFormat.Markdown);
            var markdownHtml = Assert.Single(result.Reports, report => report.Format == ReportFormat.MarkdownHtml);
            Assert.Equal(Path.Combine(directory, "report.html"), html.FilePath);
            Assert.Equal(Path.Combine(directory, "report.pdf"), pdf.FilePath);
            Assert.Equal(Path.Combine(directory, "report.md"), markdown.FilePath);
            Assert.Equal(Path.Combine(directory, "report.markdown.html"), markdownHtml.FilePath);
            Assert.Contains("data-hfx-theme-selection=\"" + theme + "\"", File.ReadAllText(html.FilePath));
            Assert.Equal("%PDF-", Encoding.ASCII.GetString(File.ReadAllBytes(pdf.FilePath), 0, 5));
            string markdownText = File.ReadAllText(markdown.FilePath);
            Assert.Contains("example.test", markdownText);
            Assert.Contains(finding.Message, markdownText);
            Assert.Contains(finding.Message, File.ReadAllText(markdownHtml.FilePath));
            string sidecar = Path.ChangeExtension(markdownHtml.FilePath, ".md");
            Assert.Equal(Path.Combine(directory, "report.markdown.md"), sidecar);
            Assert.DoesNotContain(sidecar, result.Reports.Select(report => report.FilePath));
            Assert.Equal(markdownText, File.ReadAllText(sidecar));
            Assert.False(Directory.Exists(Path.Combine(directory, "artifacts")), "Exporting already-collected views must not start another analysis/artifact run.");
        } finally { if (Directory.Exists(directory)) { Directory.Delete(directory, true); } }
    }

    [Fact]
    public async Task ReportCommandReportsMemberFailureWhileKeepingSuccessfulPdf() {
        string directory = Path.Combine(Path.GetTempPath(), "dd-cli-partial-" + Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "assessment.pdf");
        // Resolve the explicit PDF base path normally, but make its Word sibling unwritable as a file.
        Directory.CreateDirectory(Path.Combine(directory, "assessment.docx"));
        try {
            var settings = Bind<GenerateReportCommand.Settings>("example.test", "--format", "word,pdf", "--output", path);
            settings.OpenInBrowser = false;
            var error = await Assert.ThrowsAsync<InvalidOperationException>(() => GenerateReportCommand.ExportReportsAsync(settings,
                new object[] { new SpfRecordInfo { Subject = "example.test", Check = HealthCheckType.SPF } }));
            Assert.False(string.IsNullOrWhiteSpace(error.Message));
            string pdfPath = Path.Combine(directory, "assessment.pdf");
            Assert.Equal("%PDF-", Encoding.ASCII.GetString(File.ReadAllBytes(pdfPath), 0, 5));
        } finally { if (Directory.Exists(directory)) { Directory.Delete(directory, true); } }
    }

    private static TSettings Bind<TSettings>(params string[] args) where TSettings : CommandSettings, new() {
        TSettings? captured = null;
        CaptureCommand<TSettings>.Capture.Value = settings => captured = settings;
        try {
            var app = new CommandApp<CaptureCommand<TSettings>>();
            app.Configure(config => config.PropagateExceptions());
            Assert.Equal(0, app.Run(args));
            return Assert.IsType<TSettings>(captured);
        } finally { CaptureCommand<TSettings>.Capture.Value = null; }
    }

    public sealed class CaptureCommand<TSettings> : Command<TSettings> where TSettings : CommandSettings, new() {
        internal static readonly AsyncLocal<Action<TSettings>?> Capture = new();
        public override int Execute(CommandContext context, TSettings settings, CancellationToken cancellationToken) {
            Capture.Value!(settings);
            return 0;
        }
    }
}
