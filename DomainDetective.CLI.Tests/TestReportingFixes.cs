using System;
using System.IO;
using System.Text.Json;
using DomainDetective;
using DomainDetective.CLI.Commands;
using DomainDetective.CLI.Wizard;
using DomainDetective.Reports;

namespace DomainDetective.CLI.Tests;

public sealed class TestReportingFixes
{
    [Fact]
    public void EnsureReportSucceeded_ThrowsWhenDispatcherFails()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => GenerateReportCommand.EnsureReportSucceeded(new ReportResult
        {
            Success = false,
            ErrorMessage = "boom"
        }));

        Assert.Equal("boom", ex.Message);
    }

    [Fact]
    public void EnsureReportSucceeded_UsesFallbackMessageWhenDispatcherDoesNotProvideOne()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => GenerateReportCommand.EnsureReportSucceeded(new ReportResult
        {
            Success = false,
            ErrorMessage = ""
        }));

        Assert.Equal("Report generation failed.", ex.Message);
    }

    [Fact]
    public void ReportFormatsAcceptPdfAlongsideWord() {
        Assert.Equal(new[] { ReportFormat.Word, ReportFormat.Pdf }, ReportFormatParser.Parse(new[] { "word,pdf" }));
    }

    [Theory]
    [InlineData("template")]
    [InlineData("technical")]
    [InlineData("recommendations")]
    public void ReportPresentationRejectsUnsupportedOverridesWithoutAnalysis(string option) {
        var settings = new GenerateReportCommand.Settings { Domain = "example.test" };
        if (option == "template") { settings.Template = "executive"; }
        if (option == "technical") { settings.IncludeTechnical = false; }
        if (option == "recommendations") { settings.IncludeRecommendations = false; }
        var error = Assert.Throws<InvalidOperationException>(() => GenerateReportCommand.ValidatePresentation(settings));
        Assert.Contains("--" + option, error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("system")]
    [InlineData("light")]
    [InlineData("dark")]
    public void ReportPresentationAcceptsSupportedHtmlThemes(string theme) {
        var settings = new GenerateReportCommand.Settings { Formats = new[] { "html" }, Theme = theme };
        Assert.Equal(ReportFormat.Html, Assert.Single(GenerateReportCommand.ValidatePresentation(settings)));
    }

    [Theory]
    [InlineData("word", "light")]
    [InlineData("word", "dark")]
    [InlineData("excel", "light")]
    [InlineData("excel", "dark")]
    [InlineData("markdown", "light")]
    [InlineData("markdown", "dark")]
    [InlineData("markdownhtml", "light")]
    [InlineData("markdownhtml", "dark")]
    [InlineData("json", "light")]
    [InlineData("json", "dark")]
    [InlineData("pdf", "light")]
    [InlineData("pdf", "dark")]
    public void ReportPresentationRejectsThemesForNonHtmlFormats(string format, string theme) {
        var settings = new GenerateReportCommand.Settings { Formats = new[] { format }, Theme = theme };
        var error = Assert.Throws<InvalidOperationException>(() => GenerateReportCommand.ValidatePresentation(settings));
        Assert.Contains("--theme", error.Message, StringComparison.Ordinal);
        Assert.Contains("only to HTML", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("html", ReportFormat.Html)]
    [InlineData("word", ReportFormat.Word)]
    [InlineData("excel", ReportFormat.Excel)]
    [InlineData("markdown", ReportFormat.Markdown)]
    [InlineData("markdownhtml", ReportFormat.MarkdownHtml)]
    [InlineData("json", ReportFormat.Json)]
    [InlineData("pdf", ReportFormat.Pdf)]
    public void ReportPresentationAcceptsDefaultSettingsForShippedFormats(string format, ReportFormat expected) {
        Assert.Equal(expected, Assert.Single(GenerateReportCommand.ValidatePresentation(new GenerateReportCommand.Settings { Formats = new[] { format } })));
    }

    [Fact]
    public void ReportPresentationRejectsUnknownHtmlThemeInsteadOfIgnoringIt() {
        var error = Assert.Throws<InvalidOperationException>(() => GenerateReportCommand.ValidatePresentation(
            new GenerateReportCommand.Settings { Theme = "unknown" }));
        Assert.Contains("--theme", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void PdfPresentationStillRejectsUnsupportedTemplates() {
        var error = Assert.Throws<InvalidOperationException>(() => GenerateReportCommand.ValidatePresentation(
            new GenerateReportCommand.Settings { Formats = new[] { "pdf" }, Template = "executive" }));
        Assert.Contains("--template", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ResolveOutputPath_CreatesParentDirectoryForExplicitFilePath()
    {
        var root = Path.Combine(Path.GetTempPath(), "dd-reporting-" + Guid.NewGuid().ToString("N"));
        var output = Path.Combine(root, "nested", "report.json");

        try
        {
            var resolved = ReportPathHelper.ResolveOutputPath(output, null, "example.com", ReportFormat.Json);

            Assert.Equal(output, resolved);
            Assert.True(Directory.Exists(Path.GetDirectoryName(output)!));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public void WizardExportUtilities_WriteHtml_WritesExpectedFile()
    {
        var root = Path.Combine(Path.GetTempPath(), "dd-wizard-html-" + Guid.NewGuid().ToString("N"));
        var output = Path.Combine(root, "exports", "wizard.html");

        try
        {
            var healthCheck = new DomainHealthCheck();

            var writtenPath = WizardExportUtilities.WriteHtml(healthCheck, "example.com", output);

            Assert.Equal(output, writtenPath);
            Assert.True(File.Exists(writtenPath));

            var html = File.ReadAllText(writtenPath);
            Assert.Contains("DomainDetective", html, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("example.com", html, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public void WizardExportUtilities_WriteJson_CreatesParentDirectoryAndWritesFile()
    {
        var root = Path.Combine(Path.GetTempPath(), "dd-wizard-json-" + Guid.NewGuid().ToString("N"));
        var output = Path.Combine(root, "exports", "wizard.json");

        try
        {
            var healthCheck = new DomainHealthCheck();

            var writtenPath = WizardExportUtilities.WriteJson(healthCheck, output);

            Assert.Equal(output, writtenPath);
            Assert.True(File.Exists(writtenPath));

            var json = File.ReadAllText(writtenPath);
            using var document = JsonDocument.Parse(json);
            Assert.Equal(JsonValueKind.Object, document.RootElement.ValueKind);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public void WizardExportUtilities_WriteJson_ThrowsArgumentExceptionForWhitespaceOutputPath()
    {
        var healthCheck = new DomainHealthCheck();

        var ex = Assert.Throws<ArgumentException>(() => WizardExportUtilities.WriteJson(healthCheck, "   "));

        Assert.Equal("outputPath", ex.ParamName);
    }

    [Fact]
    public void WizardExportUtilities_WriteHtml_ThrowsArgumentExceptionForWhitespaceDomain()
    {
        var healthCheck = new DomainHealthCheck();

        var ex = Assert.Throws<ArgumentException>(() => WizardExportUtilities.WriteHtml(healthCheck, "   ", null));

        Assert.Equal("domain", ex.ParamName);
    }

    [Fact]
    public void ResolveOutputPathForFormat_Rewrites_Mismatched_File_Extension()
    {
        var root = Path.Combine(Path.GetTempPath(), "dd-reporting-" + Guid.NewGuid().ToString("N"));
        var output = Path.Combine(root, "nested", "report.json");

        try
        {
            var resolved = ReportPathHelper.ResolveOutputPathForFormat(output, null, "example.com", ReportFormat.Word);

            Assert.Equal(Path.Combine(root, "nested", "report.docx"), resolved);
            Assert.True(Directory.Exists(Path.GetDirectoryName(resolved)!));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }
}
