using System;
using System.IO;
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

            var writtenPath = WizardExportUtilities.WriteJson(healthCheck, "example.com", output);

            Assert.Equal(output, writtenPath);
            Assert.True(File.Exists(writtenPath));

            var json = File.ReadAllText(writtenPath);
            Assert.Contains("example.com", json, StringComparison.OrdinalIgnoreCase);
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
