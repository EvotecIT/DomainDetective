using System.Reflection;
using Spectre.Console;
using Xunit.Abstractions;

namespace DomainDetective.CLI.Tests;

[Collection("HttpListener")]
public class TestWebsiteSummaryEvidence {
    private readonly ITestOutputHelper _output;
    public TestWebsiteSummaryEvidence(ITestOutputHelper output) => _output = output;

    [Theory]
    [InlineData(AssessmentSeverity.Warning, "Warning", "warning")]
    [InlineData(AssessmentSeverity.Error, "Error", "error")]
    public void WebsiteCompositeRetainsItsTypedStatusAndFindings(AssessmentSeverity severity, string expected, string css) {
        using var source = new DomainHealthCheck();
        source.HttpAnalysis.Assessments.Add(new Assessment { Severity = severity, Message = "Synthetic website finding" });
        using var health = source.FilterAnalyses(new[] { HealthCheckType.WEBSITE });
        var view = Assert.IsType<DomainDetective.Views.WebsiteInfo>(health.GetAnalysisMap()[HealthCheckType.WEBSITE]);
        Assert.Equal(expected, view.Status);
        var previous = AnsiConsole.Console;
        using var output = new StringWriter();
        AnsiConsole.Console = AnsiConsole.Create(new AnsiConsoleSettings { Ansi = AnsiSupport.No, Out = new AnsiConsoleOutput(output) });
        AnsiConsole.Profile.Width = 160;
        var folder = Path.Combine(Path.GetTempPath(), "dd-website-summary-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try {
            OutputFormatters.FormatAsSelectedSummary(health, new[] { HealthCheckType.WEBSITE }, new HashSet<HealthCheckType> { HealthCheckType.WEBSITE });
            var path = Path.Combine(folder, "scan.html");
            OutputFormatters.ExportToHtml("fixture.example", health, path);
            var html = File.ReadAllText(path);
            _output.WriteLine("CONSOLE\n" + output + "\nHTML\n" + html);
            Assert.Contains(expected, output.ToString());
            Assert.Contains(view.Summary.Trim(), output.ToString());
            Assert.Contains("<h3>WEBSITE</h3>" + Environment.NewLine + $"<div class='status {css}'>", html);
            Assert.Contains(view.Summary.Trim(), html);
            var summary = ((string Status, string Summary))typeof(OutputFormatters)
                .GetMethod("GetCheckSummary", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, new object[] { health, HealthCheckType.WEBSITE })!;
            Assert.Equal(view.Summary, summary.Summary);
        } finally { AnsiConsole.Console = previous; Directory.Delete(folder, true); }
    }
}
