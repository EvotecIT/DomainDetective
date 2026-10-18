using System.Reflection;
using DnsClientX;
using DomainDetective.CLI.Wizard;
using Spectre.Console;
using Xunit.Abstractions;

namespace DomainDetective.CLI.Tests;

[Collection("HttpListener")]
public class TestWizardPartialResults {
    private readonly ITestOutputHelper _output;
    public TestWizardPartialResults(ITestOutputHelper output) => _output = output;

    [Fact]
    public async Task FullSummaryDoesNotAssessUnrequestedThreatIntelligence() {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) => Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError });
        await health.Verify("fixture.example", new[] { HealthCheckType.SPF });
        var previous = AnsiConsole.Console;
        using var output = new StringWriter();
        AnsiConsole.Console = AnsiConsole.Create(new AnsiConsoleSettings { Ansi = AnsiSupport.No, Out = new AnsiConsoleOutput(output) });
        try {
            Ui.RenderCheckSummariesPanel(health, false, ScanMode.Full);
            _output.WriteLine(output.ToString());
            Assert.Contains("SPF", output.ToString());
            Assert.DoesNotContain("THREAT", output.ToString());
            Assert.DoesNotContain("0/0", output.ToString());
        } finally { AnsiConsole.Console = previous; }
    }

    [Theory]
    [InlineData("standard")]
    [InlineData("advanced")]
    public async Task DetailedPartialSelectionDoesNotRenderFailedAnalysisDefaults(string details) {
        var logger = new InternalLogger();
        using var health = new DomainHealthCheck(internalLogger: logger) { Progress = false };
        health.DnsConfiguration.QueryDnsResponseOverride = (_, type, _) => type == DnsRecordType.SOA
            ? throw new InvalidOperationException("Synthetic SOA failure")
            : Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError });
        var previous = AnsiConsole.Console;
        using var output = new StringWriter();
        AnsiConsole.Console = AnsiConsole.Create(new AnsiConsoleSettings { Ansi = AnsiSupport.No, Out = new AnsiConsoleOutput(output) });
        try {
            var wizard = new DomainWizard(new WizardOptions { Domain = "fixture.example", Checks = new[] { HealthCheckType.CAA, HealthCheckType.SOA },
                Details = details, DisableLive = true, PersonaLive = false, ShowTitle = false });
            await (Task<DomainHealthCheck>)typeof(DomainWizard).GetMethod("RunCoreAsync", BindingFlags.NonPublic | BindingFlags.Instance)!
                .Invoke(wizard, new object[] { health, logger, CancellationToken.None })!;
            Assert.Contains("CAA", output.ToString());
            Assert.Contains("Incomplete", output.ToString());
            Assert.DoesNotContain("SerialNumber", output.ToString());
            _output.WriteLine(output.ToString());
        } finally { AnsiConsole.Console = previous; }
    }

    [Fact]
    public async Task PosturePanelsDistinguishUnrequestedAndIncompleteEvidence() {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsResponseOverride = (_, type, _) => type == DnsRecordType.SOA
            ? throw new InvalidOperationException("Synthetic SOA failure")
            : Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError });
        await Assert.ThrowsAsync<InvalidOperationException>(() => health.Verify("fixture.example", new[] { HealthCheckType.CAA, HealthCheckType.SOA }));
        var previous = AnsiConsole.Console;
        using var output = new StringWriter();
        AnsiConsole.Console = AnsiConsole.Create(new AnsiConsoleSettings { Ansi = AnsiSupport.No, Out = new AnsiConsoleOutput(output) });
        try {
            Ui.RenderPosturePanels(health);
            Assert.Contains("Not assessed", output.ToString());
            Assert.DoesNotContain("CLOSED", output.ToString());
            Assert.DoesNotContain("HTTP: NO", output.ToString());
            _output.WriteLine(output.ToString());
        } finally { AnsiConsole.Console = previous; }
    }

    [Fact]
    public async Task SelectedDkimSummaryRendersTheSelectorCollection() {
        using var health = new DomainHealthCheck();
        await health.DKIMAnalysis.AnalyzeDkimRecords("selector-fixture", new[] {
            new DnsAnswer { Type = DnsRecordType.TXT, DataRaw = "v=DKIM1; k=rsa; p=" }
        }, new InternalLogger());
        var previous = AnsiConsole.Console;
        using var output = new StringWriter();
        AnsiConsole.Console = AnsiConsole.Create(new AnsiConsoleSettings { Ansi = AnsiSupport.No, Out = new AnsiConsoleOutput(output) });
        try {
            OutputFormatters.FormatAsSelectedSummary(health, new[] { HealthCheckType.DKIM }, new HashSet<HealthCheckType> { HealthCheckType.DKIM });
            Assert.Contains("selector-fixture", output.ToString());
            Assert.Contains("no key", output.ToString());
            Assert.DoesNotContain("See check details", output.ToString());
            _output.WriteLine(output.ToString());
        } finally { AnsiConsole.Console = previous; }
    }
    [Fact]
    public async Task InvalidPlanStillFailsBeforeRenderingResults() {
        var logger = new InternalLogger();
        using var health = new DomainHealthCheck(internalLogger: logger);
        var wizard = new DomainWizard(new WizardOptions { Domain = "fixture.example", Output = "json", Checks = new[] { HealthCheckType.ARC } });
        var run = (Task<DomainHealthCheck>)typeof(DomainWizard).GetMethod("RunCoreAsync", BindingFlags.NonPublic | BindingFlags.Instance)!
            .Invoke(wizard, new object[] { health, logger, CancellationToken.None })!;
        await Assert.ThrowsAsync<ArgumentException>(() => run);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task SelectedSummaryRendersCollectedEvidenceAfterSiblingFailure(bool failSibling, bool live) {
        var previous = AnsiConsole.Console;
        using var output = new StringWriter();
        AnsiConsole.Console = AnsiConsole.Create(new AnsiConsoleSettings {
            Ansi = live ? AnsiSupport.Yes : AnsiSupport.No, Interactive = live ? InteractionSupport.Yes : InteractionSupport.No,
            ColorSystem = ColorSystemSupport.NoColors, Out = new AnsiConsoleOutput(output)
        });
        var logger = new InternalLogger();
        using var health = new DomainHealthCheck(internalLogger: logger) { Progress = false };
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => {
            if (failSibling && type == DnsRecordType.SOA) { throw new InvalidOperationException("Synthetic SOA failure"); }
            return Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError,
                Answers = type == DnsRecordType.CAA
                    ? new[] { new DnsAnswer { Type = type, DataRaw = "0 issue \"ca.example\"" } } : Array.Empty<DnsAnswer>() });
        };
        var wizard = new DomainWizard(new WizardOptions {
            Domain = "fixture.example", Checks = new[] { HealthCheckType.SOA, HealthCheckType.CAA },
            Details = "summary", DisableLive = !live, PersonaLive = false, ShowTitle = false
        });
        try {
            using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var result = await (Task<DomainHealthCheck>)typeof(DomainWizard).GetMethod("RunCoreAsync", BindingFlags.NonPublic | BindingFlags.Instance)!
                .Invoke(wizard, new object[] { health, logger, guard.Token })!;
            Assert.Same(health, result);
            Assert.Equal(failSibling ? 1 : 0, WizardScanCommand.WriteScanOutputs(health,
                new WizardOptions { Domain = "fixture.example" }, "fixture.example"));
            Assert.Equal(1, health.CAAAnalysis.ValidRecords);
            Assert.Contains("CAA", output.ToString());
            Assert.Contains("valid 1", output.ToString());
            if (failSibling) { Assert.Contains("incomplete", output.ToString(), StringComparison.OrdinalIgnoreCase); }
            Assert.DoesNotContain("Registrar", output.ToString());
        } finally {
            _output.WriteLine(output.ToString());
            AnsiConsole.Console = previous;
        }
    }

    [Theory]
    [InlineData("json")]
    [InlineData("html")]
    public async Task NonConsoleFailureRetainsEvidenceInWrittenArtifactAndReturnsFailure(string format) {
        var previous = AnsiConsole.Console;
        using var console = new StringWriter();
        AnsiConsole.Console = AnsiConsole.Create(new AnsiConsoleSettings { Ansi = AnsiSupport.No, Out = new AnsiConsoleOutput(console) });
        var logger = new InternalLogger();
        using var health = new DomainHealthCheck(internalLogger: logger);
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => {
            if (type == DnsRecordType.SOA) { throw new InvalidOperationException("Synthetic SOA failure <retained>"); }
            return Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError,
                Answers = name == "fixture.example" && type == DnsRecordType.TXT
                    ? new[] { new DnsAnswer { Type = type, DataRaw = "v=spf1 -all" } } : Array.Empty<DnsAnswer>() });
        };
        var folder = Path.Combine(Path.GetTempPath(), "dd-wizard-" + Guid.NewGuid().ToString("N"));
        var path = Path.Combine(folder, "scan." + format);
        var wizard = new DomainWizard(new WizardOptions {
            Domain = "fixture.example", Output = format, Out = path, Checks = new[] { HealthCheckType.SOA, HealthCheckType.SPF }
        });
        try {
            using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var result = await (Task<DomainHealthCheck>)typeof(DomainWizard).GetMethod("RunCoreAsync", BindingFlags.NonPublic | BindingFlags.Instance)!
                .Invoke(wizard, new object[] { health, logger, guard.Token })!;
            Assert.Same(health, result);
            Assert.False(health.VerificationCompleted);
            Assert.Contains(HealthCheckType.SPF, health.VerificationCompletedChecks);
            Assert.DoesNotContain(HealthCheckType.SOA, health.VerificationCompletedChecks);
            Assert.Equal("Synthetic SOA failure <retained>", health.VerificationError);
            Assert.Equal(1, WizardScanCommand.WriteScanOutputs(health, wizard.Options, "fixture.example"));
            var artifact = File.ReadAllText(path);
            Assert.Contains("Synthetic SOA failure", artifact);
            Assert.Contains("v=spf1 -all", artifact);
            if (format == "json") {
                using var parsed = System.Text.Json.JsonDocument.Parse(artifact);
                Assert.False(parsed.RootElement.GetProperty("VerificationCompleted").GetBoolean());
            } else {
                Assert.Contains("Scan incomplete", artifact);
                Assert.Contains("&lt;retained&gt;", artifact);
                Assert.Contains("AXFR: Not assessed", artifact);
                Assert.DoesNotContain("✅ closed", artifact);
                _output.WriteLine("HTML_FIXTURE\n" + artifact);
                var legacyPath = Path.Combine(folder, "legacy.html");
                OutputFormatters.ExportToHtml("fixture.example", health, legacyPath);
                var legacy = File.ReadAllText(legacyPath);
                Assert.Contains("Scan incomplete", legacy);
                Assert.Contains("&lt;retained&gt;", legacy);
                Assert.DoesNotContain("<h3>DMARC</h3>", legacy);
                Assert.Contains("<h3>SOA</h3>", legacy);
                Assert.Contains("This check did not complete", legacy);
                Assert.Contains("<meta charset='utf-8'>", legacy);
                _output.WriteLine("LEGACY_HTML_FIXTURE\n" + legacy);
            }
        } finally {
            AnsiConsole.Console = previous;
            if (Directory.Exists(folder)) { Directory.Delete(folder, true); }
        }
    }

    [Fact]
    public async Task WizardCallerCancellationStillPropagates() {
        var logger = new InternalLogger();
        using var health = new DomainHealthCheck(internalLogger: logger);
        var wizard = new DomainWizard(new WizardOptions { Domain = "fixture.example", Output = "json", Checks = new[] { HealthCheckType.CAA } });
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        var run = (Task<DomainHealthCheck>)typeof(DomainWizard).GetMethod("RunCoreAsync", BindingFlags.NonPublic | BindingFlags.Instance)!
            .Invoke(wizard, new object[] { health, logger, canceled.Token })!;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
    }
}
