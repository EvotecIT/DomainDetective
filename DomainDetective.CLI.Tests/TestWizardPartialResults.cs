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
