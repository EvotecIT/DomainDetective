using System.Reflection;
using DnsClientX;
using Spectre.Console;
using Xunit.Abstractions;

namespace DomainDetective.CLI.Tests;

[Collection("HttpListener")]
public class TestLegacyCompletionEvidence {
    private readonly ITestOutputHelper _output;
    public TestLegacyCompletionEvidence(ITestOutputHelper output) => _output = output;

    [Fact]
    public async Task SelectedSummaryIncludesCompletedChecksOutsideTheLegacyMap() {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) => Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError });
        await health.Verify("fixture.example", new[] { HealthCheckType.SOA });
        var previous = AnsiConsole.Console;
        using var output = new StringWriter();
        AnsiConsole.Console = AnsiConsole.Create(new AnsiConsoleSettings { Ansi = AnsiSupport.No, Out = new AnsiConsoleOutput(output) });
        try {
            OutputFormatters.FormatAsSelectedSummary(health, new[] { HealthCheckType.SOA }, health.VerificationCompletedChecks.ToHashSet());
            _output.WriteLine(output.ToString());
            Assert.Contains("SOA", output.ToString());
            Assert.DoesNotContain("SPF", output.ToString());
            var folder = Path.Combine(Path.GetTempPath(), "dd-selected-soa-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(folder);
            try {
                var path = Path.Combine(folder, "scan.html");
                OutputFormatters.ExportToHtml("fixture.example", health, path);
                Assert.Contains("<h3>SOA</h3>", File.ReadAllText(path));
            } finally { Directory.Delete(folder, true); }
        } finally { AnsiConsole.Console = previous; }
    }

    [Fact]
    public async Task BatchCliRetainsTheRequestedSupplementalLookup() {
        int cnameQueries = 0;
        using var health = new DomainHealthCheck();
        health.ExecutionOptions.IncludeTakeoverCname = true;
        health.DnsConfiguration.QueryDnsResponseOverride = (_, type, _) => {
            if (type == DnsRecordType.CNAME) { Interlocked.Increment(ref cnameQueries); }
            return Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError });
        };
        Func<string, DomainHealthCheck> factory = _ => health;
        var runs = await (Task<IReadOnlyList<DomainHealthCheckRun>>)typeof(CommandUtilities)
            .GetMethod("RunDomainBatchAsync", BindingFlags.NonPublic | BindingFlags.Static)!
            .Invoke(null, new object?[] { new[] { "fixture.example" }, new[] { HealthCheckType.CAA }, null, null,
                factory, false, false, true, CancellationToken.None })!;
        Assert.Null(Assert.Single(runs).Error);
        Assert.Equal(1, cnameQueries);
        Assert.True(health.VerificationTakeoverCompleted);
    }

    [Fact]
    public async Task SelectedOnlyHtmlDoesNotAssessUnrequestedSummaryFields() {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) => Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError });
        await health.Verify("fixture.example", new[] { HealthCheckType.CAA });
        var folder = Path.Combine(Path.GetTempPath(), "dd-selected-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try {
            var path = Path.Combine(folder, "scan.html");
            OutputFormatters.ExportToHtml("fixture.example", health, path);
            var html = File.ReadAllText(path);
            Assert.Contains("<h3>CAA</h3>", html);
            Assert.DoesNotContain("HasSpfRecord", html);
            Assert.DoesNotContain("CAA records present", html);
            Assert.Contains("valid 0", html);
            Assert.Empty(health.BuildSummary().Hints);
            Assert.Equal(new[] { HealthCheckType.CAA }, health.BuildSummary().AssessedChecks);
            _output.WriteLine("SELECTED_ONLY_HTML_FIXTURE\n" + html);
        } finally { Directory.Delete(folder, true); }
    }

    [Fact]
    public async Task RequestedTakeoverFailureRetainsPrimaryEvidenceAndMarksExportsIncomplete() {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsResponseOverride = (_, type, _) => {
            if (type == DnsRecordType.CNAME) { throw new InvalidOperationException("Synthetic takeover lookup failure"); }
            return Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError,
                Answers = type == DnsRecordType.TXT
                    ? new[] { new DnsAnswer { Type = type, DataRaw = "v=spf1 -all" } } : Array.Empty<DnsAnswer>() });
        };
        health.ExecutionOptions.IncludePlainHttp = true;
        health.PlainHttpAnalysis.HttpHandlerFactory = () => new SuccessfulHttpHandler();
        health.ExecutionOptions.IncludeTakeoverCname = true;
        await Assert.ThrowsAsync<InvalidOperationException>(() => health.Verify("fixture.example", new[] { HealthCheckType.SPF }));
        Assert.False(health.VerificationTakeoverCompleted);
        Assert.True(health.VerificationPlainHttpCompleted);
        Assert.Contains(HealthCheckType.SPF, health.VerificationCompletedChecks);
        using var json = System.Text.Json.JsonDocument.Parse(health.ToJson());
        Assert.False(json.RootElement.GetProperty("VerificationCompleted").GetBoolean());
        Assert.Contains("v=spf1 -all", health.ToJson());
        var previous = AnsiConsole.Console;
        using var console = new StringWriter();
        var folder = Path.Combine(Path.GetTempPath(), "dd-supplemental-" + Guid.NewGuid().ToString("N"));
        AnsiConsole.Console = AnsiConsole.Create(new AnsiConsoleSettings { Ansi = AnsiSupport.No, Out = new AnsiConsoleOutput(console) });
        try {
            typeof(WizardMode).GetMethod("DisplayResultsAsConsole", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, new object[] { "fixture.example", health, new[] { HealthCheckType.SPF }, true, true, false });
            var text = console.ToString();
            Assert.Contains("PLAIN HTTP", text);
            Assert.Contains("StatusCode", text);
            Assert.Contains("TAKEOVER", text);
            Assert.Contains("Incomplete", text);
            _output.WriteLine("SUPPLEMENTAL_CONSOLE\n" + text);
            var path = Path.Combine(folder, "scan.html");
            Directory.CreateDirectory(folder);
            OutputFormatters.ExportToHtml("fixture.example", health, path);
            var html = File.ReadAllText(path);
            Assert.Contains("Scan incomplete", html);
            Assert.Contains("Synthetic takeover lookup failure", html);
            Assert.Contains("<h3>SPF</h3>", html);
            _output.WriteLine("SUPPLEMENTAL_HTML_FIXTURE\n" + html);
        } finally {
            AnsiConsole.Console = previous;
            if (Directory.Exists(folder)) { Directory.Delete(folder, true); }
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task IncompleteLegacyResultsDoNotDisplayDefaultAssessments(bool cards) {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsResponseOverride = (_, type, _) => {
            if (type == DnsRecordType.SOA) { throw new InvalidOperationException("Synthetic SOA failure"); }
            return Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError,
                Answers = type == DnsRecordType.TXT
                    ? new[] { new DnsAnswer { Type = type, DataRaw = "v=spf1 -all" } } : Array.Empty<DnsAnswer>() });
        };
        await Assert.ThrowsAsync<InvalidOperationException>(() => health.Verify("fixture.example",
            new[] { HealthCheckType.SPF, HealthCheckType.SOA },
            executionOptions: new HealthCheckExecutionOptions { EnableParallelism = false }));
        var previous = AnsiConsole.Console;
        using var output = new StringWriter();
        AnsiConsole.Console = AnsiConsole.Create(new AnsiConsoleSettings { Ansi = AnsiSupport.No, Out = new AnsiConsoleOutput(output) });
        try {
            if (cards) { OutputFormatters.FormatAsSummaryCards("fixture.example", health); }
            else {
                typeof(WizardMode).GetMethod("DisplayResultsAsConsole", BindingFlags.NonPublic | BindingFlags.Static)!
                    .Invoke(null, new object[] { "fixture.example", health,
                        new[] { HealthCheckType.SPF, HealthCheckType.SOA, HealthCheckType.CAA }, false, false, false });
            }
            var text = output.ToString();
            _output.WriteLine("LEGACY_COMPLETION_" + (cards ? "CARDS" : "CONSOLE") + "\n" + text);
            Assert.Contains("SPF", text);
            Assert.Contains(cards ? "Not assessed" : "Incomplete", text);
            if (!cards) { Assert.DoesNotContain("CAA for fixture.example", text); }
        } finally { AnsiConsole.Console = previous; }
    }

    private sealed class SuccessfulHttpHandler : System.Net.Http.HttpMessageHandler {
        protected override Task<System.Net.Http.HttpResponseMessage> SendAsync(System.Net.Http.HttpRequestMessage request, CancellationToken token) =>
            Task.FromResult(new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK));
    }
}
