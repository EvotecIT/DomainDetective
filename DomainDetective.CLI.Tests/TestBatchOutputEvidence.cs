using System.Reflection;
using System.Text.Json;
using DnsClientX;
using Spectre.Console;
using Xunit.Abstractions;

namespace DomainDetective.CLI.Tests;

[Collection("HttpListener")]
public class TestBatchOutputEvidence {
    private readonly ITestOutputHelper _output;
    public TestBatchOutputEvidence(ITestOutputHelper output) => _output = output;

    [Theory]
    [InlineData("json")]
    [InlineData("summary")]
    [InlineData("details")]
    public async Task FailedDomainDoesNotDiscardPartialOrLaterResults(string format) {
        using var partial = CreateHealth(true);
        using var complete = CreateHealth(false);
        var checks = new[] { HealthCheckType.CAA, HealthCheckType.SOA };
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => partial.Verify("partial.example", checks,
            executionOptions: new HealthCheckExecutionOptions { EnableParallelism = false }));
        var originalFrame = error.StackTrace!.Split(Environment.NewLine)[0];
        await complete.Verify("complete.example", checks);
        var runs = new[] {
            new DomainHealthCheckRun("partial.example", partial, error),
            new DomainHealthCheckRun("factory.example", null, new InvalidOperationException("Synthetic factory failure")),
            new DomainHealthCheckRun("complete.example", complete, null)
        };
        var previous = AnsiConsole.Console;
        var previousOut = Console.Out;
        using var output = new StringWriter();
        Console.SetOut(output);
        AnsiConsole.Console = AnsiConsole.Create(new AnsiConsoleSettings { Ansi = AnsiSupport.No, Out = new AnsiConsoleOutput(output) });
        AnsiConsole.Profile.Width = 200;
        try {
            var thrown = Assert.Throws<InvalidOperationException>(() => CommandUtilities.WriteBatchResults(runs, checks,
                false, false, false, false, format == "json", format == "summary", false));
            Assert.Same(error, thrown);
            var text = output.ToString();
            _output.WriteLine(text);
            Assert.Contains("partial.example", text);
            Assert.Contains("factory.example", text);
            Assert.Contains("complete.example", text);
            Assert.Contains(originalFrame, thrown.StackTrace);
            if (format == "json") {
                var documents = ParseJsonValues(text);
                try {
                    Assert.Equal(3, documents.Count);
                    Assert.False(documents[0].RootElement.GetProperty("VerificationCompleted").GetBoolean());
                    Assert.False(documents[1].RootElement.GetProperty("VerificationCompleted").GetBoolean());
                    Assert.True(documents[2].RootElement.GetProperty("VerificationCompleted").GetBoolean());
                } finally { foreach (var document in documents) { document.Dispose(); } }
            } else {
                Assert.Contains("incomplete", text, StringComparison.OrdinalIgnoreCase);
                if (format == "details") {
                    Assert.Contains("CAA for partial.example", text);
                    Assert.DoesNotContain("SerialNumber", text[..text.IndexOf("factory.example", StringComparison.Ordinal)]);
                    Assert.Contains("SOA for complete.example", text);
                }
            }
        } finally { AnsiConsole.Console = previous; Console.SetOut(previousOut); }
    }

    [Fact]
    public async Task FallbackSummaryPreservesErrorStatusInHtml() {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) => Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError });
        await health.Verify("fixture.example", new[] { HealthCheckType.SOA });
        health.SOAAnalysis.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Error, Message = "Synthetic SOA error" });
        var summary = ((string Status, string Summary))typeof(OutputFormatters)
            .GetMethod("GetCheckSummary", BindingFlags.NonPublic | BindingFlags.Static)!
            .Invoke(null, new object[] { health, HealthCheckType.SOA })!;
        Assert.Equal("❌ Failed", summary.Status);
        var folder = Path.Combine(Path.GetTempPath(), "dd-error-summary-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try {
            var path = Path.Combine(folder, "scan.html");
            OutputFormatters.ExportToHtml("fixture.example", health, path);
            var html = File.ReadAllText(path);
            _output.WriteLine(html);
            Assert.Contains("class='status error'", html);
        } finally { Directory.Delete(folder, true); }
    }

    private static DomainHealthCheck CreateHealth(bool fail) {
        var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsResponseOverride = (_, type, _) => {
            if (fail && type == DnsRecordType.SOA) { FailSoa(); }
            return Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError });
        };
        return health;
    }

    private static void FailSoa() => throw new InvalidOperationException("Synthetic SOA failure");

    private static List<JsonDocument> ParseJsonValues(string text) {
        var bytes = System.Text.Encoding.UTF8.GetBytes(text);
        var documents = new List<JsonDocument>();
        int offset = 0;
        while (offset < bytes.Length) {
            if (char.IsWhiteSpace((char)bytes[offset])) { offset++; continue; }
            var reader = new Utf8JsonReader(bytes.AsSpan(offset));
            documents.Add(JsonDocument.ParseValue(ref reader));
            offset += (int)reader.BytesConsumed;
        }
        return documents;
    }
}
