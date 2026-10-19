using DnsClientX;
using DomainDetective.Reports;
using DomainDetective.Views;

namespace DomainDetective.Tests;

public class TestReportExecutionEvidence {
    [Theory]
    [InlineData(ReportFormat.Html, ".html")]
    [InlineData(ReportFormat.Markdown, ".md")]
    [InlineData(ReportFormat.Word, ".docx")]
    [InlineData(ReportFormat.Excel, ".xlsx")]
    public async Task DocumentExportWritesFailureEvidenceInsteadOfStaleCaa(ReportFormat format, string extension) {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, _) => Task.FromResult(new[] {
            new DnsAnswer { Type = DnsRecordType.CAA, DataRaw = "0 issue \"previous-ca.example.test\"" }
        });
        await health.Verify("example.test", new[] { HealthCheckType.CAA });
        health.DnsConfiguration.QueryDnsOverride = (_, _) => throw new TimeoutException("Current CAA lookup failed.");
        await Assert.ThrowsAsync<TimeoutException>(() => health.Verify("example.test", new[] { HealthCheckType.CAA }));
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + extension);
        try {
            var options = new ReportOptions { Format = format, OutputPath = path };
            options.CustomProperties["Domain"] = "example.test";
            var result = format == ReportFormat.Html
                ? await new DomainDetective.Reports.Html.HtmlReportGenerator().GenerateAsync(health, options)
                : await HealthCheckCompositionReport.GenerateAsync(health, options);
            Assert.True(result.Success, result.ErrorMessage);
            Assert.Contains("Current CAA lookup failed.", result.ErrorMessage);
            Assert.True(File.Exists(path));
            var text = string.Empty;
            if (format is ReportFormat.Html or ReportFormat.Markdown) { text = File.ReadAllText(path); }
            else {
                using var zip = System.IO.Compression.ZipFile.OpenRead(path);
                foreach (var entry in zip.Entries.Where(entry => entry.FullName.EndsWith(".xml", StringComparison.Ordinal))) {
                    using var reader = new StreamReader(entry.Open());
                    text += reader.ReadToEnd();
                }
            }
            Assert.Contains("Current CAA lookup failed.", text);
            Assert.DoesNotContain("previous-ca.example.test", text);
            Assert.DoesNotContain("CAA.Record.Present", text);
        } finally { if (File.Exists(path)) { File.Delete(path); } }
    }

    [Fact]
    public async Task CompositionRetainsFailureInsteadOfPreviousCaaEvidence() {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, _) => Task.FromResult(new[] {
            new DnsAnswer { Type = DnsRecordType.CAA, DataRaw = "0 issue \"ca.example.test\"" }
        });
        await health.Verify("example.test", new[] { HealthCheckType.CAA });
        Assert.IsType<CaaInfo>(Assert.Single(HealthCheckReportItems.BuildItems(health, "example.test", null, false, new())));
        health.DnsConfiguration.QueryDnsOverride = (_, _) => throw new TimeoutException("Current CAA lookup failed.");
        await Assert.ThrowsAsync<TimeoutException>(() => health.Verify("example.test", new[] { HealthCheckType.CAA }));
        var errors = new List<string>();
        var items = HealthCheckReportItems.BuildItems(health, "example.test", null, false, errors);
        Assert.DoesNotContain(items, item => item is CaaInfo);
        Assert.Equal(HealthCheckType.CAA, Assert.IsType<CheckFailureInfo>(Assert.Single(items)).Check);
        Assert.Single(errors);
        Assert.False(health.VerificationCompleted);
    }

    [Fact]
    public async Task CompositionRetainsOtherCompletedChecksBesideFailure() {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, type) => type == DnsRecordType.CAA
            ? throw new TimeoutException("Current CAA lookup failed.") : Task.FromResult(Array.Empty<DnsAnswer>());
        await Assert.ThrowsAsync<TimeoutException>(() => health.Verify("example.test", new[] { HealthCheckType.CAA, HealthCheckType.SPF },
            executionOptions: new HealthCheckExecutionOptions { EnableParallelism = false }));
        var items = HealthCheckReportItems.BuildItems(health, "example.test", null, false, new());
        Assert.Contains(items, item => item is SpfRecordInfo);
        Assert.Single(items.OfType<CheckFailureInfo>());
        Assert.DoesNotContain(items, item => item is CaaInfo);
        Assert.Contains(HealthCheckType.SPF, health.VerificationCompletedChecks);
        Assert.DoesNotContain(HealthCheckType.CAA, health.VerificationCompletedChecks);
    }
}
