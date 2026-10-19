using DnsClientX;
using DomainDetective.Reports;
using DomainDetective.Views;

namespace DomainDetective.Tests;

public class TestFailureAdmissionAndRetry {
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task QueuedSelectedChecksDoNotBecomeCanceledResults(int capacity) {
        using var health = new DomainHealthCheck();
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var started = 0;
        health.DnsConfiguration.QueryDnsOverride = async (_, _) => {
            if (Interlocked.Increment(ref started) == capacity) { entered.TrySetResult(true); }
            await Task.Delay(Timeout.Infinite, cancellation.Token);
            return Array.Empty<DnsAnswer>();
        };
        var run = health.Verify("example.test", new[] { HealthCheckType.CAA, HealthCheckType.SOA, HealthCheckType.SPF, HealthCheckType.DMARC },
            cancellationToken: cancellation.Token,
            executionOptions: new HealthCheckExecutionOptions { EnableParallelism = true, MaxParallelism = capacity });
        Assert.Same(entered.Task, await Task.WhenAny(entered.Task, Task.Delay(TimeSpan.FromSeconds(10))));
        cancellation.Cancel();
        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
        Assert.Equal(cancellation.Token, exception.CancellationToken);
        Assert.Equal(capacity, health.LastVerifiedChecks.Count);
        Assert.Equal(capacity, started);
        Assert.Equal(capacity, Converters.ConvertChecks(health).OfType<CheckFailureInfo>().Count());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SuccessfulDirectCaaRetryReplacesOnlyItsPriorFailure(bool useRawRecord) {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, _) => throw new TimeoutException("Original lookup failed.");
        await Assert.ThrowsAsync<TimeoutException>(() => health.Verify("example.test", new[] { HealthCheckType.CAA }));
        await Assert.ThrowsAsync<TimeoutException>(() => health.VerifyCAA("example.test"));
        Assert.IsType<CheckFailureInfo>(Assert.Single(Converters.ConvertChecks(health)));
        health.DnsConfiguration.QueryDnsOverride = (_, type) => Task.FromResult(new[] {
            new DnsAnswer { Type = type, DataRaw = "0 issue \"current-ca.example.test\"" }
        });
        if (useRawRecord) { await health.CheckCAA("0 issue \"current-ca.example.test\""); }
        else { await health.VerifyCAA("example.test"); }
        var view = Assert.IsType<CaaInfo>(Assert.Single(Converters.ConvertChecks(health)));
        Assert.Contains("current-ca.example.test", view.CanIssueCertificatesForDomain);
        Assert.DoesNotContain(health.Assessments, value => value.Code == "Verification.Check.Failed");
        Assert.Contains(HealthCheckType.CAA, health.VerificationCompletedChecks);
        Assert.DoesNotContain(HealthCheckReportItems.BuildItems(health, "example.test", null, false, new()), value => value is CheckFailureInfo);
    }

    [Theory]
    [InlineData(HealthCheckType.CAA)]
    [InlineData(HealthCheckType.SPF)]
    [InlineData(HealthCheckType.SOA)]
    [InlineData(HealthCheckType.DMARC)]
    public async Task DirectResultCompletionRetainsIndependentFailures(HealthCheckType check) {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, _) => throw new TimeoutException("Current DNS unavailable.");
        await Assert.ThrowsAsync<TimeoutException>(() => health.Verify("example.test", new[] { HealthCheckType.CAA, HealthCheckType.MX },
            executionOptions: new HealthCheckExecutionOptions { EnableParallelism = false }));
        Assert.Equal(2, Converters.ConvertChecks(health).OfType<CheckFailureInfo>().Count());
        health.DnsConfiguration.QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>());
        switch (check) {
            case HealthCheckType.CAA: await health.VerifyCAA("example.test"); break;
            case HealthCheckType.SPF: await health.VerifySPF("example.test"); break;
            case HealthCheckType.SOA: await health.CheckSOA("ns.example.test hostmaster.example.test 1 3600 600 86400 300"); break;
            case HealthCheckType.DMARC: await health.CheckDMARC("v=DMARC1; p=none"); break;
        }
        Assert.Equal(HealthCheckType.MX, Assert.Single(Converters.ConvertChecks(health, new[] { check, HealthCheckType.MX }).OfType<CheckFailureInfo>()).Check);
        Assert.Contains(check, health.VerificationCompletedChecks);
        Assert.Equal(check == HealthCheckType.CAA ? 1 : 2, health.Assessments.Count(value => value.Code == "Verification.Check.Failed"));
    }

    [Fact]
    public async Task CanceledDirectRetryPreservesFailureAndCallerToken() {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, _) => throw new TimeoutException("Original CAA unavailable.");
        await Assert.ThrowsAsync<TimeoutException>(() => health.Verify("example.test", new[] { HealthCheckType.CAA }));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        health.DnsConfiguration.QueryDnsOverride = (_, _) => Task.FromCanceled<DnsAnswer[]>(cancellation.Token);
        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => health.VerifyCAA("example.test", cancellation.Token));
        Assert.Equal(cancellation.Token, error.CancellationToken);
        Assert.Contains("Original CAA unavailable", Assert.Single(Assert.IsType<CheckFailureInfo>(Assert.Single(Converters.ConvertChecks(health))).Assessments).Message);
    }

    [Fact]
    public async Task OlderDirectRetryCannotEraseANewerRunFailure() {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, _) => throw new TimeoutException("First run failed.");
        await Assert.ThrowsAsync<TimeoutException>(() => health.Verify("example.test", new[] { HealthCheckType.CAA }));
        var pending = new TaskCompletionSource<DnsAnswer[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        health.DnsConfiguration.QueryDnsOverride = (_, _) => { entered.TrySetResult(true); return pending.Task; };
        var direct = health.VerifyCAA("example.test");
        try {
            Assert.Same(entered.Task, await Task.WhenAny(entered.Task, Task.Delay(TimeSpan.FromSeconds(10))));
            health.DnsConfiguration.QueryDnsOverride = (_, _) => throw new TimeoutException("Newer run failed.");
            await Assert.ThrowsAsync<TimeoutException>(() => health.Verify("example.test", new[] { HealthCheckType.CAA }));
        } finally {
            pending.TrySetResult(new[] { new DnsAnswer { Type = DnsRecordType.CAA, DataRaw = "0 issue \"old-retry.example.test\"" } });
            await direct;
        }
        var failure = Assert.IsType<CheckFailureInfo>(Assert.Single(Converters.ConvertChecks(health)));
        Assert.Contains("Newer run failed", Assert.Single(failure.Assessments).Message);
    }

    [Fact]
    public async Task DirectMailRetryDoesNotReuseAFailedMxPrerequisite() {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, _) => throw new TimeoutException("MX unavailable.");
        await Assert.ThrowsAsync<TimeoutException>(() => health.Verify("example.test", new[] { HealthCheckType.SMTPTLS }));
        var queries = 0;
        health.DnsConfiguration.QueryDnsOverride = (_, _) => { Interlocked.Increment(ref queries); return Task.FromResult(Array.Empty<DnsAnswer>()); };
        await health.VerifySMTPTLS("example.test");
        Assert.True(queries > 0);
        Assert.IsType<MailTlsInfo>(Assert.Single(Converters.ConvertChecks(health)));
        Assert.DoesNotContain(health.Assessments, value => value.Code == "Verification.Check.Failed");
    }

    [Fact]
    public void CleanWebsiteProjectionRetainsItsDomainAndHttpTechnicalEvidence() {
        var certificate = new CertificateInfo { Subject = "example.test" };
        var http = new HttpInfo { Subject = "example.test", Url = "https://example.test", HstsPresent = true };
        var website = Converters.CombineWebsite(certificate, http);
        var bucket = Assert.Single(CompositionBuilder.GroupBySubject(new object[] { website }));
        Assert.Equal("example.test", bucket.Key);
        Assert.Same(http, bucket.Value.Http);
    }

    [Theory]
    [InlineData(ReportFormat.Html, ".html")]
    [InlineData(ReportFormat.Word, ".docx")]
    public void WebsiteOnlyExportRetainsDomainAndHttpSection(ReportFormat format, string extension) {
        var http = new HttpInfo { Subject = "example.test", Url = "https://example.test/website-proof", HstsPresent = true };
        var items = new object[] { Converters.CombineWebsite(new CertificateInfo { Subject = "example.test" }, http) };
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + extension);
        try {
            if (format == ReportFormat.Html) {
                DomainDetective.Reports.Html.HtmlCompositionReport.Generate(path, items, ReportScope.Detailed);
            } else {
                DomainDetective.Reports.Office.WordCompositionReport.Generate(path, items, ReportScope.Detailed, showInfoFindings: false);
            }
            string content;
            if (format == ReportFormat.Html) { content = File.ReadAllText(path); }
            else {
                using var zip = System.IO.Compression.ZipFile.OpenRead(path);
                using var reader = new StreamReader(zip.GetEntry("word/document.xml")!.Open());
                content = reader.ReadToEnd();
            }
            Assert.Contains("example.test", content);
            Assert.Contains("website-proof", content);
        } finally { if (File.Exists(path)) { File.Delete(path); } }
    }
}
