using DnsClientX;
using DomainDetective.Views;
using DomainDetective.Reports;
using DomainDetective.Reports.Html;
using DomainDetective.DesiredState;
using DomainDetective.Narratives;
using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.IO.Compression;
using System.Xml.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestCheckFailureIsolation {
    private static DomainHealthCheck Create() {
        var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, type) => Task.FromResult(type == DnsRecordType.CAA
            ? new[] { new DnsAnswer { Type = type, DataRaw = "0 issue \"letsencrypt.org\"" } }
            : Array.Empty<DnsAnswer>());
        return health;
    }

    [Theory]
    [InlineData(HealthCheckType.DMARC)]
    [InlineData(HealthCheckType.EDNSSUPPORT)]
    public async Task FailureEvidenceRetainsCheckIdentityInAssessmentReports(HealthCheckType check) {
        using var health = Create();
        health.DmarcDiscoveryMode = DmarcDiscoveryMode.LegacyPublicSuffix;
        health.DnsConfiguration.QueryDnsOverride = (_, type) => type == DnsRecordType.TXT
            ? throw new TimeoutException("DMARC query failed.")
            : Task.FromResult(new[] { new DnsAnswer { Type = DnsRecordType.CAA, DataRaw = "0 issue \"letsencrypt.org\"" } });
        health.EdnsSupportAnalysis.QueryDnsOverride = (_, _) => throw new TimeoutException("EDNS discovery failed.");
        await health.Verify("example.com", new[] { check, HealthCheckType.CAA });
        var report = DomainAssessmentBuilder.Build(Converters.ConvertChecks(health));
        var domain = Assert.Single(report.Domains);
        Assert.Equal(2, domain.Checks.Count);
        var failed = Assert.Single(domain.Checks, item => item.Check == check);
        Assert.Equal(1, failed.ErrorCount);
        Assert.Equal(Converters.AreaFor(check), failed.Area);
        Assert.Equal(1, domain.ErrorChecks);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DocumentOverviewCountsFailuresWhenSomeOrAllChecksFail(bool allFail) {
        using var health = Create();
        health.EdnsSupportAnalysis.QueryDnsOverride = (_, _) => throw new TimeoutException("EDNS discovery failed.");
        if (allFail) {
            health.DnsConfiguration.QueryDnsOverride = (_, _) => throw new TimeoutException("CAA query failed.");
        }
        await health.Verify("example.com", new[] { HealthCheckType.EDNSSUPPORT, HealthCheckType.CAA });
        var views = Converters.ConvertChecks(health).ToList();
        int expected = allFail ? 2 : 1;
        var row = Assert.Single(ExecutiveSummaryBuilder.Build(views, DomainOrder.Alphabetical));
        Assert.Equal("example.com", row.Domain);
        Assert.Equal(expected, row.Errors);
        Assert.Contains("1 domain", OverviewWording.ComposeFromItems(views));

        // Additional evidence may overlap a view's assessment; keep each finding once and preserve other findings.
        var extra = new Assessment { Severity = AssessmentSeverity.Error, Message = "Additional evidence" };
        views.Add(new AssessmentEvidenceInfo("example.com", health.Assessments.Concat(new[] { extra })));
        Assert.Equal(expected + 1, Assert.Single(ExecutiveSummaryBuilder.Build(views, DomainOrder.Alphabetical)).Errors);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedCheckPreservesOtherResultsAndReportsFailure(bool parallel) {
        using var health = Create();
        health.EdnsSupportAnalysis.QueryDnsOverride = (_, _) => throw new TimeoutException("Authoritative DNS timed out.");

        await health.Verify("example.com", new[] { HealthCheckType.EDNSSUPPORT, HealthCheckType.CAA },
            executionOptions: new HealthCheckExecutionOptions { EnableParallelism = parallel, MaxParallelism = 2 });

        var errors = new List<string>();
        var items = Converters.ConvertChecks(health, errors: errors);
        Assert.Contains(items, item => item is CaaInfo);
        Assert.DoesNotContain(items, item => item is EdnsSupportSummary);
        var failure = Assert.Single(items.OfType<CheckFailureInfo>());
        Assert.Equal(HealthCheckType.EDNSSUPPORT, failure.Check);
        Assert.Equal(Converters.AreaFor(HealthCheckType.EDNSSUPPORT), failure.Area);
        Assert.Equal("EDNSSUPPORT: TimeoutException: Authoritative DNS timed out.", Assert.Single(errors));
        Assert.Contains(health.GetAllAssessments(), assessment =>
            assessment.Severity == AssessmentSeverity.Error && assessment.Category == "EDNSSUPPORT" &&
            assessment.Target == "example.com" && assessment.Message.Contains("Authoritative DNS timed out."));
    }

    [Fact]
    public async Task LaterRunClearsExecutionFailures() {
        using var health = Create();
        health.EdnsSupportAnalysis.QueryDnsOverride = (_, _) => throw new TimeoutException("Discovery failed.");
        await health.Verify("example.com", new[] { HealthCheckType.EDNSSUPPORT });

        health.EdnsSupportAnalysis.QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>());
        await health.Verify("example.net", new[] { HealthCheckType.EDNSSUPPORT });

        var errors = new List<string>();
        Assert.IsType<EdnsSupportSummary>(Assert.Single(Converters.ConvertChecks(health, errors: errors)));
        Assert.Empty(errors);
        Assert.DoesNotContain(health.GetAllAssessments(), a => a.Code == "Verification.Check.Failed");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InternalCancellationIsReportedAsACheckFailure(bool parallel) {
        using var health = Create();
        health.EdnsSupportAnalysis.QueryDnsOverride = (_, _) => throw new OperationCanceledException("Internal probe canceled.");
        await health.Verify("example.com", new[] { HealthCheckType.EDNSSUPPORT, HealthCheckType.CAA },
            executionOptions: new HealthCheckExecutionOptions { EnableParallelism = parallel });

        var errors = new List<string>();
        Assert.Single(Converters.ConvertChecks(health, errors: errors).OfType<CaaInfo>());
        Assert.Contains("OperationCanceledException", Assert.Single(errors));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task CallerCancellationPropagatesEvenWhenCheckReturnsOrThrows(bool parallel, bool throws) {
        using var health = Create();
        using var cancellation = new CancellationTokenSource();
        health.EdnsSupportAnalysis.QueryDnsOverride = (_, _) => {
            cancellation.Cancel();
            if (throws) { throw new TimeoutException("Timeout after caller canceled."); }
            return Task.FromResult(Array.Empty<DnsAnswer>());
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => health.Verify("example.com",
            new[] { HealthCheckType.EDNSSUPPORT, HealthCheckType.CAA }, cancellationToken: cancellation.Token,
            executionOptions: new HealthCheckExecutionOptions { EnableParallelism = parallel, MaxParallelism = 1 }));
        Assert.DoesNotContain(health.GetAllAssessments(), a => a.Code == "Verification.Check.Failed");
    }

    [Fact]
    public async Task ConcurrentFailuresAreBothReported() {
        using var health = Create();
        health.DnsConfiguration.QueryDnsOverride = async (_, _) => {
            await Task.Yield();
            throw new TimeoutException("CAA failed.");
        };
        health.EdnsSupportAnalysis.QueryDnsOverride = async (_, _) => {
            await Task.Yield();
            throw new TimeoutException("NS failed.");
        };
        await health.Verify("example.com", new[] { HealthCheckType.EDNSSUPPORT, HealthCheckType.CAA },
            executionOptions: new HealthCheckExecutionOptions { EnableParallelism = true, MaxParallelism = 2 });
        var errors = new List<string>();
        Assert.Equal(2, Converters.ConvertChecks(health, errors: errors).OfType<CheckFailureInfo>().Count());
        Assert.Equal(2, errors.Count);
        Assert.Equal(2, health.GetAllAssessments().Count(a => a.Code == "Verification.Check.Failed"));
    }

    [Fact]
    public async Task HtmlReportContainsTheCheckFailureAndSuccessfulCheck() {
        using var health = Create();
        health.EdnsSupportAnalysis.QueryDnsOverride = (_, _) => throw new TimeoutException("Authoritative DNS timed out.");
        await health.Verify("example.com", new[] { HealthCheckType.EDNSSUPPORT, HealthCheckType.CAA });
        var output = Path.Combine(Path.GetTempPath(), "dd-check-failure-" + Guid.NewGuid().ToString("N") + ".html");
        try {
            var result = await new HtmlReportGenerator().GenerateAsync(health, new ReportOptions {
                Format = ReportFormat.Html,
                OutputPath = output,
                CustomProperties = new Dictionary<string, object> { ["Domain"] = "example.com" }
            });
            Assert.True(result.Success);
            Assert.Contains("EDNSSUPPORT: TimeoutException", result.ErrorMessage);
            var html = File.ReadAllText(output);
            Assert.Contains("Authoritative DNS timed out.", html);
            Assert.Contains("letsencrypt.org", html);
        } finally {
            if (File.Exists(output)) { File.Delete(output); }
        }
    }

    [Theory]
    [InlineData(ReportFormat.Word, "docx")]
    [InlineData(ReportFormat.Excel, "xlsx")]
    [InlineData(ReportFormat.Markdown, "md")]
    [InlineData(ReportFormat.MarkdownHtml, "html")]
    public async Task DocumentReportsPreserveSuccessfulChecksAndFailureEvidence(ReportFormat format, string extension) {
        using var health = Create();
        health.EdnsSupportAnalysis.QueryDnsOverride = (_, _) => throw new TimeoutException("Authoritative DNS timed out.");
        await health.Verify("example.com", new[] { HealthCheckType.EDNSSUPPORT, HealthCheckType.CAA });
        var directory = Path.Combine(Path.GetTempPath(), "dd-partial-report-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try {
            var output = Path.Combine(directory, "report." + extension);
            var result = await HealthCheckCompositionReport.GenerateAsync(health, new ReportOptions {
                Format = format, OutputPath = output, IncludeTechnicalDetails = true,
                CustomProperties = new Dictionary<string, object> { ["Domain"] = "example.com" }
            });
            Assert.True(result.Success, result.ErrorMessage);
            Assert.Contains("EDNSSUPPORT: TimeoutException", result.ErrorMessage);
            Assert.True(File.Exists(output));
            string content;
            if (extension is "docx" or "xlsx") {
                using var archive = ZipFile.OpenRead(output);
                content = string.Join(" ", archive.Entries.Where(entry => entry.FullName.EndsWith(".xml", StringComparison.Ordinal)).Select(entry => {
                    using var stream = entry.Open();
                    return XDocument.Load(stream).Root?.Value ?? string.Empty;
                }));
            } else {
                content = File.ReadAllText(output);
            }
            Assert.Contains("Authoritative DNS timed out.", content);
            Assert.Contains("letsencrypt.org", content);
        } finally {
            Directory.Delete(directory, true);
        }
    }

    [Fact]
    public async Task FailedClassificationIsNotRerunDuringReportConversion() {
        using var health = Create();
        int mxQueries = 0;
        health.DnsConfiguration.QueryDnsOverride = (_, type) => {
            if (type == DnsRecordType.MX) {
                mxQueries++;
                throw new TimeoutException("MX discovery failed.");
            }
            return Task.FromResult(new[] { new DnsAnswer { Type = DnsRecordType.CAA, DataRaw = "0 issue \"letsencrypt.org\"" } });
        };
        await health.Verify("example.com", new[] { HealthCheckType.MAILCLASSIFICATION, HealthCheckType.CAA });
        int attempted = mxQueries;
        var errors = new List<string>();
        var views = Converters.ConvertChecks(health, errors: errors);
        Assert.True(attempted > 0);
        Assert.Single(views.OfType<CaaInfo>());
        Assert.Equal(HealthCheckType.MAILCLASSIFICATION, Assert.Single(views.OfType<CheckFailureInfo>()).Check);
        Assert.StartsWith("MAILCLASSIFICATION: TimeoutException", Assert.Single(errors));
        Assert.Equal(attempted, mxQueries);
    }

    [Fact]
    public void EdnsNarrativeAndDesiredStateKeepFailedCapabilityUnknown() {
        using var health = Create();
        health.EdnsSupportAnalysis.ServerSupport["ns.example.com (192.0.2.1)"] = new EdnsSupportInfo {
            QuerySucceeded = false, Error = "TimeoutException: The UDP query timed out."
        };
        var narrative = EdnsNarrative.Build(health.EdnsSupportAnalysis);
        Assert.Contains(narrative.Details, line => line.Contains("support is unknown") && line.Contains("TimeoutException"));
        Assert.DoesNotContain(narrative.Details, line => line.Contains("no EDNS support"));
        var desired = DesiredStateEvaluator.Evaluate("example.com", health, new DesiredStateProfile {
            EdnsSupport = new DesiredStateEdnsSupportPolicy { RequireAllServersSupported = true }
        });
        Assert.False(desired.Conforms);
        Assert.Contains(desired.Assessments, a => a.Code == DesiredStateCodes.EdnsQueryFailed);
        Assert.DoesNotContain(desired.Assessments, a => a.Code == DesiredStateCodes.EdnsNotSupported);
    }

    private static Task<DnsAnswer[]> ServerDiscovery(DnsRecordType type, params string[] servers) => Task.FromResult(type switch {
        DnsRecordType.NS => new[] { new DnsAnswer { Type = type, DataRaw = "ns.example.com" } },
        DnsRecordType.A => servers.Select(server => new DnsAnswer { Type = type, DataRaw = server }).ToArray(),
        _ => Array.Empty<DnsAnswer>()
    });

    [Fact]
    public async Task ServerTimeoutPreservesOtherServersAndIsNotUnsupportedEdns() {
        var analysis = new EdnsSupportAnalysis {
            QueryDnsOverride = (_, type) => ServerDiscovery(type, "192.0.2.1", "192.0.2.2"),
            QueryServerOverride = server => server == "192.0.2.1"
                ? throw new TimeoutException("The UDP query timed out.")
                : Task.FromResult(new EdnsSupportInfo { Supported = true, UdpPayloadSize = 1232 })
        };
        await analysis.Analyze("example.com", new InternalLogger());
        var summary = Converters.Convert(analysis);
        Assert.Equal(2, summary.TotalChecked);
        Assert.Equal(1, summary.SupportedCount);
        Assert.Equal(1, summary.FailedCount);
        Assert.Equal(0, summary.NotSupportedCount);
        Assert.Equal(1, summary.ErrorCount);
        Assert.Contains(summary.Servers, server => !server.QuerySucceeded && server.Error!.Contains("TimeoutException"));
        Assert.DoesNotContain(analysis.Assessments, a => a.Code == "EDNS.Server.NotSupported");

        analysis.QueryServerOverride = _ => Task.FromResult(new EdnsSupportInfo { Supported = true });
        await analysis.Analyze("example.com", new InternalLogger());
        Assert.Equal(0, Converters.Convert(analysis).FailedCount);
        Assert.DoesNotContain(analysis.Assessments, a => a.Code == "EDNS.Server.QueryFailed");
    }

    [Fact]
    public async Task ActualUdpTimeoutReturnsAServerFailureAndOtherCheckResults() {
        using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var endpoint = $"127.0.0.1:{((IPEndPoint)server.Client.LocalEndPoint!).Port}";
        using var health = Create();
        health.EdnsSupportAnalysis.QueryDnsOverride = (_, type) => ServerDiscovery(type, endpoint);

        await health.Verify("example.com", new[] { HealthCheckType.EDNSSUPPORT, HealthCheckType.CAA });

        var errors = new List<string>();
        var views = Converters.ConvertChecks(health, errors: errors);
        Assert.Contains(views, item => item is CaaInfo);
        var edns = Assert.Single(views.OfType<EdnsSupportSummary>());
        Assert.Equal(1, edns.FailedCount);
        Assert.Contains("TimeoutException", Assert.Single(edns.Servers).Error);
        Assert.Equal(1, edns.ErrorCount);
        Assert.Empty(errors); // The analysis completed with a recorded server failure.
    }

    [Fact]
    public async Task CallerCancellationReachesAnActiveUdpProbe() {
        using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var endpoint = $"127.0.0.1:{((IPEndPoint)server.Client.LocalEndPoint!).Port}";
        using var health = Create();
        using var cancellation = new CancellationTokenSource();
        health.EdnsSupportAnalysis.QueryDnsOverride = (_, type) => ServerDiscovery(type, endpoint);
        var verification = health.Verify("example.com", new[] { HealthCheckType.EDNSSUPPORT }, cancellationToken: cancellation.Token);
        var received = server.ReceiveAsync();
        try {
            Assert.Same(received, await Task.WhenAny(received, Task.Delay(TimeSpan.FromSeconds(5))));
            await received;
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => verification);
            Assert.Empty(health.EdnsSupportAnalysis.ServerSupport);
            Assert.DoesNotContain(health.GetAllAssessments(), a => a.Severity == AssessmentSeverity.Error);
        } finally {
            cancellation.Cancel();
            server.Close();
            try { await received; } catch (SocketException) { } catch (ObjectDisposedException) { }
            try { await verification; } catch (OperationCanceledException) { }
        }
    }
}
