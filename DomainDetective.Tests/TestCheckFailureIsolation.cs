using DnsClientX;
using DomainDetective.Views;
using DomainDetective.DesiredState;
using DomainDetective.Narratives;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestCheckFailureIsolation {
    [Fact]
    public void SharedNameServerAnalysisPreservesEachSelectedCheckIdentity() {
        using var health = Create();
        var delegation = Assert.IsType<NsInfo>(Assert.Single(Converters.ConvertChecks(health, new[] { HealthCheckType.DELEGATION })));
        Assert.Equal(HealthCheckType.DELEGATION, delegation.Check);
        var views = Converters.ConvertChecks(health, new[] { HealthCheckType.NS, HealthCheckType.DELEGATION }).Cast<NsInfo>().ToArray();
        Assert.Equal(new[] { HealthCheckType.NS, HealthCheckType.DELEGATION }, views.Select(view => view.Check));
        Assert.NotSame(views[0], views[1]);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CanceledProbeDoesNotPublishEarlierAddressDiscoveryFailures(bool withLogger) {
        using var canceled = new CancellationTokenSource();
        var analysis = new EdnsSupportAnalysis {
            QueryDnsOverride = (_, type) => type switch {
                DnsRecordType.NS => Task.FromResult(new[] { new DnsAnswer { Type = type, DataRaw = "ns.example.test" } }),
                DnsRecordType.A => Task.FromResult(new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" } }),
                _ => throw new TimeoutException("AAAA discovery failed.")
            },
            QueryServerOverride = _ => { canceled.Cancel(); return Task.FromResult(new EdnsSupportInfo { Supported = true }); }
        };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => analysis.Analyze("example.test", withLogger ? new InternalLogger() : null, canceled.Token));
        Assert.Empty(analysis.ServerSupport);
        Assert.Empty(analysis.Assessments);
    }

    [Fact]
    public async Task DiscoveryUsesTheConfiguredBudgetWithoutRequiringALogger() {
        var started = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var analysis = new EdnsSupportAnalysis { DiscoveryTimeout = TimeSpan.FromMilliseconds(20),
            QueryDnsOverride = async (_, _) => { started.TrySetResult(true); await Task.Delay(100); return Array.Empty<DnsAnswer>(); } };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => analysis.Analyze("example.test", null));
        Assert.True(started.Task.IsCompleted);
        analysis.DiscoveryTimeout = TimeSpan.FromSeconds(1);
        await analysis.Analyze("example.test", null);
        Assert.Empty(analysis.ServerSupport);
    }

    [Fact]
    public async Task EdnsBatchesAllNameServersUnderOneConcurrencyCap() {
        int active = 0, peak = 0;
        var admitted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var analysis = new EdnsSupportAnalysis {
            QueryDnsOverride = (name, type) => Task.FromResult(type switch {
                DnsRecordType.NS => new[] { new DnsAnswer { Type = type, DataRaw = "one.example.test" }, new DnsAnswer { Type = type, DataRaw = "two.example.test" } },
                DnsRecordType.A => Enumerable.Range(name.StartsWith("one", StringComparison.Ordinal) ? 1 : 9, 8)
                    .Select(i => new DnsAnswer { Type = type, DataRaw = $"192.0.2.{i}" }).ToArray(),
                _ => Array.Empty<DnsAnswer>()
            }),
            QueryServerOverride = async _ => {
                int count = Interlocked.Increment(ref active);
                int old;
                do { old = Volatile.Read(ref peak); } while (count > old && Interlocked.CompareExchange(ref peak, count, old) != old);
                if (count == 8) { admitted.TrySetResult(true); }
                try { await release.Task; }
                finally { Interlocked.Decrement(ref active); }
                return new EdnsSupportInfo { Supported = true };
            }
        };
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var run = analysis.Analyze("example.test", new InternalLogger(), guard.Token);
        try { await admitted.Task.WaitWithCancellation(guard.Token); Assert.Equal(8, Volatile.Read(ref active)); }
        finally { release.TrySetResult(true); }
        await run;
        Assert.Equal(8, peak);
        Assert.Equal(16, analysis.ServerSupport.Count);
    }
    [Fact]
    public async Task DisabledPolicyDoesNotRequireAFailedCheck() {
        using var health = Create();
        health.DnsConfiguration.QueryDnsOverride = (_, _) => throw new InvalidOperationException("Query failed.");
        await health.Verify("example.test", new[] { HealthCheckType.CAA });
        var result = DesiredStateEvaluator.Evaluate("example.test", health, new DesiredStateProfile {
            Caa = new DesiredStateCaaPolicy { Enabled = false }
        });
        Assert.True(result.Conforms);
        Assert.DoesNotContain(result.Assessments, a => a.Code == "DesiredState.Check.QueryFailed");
    }

    [Fact]
    public async Task CallerCancellationFollowedByServerTimeoutDoesNotPublishAnEdnsFailure() {
        using var cancellation = new CancellationTokenSource();
        var analysis = new EdnsSupportAnalysis {
            QueryDnsOverride = (_, type) => ServerDiscovery(type, "192.0.2.1"),
            QueryServerOverride = _ => { cancellation.Cancel(); throw new TimeoutException("Timeout after cancellation."); }
        };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => analysis.Analyze("example.test", new InternalLogger(), cancellation.Token));
        Assert.Empty(analysis.ServerSupport);
        Assert.DoesNotContain(analysis.Assessments, a => a.Code == EdnsCodes.QueryFailed);
    }
    [Fact]
    public async Task FilteredSnapshotsRetainFailedChecksAfterTheOriginalRunsAgain() {
        using var health = Create();
        health.EdnsSupportAnalysis.QueryDnsOverride = (_, _) => throw new TimeoutException("Discovery failed.");
        await health.Verify("example.test", new[] { HealthCheckType.EDNSSUPPORT, HealthCheckType.CAA });
        var snapshot = health.FilterAnalyses(new[] { HealthCheckType.EDNSSUPPORT });
        health.EdnsSupportAnalysis.QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>());
        await health.Verify("other.test", new[] { HealthCheckType.EDNSSUPPORT });
        var failure = Assert.IsType<CheckFailureInfo>(Assert.Single(Converters.ConvertChecks(snapshot)));
        Assert.Equal(HealthCheckType.EDNSSUPPORT, failure.Check);
        Assert.Equal("example.test", failure.Subject);
        Assert.Contains(snapshot.GetAllAssessments(), a => a.Code == "Verification.Check.Failed");
    }

    [Fact]
    public async Task FailedRepeatCheckCannotConformUsingPreviousCaaResults() {
        using var health = Create();
        await health.Verify("example.test", new[] { HealthCheckType.CAA });
        var profile = new DesiredStateProfile { Caa = new DesiredStateCaaPolicy { RequireRecord = true } };
        Assert.True(DesiredStateEvaluator.Evaluate("example.test", health, profile).Conforms);
        health.DnsConfiguration.QueryDnsOverride = (_, _) => throw new InvalidOperationException("Current lookup failed.");
        await health.Verify("example.test", new[] { HealthCheckType.CAA });
        var result = DesiredStateEvaluator.Evaluate("example.test", health, profile);
        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a => a.Code == "DesiredState.Check.QueryFailed");
    }

    [Fact]
    public async Task MissingConverterRetainsCheckIdentityWithoutAnOptionalErrorSink() {
        using var health = Create();
        await health.Verify("example.test", new[] { HealthCheckType.CAA });
        var failure = Assert.IsType<CheckFailureInfo>(Assert.Single(Converters.ConvertChecks(health, new[] { HealthCheckType.ROBOTS })));
        Assert.Equal(HealthCheckType.ROBOTS, failure.Check);
        Assert.Equal("example.test", failure.Subject);
        Assert.Equal("Verification.Conversion.Failed", Assert.Single(failure.Assessments).Code);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DaneFailureDoesNotAbortOrBecomeSmtpTlsFailure(bool parallel) {
        using var health = Create();
        health.DaneDnsOverride = (_, _) => throw new InvalidOperationException("DANE only failed.");
        await health.Verify("example.test", new[] { HealthCheckType.SMTPTLS, HealthCheckType.DANE },
            executionOptions: new HealthCheckExecutionOptions { EnableParallelism = parallel });
        Assert.Equal(HealthCheckType.DANE, Assert.Single(Converters.ConvertChecks(health).OfType<CheckFailureInfo>()).Check);
        Assert.Single(Converters.ConvertChecks(health).OfType<MailTlsInfo>());
    }
    private static DomainHealthCheck Create() {
        var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, type) => Task.FromResult(type == DnsRecordType.CAA
            ? new[] { new DnsAnswer { Type = type, DataRaw = "0 issue \"letsencrypt.org\"" } }
            : Array.Empty<DnsAnswer>());
        return health;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedCheckPreservesOtherResultsAndReportsFailure(bool parallel) {
        using var health = Create();
        health.EdnsSupportAnalysis.QueryDnsOverride = (_, _) => throw new TimeoutException("Authoritative DNS timed out.");

        await health.Verify("example.test", new[] { HealthCheckType.EDNSSUPPORT, HealthCheckType.CAA },
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
            assessment.Target == "example.test" && assessment.Message.Contains("Authoritative DNS timed out."));
    }

    [Fact]
    public async Task LaterRunClearsExecutionFailures() {
        using var health = Create();
        health.EdnsSupportAnalysis.QueryDnsOverride = (_, _) => throw new TimeoutException("Discovery failed.");
        await health.Verify("example.test", new[] { HealthCheckType.EDNSSUPPORT });

        health.EdnsSupportAnalysis.QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>());
        await health.Verify("other.test", new[] { HealthCheckType.EDNSSUPPORT });

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
        await health.Verify("example.test", new[] { HealthCheckType.EDNSSUPPORT, HealthCheckType.CAA },
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

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => health.Verify("example.test",
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
        await health.Verify("example.test", new[] { HealthCheckType.EDNSSUPPORT, HealthCheckType.CAA },
            executionOptions: new HealthCheckExecutionOptions { EnableParallelism = true, MaxParallelism = 2 });
        var errors = new List<string>();
        Assert.Equal(2, Converters.ConvertChecks(health, errors: errors).OfType<CheckFailureInfo>().Count());
        Assert.Equal(2, errors.Count);
        Assert.Equal(2, health.GetAllAssessments().Count(a => a.Code == "Verification.Check.Failed"));
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
        await health.Verify("example.test", new[] { HealthCheckType.MAILCLASSIFICATION, HealthCheckType.CAA });
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
        health.EdnsSupportAnalysis.ServerSupport["ns.example.test (192.0.2.1)"] = new EdnsSupportInfo {
            QuerySucceeded = false, Error = "TimeoutException: The UDP query timed out."
        };
        var narrative = EdnsNarrative.Build(health.EdnsSupportAnalysis);
        Assert.Contains(narrative.Details, line => line.Contains("support is unknown") && line.Contains("TimeoutException"));
        Assert.DoesNotContain(narrative.Details, line => line.Contains("no EDNS support"));
        var desired = DesiredStateEvaluator.Evaluate("example.test", health, new DesiredStateProfile {
            EdnsSupport = new DesiredStateEdnsSupportPolicy { RequireAllServersSupported = true }
        });
        Assert.False(desired.Conforms);
        Assert.Contains(desired.Assessments, a => a.Code == DesiredStateCodes.EdnsQueryFailed);
        Assert.DoesNotContain(desired.Assessments, a => a.Code == DesiredStateCodes.EdnsNotSupported);
    }

    private static Task<DnsAnswer[]> ServerDiscovery(DnsRecordType type, params string[] servers) => Task.FromResult(type switch {
        DnsRecordType.NS => new[] { new DnsAnswer { Type = type, DataRaw = "ns.example.test" } },
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
        await analysis.Analyze("example.test", new InternalLogger());
        var summary = Converters.Convert(analysis);
        Assert.Equal(2, summary.TotalChecked);
        Assert.Equal(1, summary.SupportedCount);
        Assert.Equal(1, summary.FailedCount);
        Assert.Equal(0, summary.NotSupportedCount);
        Assert.Equal(1, summary.ErrorCount);
        Assert.Contains(summary.Servers, server => !server.QuerySucceeded && server.Error!.Contains("TimeoutException"));
        Assert.DoesNotContain(analysis.Assessments, a => a.Code == "EDNS.Server.NotSupported");

        analysis.QueryServerOverride = _ => Task.FromResult(new EdnsSupportInfo { Supported = true });
        await analysis.Analyze("example.test", new InternalLogger());
        Assert.Equal(0, Converters.Convert(analysis).FailedCount);
        Assert.DoesNotContain(analysis.Assessments, a => a.Code == "EDNS.Server.QueryFailed");
    }

    [Fact]
    public async Task ActualUdpTimeoutReturnsAServerFailureAndOtherCheckResults() {
        using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var endpoint = $"127.0.0.1:{((IPEndPoint)server.Client.LocalEndPoint!).Port}";
        using var health = Create();
        health.EdnsSupportAnalysis.QueryDnsOverride = (_, type) => ServerDiscovery(type, endpoint);

        await health.Verify("example.test", new[] { HealthCheckType.EDNSSUPPORT, HealthCheckType.CAA });

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
        var verification = health.Verify("example.test", new[] { HealthCheckType.EDNSSUPPORT }, cancellationToken: cancellation.Token);
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
