using DnsClientX;
using DomainDetective.Views;
using DomainDetective.DesiredState;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestVerificationRunState {
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task EdnsDiscoveryRetainsResolverFailureEnvelopes(bool nameServersFail) {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsResponseOverride = (_, type, _) => Task.FromResult(new DnsResponse {
            Status = type == (nameServersFail ? DnsRecordType.NS : DnsRecordType.AAAA) ? DnsResponseCode.ServerFailure : DnsResponseCode.NoError,
            Answers = type == DnsRecordType.NS ? new[] { new DnsAnswer { Type = type, DataRaw = "ns.example.test" } } : Array.Empty<DnsAnswer>()
        });
        var verification = health.Verify("example.test", new[] { HealthCheckType.EDNSSUPPORT });
        if (nameServersFail) { await Assert.ThrowsAsync<InvalidOperationException>(() => verification); }
        else { await verification; }
        var view = Assert.Single(Converters.ConvertChecks(health));
        if (nameServersFail) {
            Assert.Contains("ServerFailure", Assert.Single(Assert.IsType<CheckFailureInfo>(view).Assessments).Message);
        } else {
            var summary = Assert.IsType<EdnsSupportSummary>(view);
            Assert.Equal(1, summary.FailedCount);
            Assert.Contains("ServerFailure", Assert.Single(summary.Servers).Error);
            Assert.Equal("Error", summary.Status);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RejectedInputPreservesTheLastCompletedFailure(bool invalidSelection) {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, _) => throw new TimeoutException("CAA unavailable.");
        await Assert.ThrowsAsync<TimeoutException>(() => health.Verify("example.test", new[] { HealthCheckType.CAA }));
        if (invalidSelection) {
            await Assert.ThrowsAsync<NotSupportedException>(() => health.Verify("other.test", new[] { (HealthCheckType)int.MaxValue }));
        } else {
            await Assert.ThrowsAnyAsync<ArgumentException>(() => health.Verify("bad host.test", new[] { HealthCheckType.CAA }));
        }
        var view = Assert.IsType<CheckFailureInfo>(Assert.Single(Converters.ConvertChecks(health)));
        Assert.Equal("example.test", view.Subject);
        Assert.Equal(HealthCheckType.CAA, view.Check);
        Assert.Contains("CAA unavailable", Assert.Single(view.Assessments).Message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CancellationDoesNotExposeUnstartedChecks(bool preCanceled) {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>());
        await health.Verify("previous.test", new[] { HealthCheckType.CAA });
        using var canceled = new CancellationTokenSource();
        if (preCanceled) { canceled.Cancel(); }
        health.EdnsSupportAnalysis.QueryDnsOverride = (_, _) => { canceled.Cancel(); throw new OperationCanceledException(canceled.Token); };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => health.Verify("current.test",
            new[] { HealthCheckType.EDNSSUPPORT, HealthCheckType.CAA }, cancellationToken: canceled.Token,
            executionOptions: new HealthCheckExecutionOptions { EnableParallelism = false }));
        if (preCanceled) {
            // A canceled waiter never replaces the latest admitted run.
            Assert.Equal(HealthCheckType.CAA, Assert.Single(health.LastVerifiedChecks));
            Assert.IsType<CaaInfo>(Assert.Single(Converters.ConvertChecks(health)));
            Assert.True(health.VerificationCompleted);
            Assert.Equal("previous.test", health.VerificationDomain);
            return;
        }
        Assert.DoesNotContain(HealthCheckType.CAA, health.LastVerifiedChecks);
        Assert.DoesNotContain(Converters.ConvertChecks(health), view => view is CaaInfo);
        Assert.Equal(preCanceled ? 0 : 1, health.LastVerifiedChecks.Count);
        var explicitViews = Converters.ConvertChecks(health, new[] { HealthCheckType.EDNSSUPPORT, HealthCheckType.CAA });
        Assert.All(explicitViews, view => Assert.Equal("Incomplete", Assert.IsType<CheckFailureInfo>(view).Status));
        using var unstarted = health.FilterAnalyses(new[] { HealthCheckType.CAA });
        var unstartedView = Assert.IsType<CheckFailureInfo>(Assert.Single(Converters.ConvertChecks(unstarted, new[] { HealthCheckType.CAA })));
        Assert.Equal("Verification.Check.NotRun", Assert.Single(unstartedView.Assessments).Code);
        var profile = new DesiredStateProfile { Caa = new DesiredStateCaaPolicy { Enabled = true } };
        Assert.False(DesiredStateEvaluator.Evaluate("current.test", health, profile).Conforms);
        Assert.False(DesiredStateEvaluator.Evaluate("current.test", unstarted, profile).Conforms);
        var errors = new System.Collections.Generic.List<string>();
        var views = Converters.ConvertChecks(health, errors: errors);
        Assert.Empty(errors);
        if (preCanceled) { Assert.Empty(views); }
        else {
            var incomplete = Assert.IsType<CheckFailureInfo>(Assert.Single(views));
            Assert.Equal("Incomplete", incomplete.Status);
            Assert.Equal("current.test", incomplete.Subject);
            Assert.Equal(0, incomplete.ErrorCount);
            Assert.Equal(1, incomplete.WarningCount);
            Assert.Equal("Verification.Check.Canceled", Assert.Single(incomplete.Assessments).Code);
            using var filtered = health.FilterAnalyses(new[] { HealthCheckType.EDNSSUPPORT });
            Assert.Equal("Incomplete", Assert.IsType<CheckFailureInfo>(Assert.Single(Converters.ConvertChecks(filtered))).Status);
        }
    }

    [Fact]
    public async Task PrestartedDaneFailureSurvivesCancellationBeforeItsGatedWrapper() {
        using var health = new DomainHealthCheck();
        using var caller = new CancellationTokenSource();
        health.DnsConfiguration.QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>());
        health.DaneDnsOverride = (_, _) => throw new InvalidOperationException("DANE failed before cancellation.");
        health.EdnsSupportAnalysis.QueryDnsOverride = (_, _) => { caller.Cancel(); throw new OperationCanceledException(caller.Token); };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => health.Verify("example.test",
            new[] { HealthCheckType.EDNSSUPPORT, HealthCheckType.DANE, HealthCheckType.MTASTS },
            daneServiceType: new[] { ServiceType.HTTPS }, cancellationToken: caller.Token,
            executionOptions: new HealthCheckExecutionOptions { EnableParallelism = true, MaxParallelism = 1 }));
        var failure = Assert.Single(Converters.ConvertChecks(health).OfType<CheckFailureInfo>(), view => view.Check == HealthCheckType.DANE);
        Assert.Equal("Error", failure.Status);
        Assert.Contains("DANE failed before cancellation.", failure.Summary);
        Assert.Single(health.Assessments, item => item.Code == "Verification.Check.Failed" && item.Category == "DANE");
    }

    [Fact]
    public async Task CancellationKeepsCompletedViewsAndMarksInterruptedViews() {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>());
        using var caller = new CancellationTokenSource();
        health.EdnsSupportAnalysis.QueryDnsOverride = (_, _) => { caller.Cancel(); return Task.FromResult(Array.Empty<DnsAnswer>()); };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => health.Verify("example.test",
            new[] { HealthCheckType.CAA, HealthCheckType.EDNSSUPPORT }, cancellationToken: caller.Token,
            executionOptions: new HealthCheckExecutionOptions { EnableParallelism = false }));
        var views = Converters.ConvertChecks(health);
        Assert.IsType<CaaInfo>(views[0]);
        Assert.Equal("Incomplete", Assert.IsType<CheckFailureInfo>(views[1]).Status);
        Assert.Equal(2, views.Count);
        Assert.DoesNotContain(health.Assessments, item => item.Code == "Verification.Check.Failed");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BatchFailureRetainsPartialResultsAndReportsUnsuccessful(bool streaming) {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>());
        health.EdnsSupportAnalysis.QueryDnsOverride = (_, _) => throw new TimeoutException("EDNS unavailable.");
        DomainHealthCheckRun? result = null;
        if (streaming) {
            await DomainHealthCheck.ProcessBatchAsync(new[] { "example.test" }, (run, _) => { result = run; return Task.CompletedTask; },
                new[] { HealthCheckType.EDNSSUPPORT, HealthCheckType.CAA }, healthCheckFactory: _ => health);
        } else {
            result = Assert.Single(await DomainHealthCheck.VerifyBatchAsync(new[] { "example.test" },
                new[] { HealthCheckType.EDNSSUPPORT, HealthCheckType.CAA }, healthCheckFactory: _ => health));
        }
        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Contains("EDNS unavailable", Assert.IsType<TimeoutException>(result.Error).Message);
        Assert.Same(health, result.HealthCheck);
        Assert.Single(Converters.ConvertChecks(health).OfType<CaaInfo>());
    }

    [Fact]
    public async Task EdnsWithoutALoggerPreservesFailureHealthAndDiscoveryDetails() {
        var analysis = new EdnsSupportAnalysis {
            QueryDnsOverride = (_, type) => type switch {
                DnsRecordType.NS => Task.FromResult(new[] { new DnsAnswer { Type = type, DataRaw = "ns.example.test" } }),
                DnsRecordType.A => Task.FromResult(new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" } }),
                _ => throw new TimeoutException("AAAA unavailable.")
            },
            QueryServerOverride = _ => throw new InvalidOperationException("UDP unavailable.")
        };
        await analysis.Analyze("example.test", null);
        var view = Converters.Convert(analysis);
        Assert.Equal(2, view.FailedCount);
        Assert.Equal(2, view.ErrorCount);
        Assert.Equal("Error", view.Status);
        Assert.Contains(view.Servers, server => server.Error!.Contains("AAAA: TimeoutException: AAAA unavailable."));
        Assert.Contains(view.Servers, server => server.Error!.Contains("InvalidOperationException: UDP unavailable."));
    }
}
