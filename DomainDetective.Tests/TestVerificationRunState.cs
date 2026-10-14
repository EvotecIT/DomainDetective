using DnsClientX;
using DomainDetective.Views;
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
        await health.Verify("example.test", new[] { HealthCheckType.EDNSSUPPORT });
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
        await health.Verify("example.test", new[] { HealthCheckType.CAA });
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
        Assert.DoesNotContain(HealthCheckType.CAA, health.LastVerifiedChecks);
        Assert.DoesNotContain(Converters.ConvertChecks(health), view => view is CaaInfo);
        Assert.Equal(preCanceled ? 0 : 1, health.LastVerifiedChecks.Count);
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
        Assert.Contains("EDNS unavailable", Assert.Single(Assert.IsType<AggregateException>(result.Error).InnerExceptions).Message);
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
