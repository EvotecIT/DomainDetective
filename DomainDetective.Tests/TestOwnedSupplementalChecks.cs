using System.Net;
using System.Net.Http;
using DnsClientX;

namespace DomainDetective.Tests;

public class TestOwnedSupplementalChecks {
    [Fact]
    public async Task FilteredPlainHttpEvidenceDoesNotFollowTheNextSourceRun() {
        using var health = new DomainHealthCheck();
        health.ExecutionOptions.IncludePlainHttp = true;
        health.PlainHttpAnalysis.HttpHandlerFactory = () => new Handler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        health.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) => Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError });
        await health.Verify("first.fixture.example", new[] { HealthCheckType.CAA });
        using var snapshot = health.FilterAnalyses(new[] { HealthCheckType.CAA });
        var visited = snapshot.PlainHttpAnalysis.VisitedUrls.ToArray();
        var missing = snapshot.PlainHttpAnalysis.MissingSecurityHeaders.ToArray();
        Assert.NotEmpty(visited);
        await health.Verify("second.fixture.example", new[] { HealthCheckType.CAA });
        Assert.Equal(visited, snapshot.PlainHttpAnalysis.VisitedUrls);
        Assert.Equal(missing, snapshot.PlainHttpAnalysis.MissingSecurityHeaders);
        Assert.NotSame(health.PlainHttpAnalysis.Assessments, snapshot.PlainHttpAnalysis.Assessments);
        Assert.True(snapshot.VerificationPlainHttpCompleted);
    }

    [Fact]
    public async Task SupplementalOnlyPlanDoesNotInventDefaultChecks() {
        using var health = new DomainHealthCheck();
        var questions = new List<DnsRecordType>();
        health.DnsConfiguration.QueryDnsResponseOverride = (_, type, _) => {
            questions.Add(type);
            return Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError });
        };
        await health.Verify("fixture.example", Array.Empty<HealthCheckType>(),
            executionOptions: new HealthCheckExecutionOptions { IncludeTakeoverCname = true }, useDefaultChecksWhenEmpty: false);
        Assert.True(health.VerificationCompleted);
        Assert.True(health.VerificationTakeoverCompleted);
        Assert.Null(health.VerificationPlainHttpCompleted);
        Assert.Empty(health.VerificationRequestedChecks);
        Assert.Empty(health.VerificationCompletedChecks);
        Assert.Equal(new[] { DnsRecordType.CNAME }, questions);
    }

    [Fact]
    public async Task CompletedSupplementalEvidenceSurvivesMainFailureAndNextRunResets() {
        using var health = new DomainHealthCheck();
        health.ExecutionOptions.IncludePlainHttp = true;
        health.ExecutionOptions.IncludeTakeoverCname = true;
        health.PlainHttpAnalysis.HttpHandlerFactory = () => new Handler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        health.DnsConfiguration.QueryDnsResponseOverride = (_, type, _) => type == DnsRecordType.SOA
            ? throw new InvalidOperationException("Synthetic SOA failure")
            : Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError });
        await Assert.ThrowsAsync<InvalidOperationException>(() => health.Verify("fixture.example", new[] { HealthCheckType.SOA }));
        Assert.False(health.VerificationCompleted);
        Assert.True(health.VerificationPlainHttpCompleted);
        Assert.True(health.VerificationTakeoverCompleted);
        Assert.Equal("http://fixture.example", health.PlainHttpAnalysis.Subject);
        Assert.Empty(health.VerificationCompletedChecks);
        health.ExecutionOptions.IncludePlainHttp = false;
        health.ExecutionOptions.IncludeTakeoverCname = false;
        await health.Verify("fixture.example", new[] { HealthCheckType.CAA });
        Assert.True(health.VerificationCompleted);
        Assert.Null(health.VerificationError);
        Assert.Null(health.VerificationPlainHttpCompleted);
        Assert.Null(health.VerificationTakeoverCompleted);
    }

    [Fact]
    public async Task CallerCancellationDrainsBothSupplementalOwnersWithTheOriginalToken() {
        using var health = new DomainHealthCheck();
        using var caller = new CancellationTokenSource();
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var httpEntered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var takeoverEntered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int active = 0;
        health.ExecutionOptions.IncludePlainHttp = true;
        health.ExecutionOptions.IncludeTakeoverCname = true;
        health.PlainHttpAnalysis.HttpHandlerFactory = () => new Handler(async (_, token) => {
            Interlocked.Increment(ref active);
            httpEntered.TrySetResult(true);
            try { await Task.Delay(Timeout.Infinite, token); }
            finally { Interlocked.Decrement(ref active); }
            return new HttpResponseMessage(HttpStatusCode.OK);
        });
        health.DnsConfiguration.QueryDnsResponseOverride = async (_, type, token) => {
            if (type == DnsRecordType.CNAME) {
                Interlocked.Increment(ref active);
                takeoverEntered.TrySetResult(true);
                try { await Task.Delay(Timeout.Infinite, token); }
                finally { Interlocked.Decrement(ref active); }
            }
            return new DnsResponse { Status = DnsResponseCode.NoError };
        };
        var run = health.Verify("fixture.example", new[] { HealthCheckType.CAA }, cancellationToken: caller.Token);
        await Task.WhenAll(httpEntered.Task, takeoverEntered.Task).WaitWithCancellation(guard.Token);
        caller.Cancel();
        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.WaitWithCancellation(guard.Token));
        Assert.Equal(caller.Token, error.CancellationToken);
        Assert.Equal(0, active);
        Assert.False(health.VerificationCompleted);
        Assert.False(health.VerificationPlainHttpCompleted);
        Assert.False(health.VerificationTakeoverCompleted);
    }

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request, cancellationToken);
    }
}
