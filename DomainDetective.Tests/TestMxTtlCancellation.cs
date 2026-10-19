using DnsClientX;
using System.Threading;

namespace DomainDetective.Tests;

public class TestMxTtlCancellation {
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PublicMxEntryPointsForwardCallerCancellation(bool rawRecord) {
        using var health = new DomainHealthCheck();
        using var caller = new CancellationTokenSource();
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var blocked = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int active = 0;
        health.DnsConfiguration.QueryDnsResponseOverride = async (_, type, token) => {
            if (type == DnsRecordType.MX) { return TestMxTtlScheduling.Reply(type, "10 mail.example.test"); }
            if (type != DnsRecordType.CNAME) { return new DnsResponse(); }
            Interlocked.Increment(ref active);
            entered.TrySetResult(true);
            try { await blocked.Task.WaitWithCancellation(token); return new DnsResponse(); }
            finally { Interlocked.Decrement(ref active); }
        };
        var run = rawRecord ? health.CheckMX("10 mail.example.test", caller.Token) : health.VerifyMX("example.test", caller.Token);
        try {
            await entered.Task.WaitWithCancellation(guard.Token);
            caller.Cancel();
            var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.WaitWithCancellation(guard.Token));
            Assert.Equal(caller.Token, error.CancellationToken);
            Assert.Equal(0, active);
        } finally { caller.Cancel(); blocked.TrySetResult(true); try { await run; } catch (OperationCanceledException) { } }
    }

    [Theory]
    [InlineData(DnsRecordType.SOA)]
    [InlineData(DnsRecordType.NS)]
    [InlineData(DnsRecordType.AAAA)]
    public async Task MxAuthorityDiscoveryRetainsOriginalCallerCancellation(DnsRecordType blockedType) {
        var analysis = new MXAnalysis { Subject = "example.test" };
        using var configuration = analysis.DnsConfiguration;
        TestMxTtlScheduling.ConfigureMxDiscovery(analysis);
        var respond = configuration.QueryDnsResponseOverride!;
        using var caller = new CancellationTokenSource();
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var blocked = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int active = 0;
        configuration.QueryDnsResponseOverride = async (owner, type, token) => {
            if (type != blockedType || type == DnsRecordType.AAAA && owner != "ns.example.test") {
                return await respond(owner, type, token);
            }
            Interlocked.Increment(ref active);
            entered.TrySetResult(true);
            try { await blocked.Task.WaitWithCancellation(token); return new DnsResponse(); }
            finally { Interlocked.Decrement(ref active); }
        };
        var run = analysis.AnalyzeMxRecords(new[] { new DnsAnswer { Type = DnsRecordType.MX, DataRaw = "10 mail.example.test" } }, new InternalLogger(), caller.Token);
        try {
            await entered.Task.WaitWithCancellation(guard.Token);
            caller.Cancel();
            var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.WaitWithCancellation(guard.Token));
            Assert.Equal(caller.Token, error.CancellationToken);
            Assert.Equal(0, active);
        } finally { caller.Cancel(); blocked.TrySetResult(true); try { await run; } catch (OperationCanceledException) { } }
    }

    [Fact]
    public async Task MxCancellationDrainsAdmittedComparisonProbesBeforeReturning() {
        using var caller = new CancellationTokenSource();
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var canceled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int active = 0;
        var analysis = new MXAnalysis(async (_, _, type, token) => {
            using var registration = token.Register(() => canceled.TrySetResult(true));
            Interlocked.Increment(ref active);
            entered.TrySetResult(true);
            try { await release.Task; return TestMxTtlScheduling.Reply(type, "192.0.2.100"); }
            finally { Interlocked.Decrement(ref active); }
        }) { Subject = "example.test" };
        using var configuration = analysis.DnsConfiguration;
        TestMxTtlScheduling.ConfigureMxDiscovery(analysis);
        var run = analysis.AnalyzeMxRecords(new[] { new DnsAnswer { Type = DnsRecordType.MX, DataRaw = "10 mail.example.test" } }, new InternalLogger(), caller.Token);
        try {
            await entered.Task.WaitWithCancellation(guard.Token);
            caller.Cancel();
            await canceled.Task.WaitWithCancellation(guard.Token);
            Assert.False(run.IsCompleted);
            release.TrySetResult(true);
            var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.WaitWithCancellation(guard.Token));
            Assert.Equal(caller.Token, error.CancellationToken);
            Assert.Equal(0, active);
        } finally { caller.Cancel(); release.TrySetResult(true); try { await run; } catch (OperationCanceledException) { } }
    }

    [Fact]
    public async Task TtlCancellationDrainsTheReachabilityAndRecordPipeline() {
        using var caller = new CancellationTokenSource();
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var canceled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int active = 0;
        var analysis = new DnsTtlAnalysis(async (_, _, type, _, token, preflight) => {
            if (preflight) { return TestMxTtlScheduling.Reply(type, "ns.example.test"); }
            using var registration = token.Register(() => canceled.TrySetResult(true));
            Interlocked.Increment(ref active);
            entered.TrySetResult(true);
            try { await release.Task; return TestMxTtlScheduling.Reply(type, "192.0.2.100"); }
            finally { Interlocked.Decrement(ref active); }
        }) { UniformityMaxParallelism = 2 };
        using var configuration = analysis.DnsConfiguration;
        TestMxTtlScheduling.ConfigureTtlDiscovery(analysis, "192.0.2.1", "192.0.2.2");
        var run = analysis.AnalyzeUniformityAcrossServers("example.test", new InternalLogger(), caller.Token);
        try {
            await entered.Task.WaitWithCancellation(guard.Token);
            caller.Cancel();
            await canceled.Task.WaitWithCancellation(guard.Token);
            Assert.False(run.IsCompleted);
            release.TrySetResult(true);
            var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.WaitWithCancellation(guard.Token));
            Assert.Equal(caller.Token, error.CancellationToken);
            Assert.Equal(0, active);
        } finally { caller.Cancel(); release.TrySetResult(true); try { await run; } catch (OperationCanceledException) { } }
    }
}
