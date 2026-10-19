using DnsClientX;
using System.Collections.Concurrent;

namespace DomainDetective.Tests;

public class TestDiscoveryBottleneckScheduling {
    [Fact]
    public async Task AutodiscoverQueriesAllIndependentDnsHintsBeforeWaitingForAnswers() {
        var release = Signal();
        var allEntered = Signal();
        int entered = 0;
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var analysis = new AutodiscoverAnalysis {
            QueryDnsOverride = async (owner, type) => {
                if (Interlocked.Increment(ref entered) == 3) allEntered.TrySetResult(true);
                await release.Task;
                return new[] { Answer(type, type == DnsRecordType.SRV ? "0 0 443 service.example.test" : "mail.example.test") };
            }
        };
        using var config = new DnsConfiguration();
        var run = analysis.Analyze("example.test", config, new InternalLogger(), guard.Token);
        try { await allEntered.Task.WaitWithCancellation(guard.Token); }
        finally { release.TrySetResult(true); try { await run; } catch (OperationCanceledException) when (guard.IsCancellationRequested) { } }
        await run;
        Assert.True(analysis.SrvRecordExists);
        Assert.Equal(443, analysis.SrvPort);
        Assert.Equal("service.example.test", analysis.SrvTarget);
        Assert.Equal("mail.example.test", analysis.AutoconfigTarget);
        Assert.Equal("mail.example.test", analysis.AutodiscoverTarget);
    }

    [Fact]
    public async Task AutodiscoverCallerCancellationReachesAndDrainsDnsRequests() {
        var entered = Signal();
        var release = Signal();
        int active = 0;
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var caller = new CancellationTokenSource();
        using var config = new DnsConfiguration {
            QueryDnsResponseOverride = async (_, _, token) => {
                Interlocked.Increment(ref active);
                entered.TrySetResult(true);
                try { await release.Task.WaitWithCancellation(token); return new DnsResponse(); }
                finally { Interlocked.Decrement(ref active); }
            }
        };
        var run = new AutodiscoverAnalysis().Analyze("example.test", config, new InternalLogger(), caller.Token);
        try {
            await entered.Task.WaitWithCancellation(guard.Token);
            caller.Cancel();
            var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.WaitWithCancellation(guard.Token));
            Assert.Equal(caller.Token, error.CancellationToken);
            Assert.Equal(0, active);
        } finally { release.TrySetResult(true); try { await run; } catch (OperationCanceledException) { } }
    }

    [Fact]
    public async Task SpfAddressProjectionOverlapsFamiliesAndKeepsBothAddressSets() {
        var analysis = new SpfAnalysis { QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>()) };
        await analysis.AnalyzeSpfRecords(new[] { Answer(DnsRecordType.TXT, "v=spf1 a -all") }, new InternalLogger());
        var release = Signal();
        var bothEntered = Signal();
        int entered = 0;
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        analysis.QueryDnsOverride = async (_, type) => {
            if (Interlocked.Increment(ref entered) == 2) bothEntered.TrySetResult(true);
            await release.Task;
            return new[] { Answer(type, type == DnsRecordType.A ? "192.0.2.1" : "2001:db8::1") };
        };
        var run = analysis.GetFlattenedIpAnalysis("example.test");
        try { await bothEntered.Task.WaitWithCancellation(guard.Token); }
        finally { release.TrySetResult(true); await run; }
        var result = await run;
        Assert.True(result.Complete);
        Assert.Equal(new[] { "192.0.2.1", "2001:db8::1" }, result.UniqueIps);
        Assert.Equal(result.UniqueIps, result.TokenIpMap["a"]);
    }

    [Fact]
    public async Task ReverseDnsOverlapsAddressesAndRetainsEveryPtrAndForwardConfirmation() {
        var release = Signal();
        var bothEntered = Signal();
        var ptrs = new ConcurrentDictionary<string, byte>();
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var analysis = new ReverseDnsAnalysis {
            QueryDnsOverride = async (owner, type) => {
                if (type == DnsRecordType.PTR) {
                    ptrs.TryAdd(owner, 0);
                    if (ptrs.Count == 2) bothEntered.TrySetResult(true);
                    await release.Task.WaitWithCancellation(guard.Token);
                    return new[] { Answer(type, "mail.example.test") };
                }
                return type == DnsRecordType.A ? new[] { Answer(type, "192.0.2.1"), Answer(type, "192.0.2.2") } : Array.Empty<DnsAnswer>();
            }
        };
        var run = analysis.AnalyzeHosts(new[] { "mail.example.test" }, new InternalLogger(), guard.Token);
        try { await bothEntered.Task.WaitWithCancellation(guard.Token); }
        finally { release.TrySetResult(true); try { await run; } catch (OperationCanceledException) when (guard.IsCancellationRequested) { } }
        await run;
        Assert.Equal(2, analysis.Results.Count);
        Assert.All(analysis.Results, result => {
            Assert.True(result.IsValid);
            Assert.True(result.FcrDnsValid);
            Assert.Equal("mail.example.test", Assert.Single(result.PtrRecords));
        });
    }

    private static TaskCompletionSource<bool> Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static DnsAnswer Answer(DnsRecordType type, string value) => new() { Type = type, DataRaw = value, TTL = 300 };
}
