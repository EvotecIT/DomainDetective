using DnsClientX;
using System.Collections.Concurrent;

namespace DomainDetective.Tests;

public class TestDnsAuxiliaryScheduling {
    [Fact]
    public async Task ChaosQueriesOverlapAsnEnrichmentWithoutDroppingEitherResult() {
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var chaosEntered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var analysis = new NSAnalysis {
            QueryDnsOverride = (host, type) => Task.FromResult(type == DnsRecordType.A
                ? new[] { Answer(type, host.TrimEnd('.').StartsWith("one.", StringComparison.Ordinal) ? "192.0.2.1" : "198.51.100.1") }
                : Array.Empty<DnsAnswer>()),
            LookupAsnOverride = async ip => { await release.Task; return ip == "192.0.2.1" ? 64500 : 64501; },
            QueryResponseOverride = (_, _, _) => {
                chaosEntered.TrySetResult(true);
                return Task.FromResult<DnsResponse?>(new DnsResponse { Answers = new[] { Answer(DnsRecordType.TXT, "synthetic") } });
            }
        };
        var run = analysis.AnalyzeNsRecords(new[] { Answer(DnsRecordType.NS, "one.example.test"), Answer(DnsRecordType.NS, "two.example.test") }, new InternalLogger(), guard.Token);
        try {
            await chaosEntered.Task.WaitWithCancellation(guard.Token);
            Assert.False(run.IsCompleted);
        } finally { release.TrySetResult(true); try { await run; } catch (OperationCanceledException) when (guard.IsCancellationRequested) { } }
        await run;
        Assert.Equal(2, analysis.AsnDistinctCount);
        Assert.Equal(2, analysis.ChaosVersionByServer.Count);
        Assert.Equal(2, analysis.ChaosHostnameByServer.Count);
        Assert.True(analysis.AsnDiversityComplete);
    }

    [Fact]
    public async Task MxAuthorityAddressDiscoveryOverlapsHostsAndRetainsBothFamilies() {
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var allHosts = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = new ConcurrentDictionary<string, byte>();
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var analysis = new MXAnalysis();
        analysis.DnsConfiguration.QueryDnsResponseOverride = async (owner, type, token) => {
            if (type == DnsRecordType.NS) {
                return new DnsResponse { Answers = new[] { Answer(type, "one.example.test"), Answer(type, "two.example.test") } };
            }
            entered.TryAdd(owner, 0);
            if (entered.Count == 2) { allHosts.TrySetResult(true); }
            await release.Task.WaitWithCancellation(token);
            return new DnsResponse { Answers = new[] { Answer(type, type == DnsRecordType.A
                ? (owner.StartsWith("one.", StringComparison.Ordinal) ? "192.0.2.1" : "192.0.2.2")
                : (owner.StartsWith("one.", StringComparison.Ordinal) ? "2001:db8::1" : "2001:db8::2")) } };
        };
        var run = analysis.DiscoverAuthoritativeServersAsync("example.test", guard.Token);
        try { await allHosts.Task.WaitWithCancellation(guard.Token); }
        finally { release.TrySetResult(true); try { await run; } catch (OperationCanceledException) when (guard.IsCancellationRequested) { } }
        var result = await run;
        Assert.False(result.Incomplete);
        Assert.Equal(4, result.Addresses.Count);
        Assert.Contains("192.0.2.1", result.Addresses);
        Assert.Contains("192.0.2.2", result.Addresses);
        Assert.Contains("2001:db8::1", result.Addresses);
        Assert.Contains("2001:db8::2", result.Addresses);
    }

    private static DnsAnswer Answer(DnsRecordType type, string value) => new() { Type = type, DataRaw = value, TTL = 300 };

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AuthoritativeTtlValuesTryAnotherResolvedFamilyWhenFirstServerDoesNotAnswer(bool ipv4Responds) {
        var analysis = new DnsTtlAnalysis((server, owner, type, _, _, _) => {
            bool ipv4 = server.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
            DnsResponse? response = ipv4 != ipv4Responds ? null : new DnsResponse {
                IsAuthoritativeAnswer = true,
                Answers = new[] { new DnsAnswer { Name = owner, Type = type, DataRaw = type == DnsRecordType.NS ? "ns.example.test" : "192.0.2.44", TTL = 600 } }
            };
            return Task.FromResult(response);
        });
        analysis.DnsConfiguration.QueryDnsResponseOverride = (owner, type, _) => Task.FromResult(new DnsResponse {
            Answers = owner == "ns.example.test"
                ? type == DnsRecordType.A ? new[] { Answer(type, "192.0.2.1") }
                    : type == DnsRecordType.AAAA ? new[] { Answer(type, "2001:db8::1") } : Array.Empty<DnsAnswer>()
                : type == DnsRecordType.NS ? new[] { Answer(type, "ns.example.test") }
                    : type == DnsRecordType.A ? new[] { Answer(type, "192.0.2.44") } : Array.Empty<DnsAnswer>()
        });
        await analysis.Analyze("example.test", new InternalLogger());
        Assert.Equal(600, Assert.Single(analysis.ATtls));
        Assert.Equal(600, Assert.Single(analysis.NsTtls));
        Assert.True(analysis.TtlsFromAuthoritativeServers);
    }

    [Fact]
    public async Task PublicTtlScanOverlapsValueCollectionAndUniformityAndRetainsBothOutcomes() {
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var uniformityEntered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int nsQueries = 0;
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsResponseOverride = (_, type, _) => {
            if (type == DnsRecordType.NS && Interlocked.Increment(ref nsQueries) > 1) {
                uniformityEntered.TrySetResult(true);
                return Task.FromResult(new DnsResponse());
            }
            return Task.FromResult(new DnsResponse { Answers = type == DnsRecordType.A
                ? new[] { Answer(type, "192.0.2.1") }
                : type == DnsRecordType.NS ? new[] { Answer(type, "ns.example.test") } : Array.Empty<DnsAnswer>() });
        };
        health.DnsTtlAnalysis.AuthoritativeTtlOverride = async (_, _) => { await release.Task; return 300; };
        var run = health.Verify("example.test", new[] { HealthCheckType.TTL }, cancellationToken: guard.Token);
        try {
            await uniformityEntered.Task.WaitWithCancellation(guard.Token);
            Assert.False(run.IsCompleted);
        } finally { release.TrySetResult(true); try { await run; } catch (OperationCanceledException) when (guard.IsCancellationRequested) { } }
        await run;
        Assert.Equal(300, Assert.Single(health.DnsTtlAnalysis.ATtls));
        Assert.True(health.DnsTtlAnalysis.TtlsFromAuthoritativeServers);
        Assert.True(health.DnsTtlAnalysis.UniformityIncomplete);
        Assert.True(health.VerificationCompleted);
        Assert.Contains(HealthCheckType.TTL, health.VerificationCompletedChecks);
    }
}
