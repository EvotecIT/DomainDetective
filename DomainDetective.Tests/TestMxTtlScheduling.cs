using DnsClientX;
using System.Collections.Concurrent;
using System.Net;
using System.Threading;

namespace DomainDetective.Tests;

public class TestMxTtlScheduling {
    [Fact]
    public async Task IndependentMxOwnersOverlapWithoutDroppingAnyServerOrAddressFamily() {
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var allOwners = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = new ConcurrentDictionary<string, int>();
        var owners = new ConcurrentDictionary<string, byte>();
        var analysis = new MXAnalysis(async (server, owner, type, token) => {
            calls.AddOrUpdate(server + "|" + owner + "|" + type, 1, (_, count) => count + 1);
            owners.TryAdd(owner, 0);
            if (owners.Count == 4) { allOwners.TrySetResult(true); }
            await release.Task.WaitWithCancellation(token);
            return Reply(type, type == DnsRecordType.MX ? "10 one.example.test" :
                type == DnsRecordType.A ? "192.0.2.100" : "2001:db8::100");
        }) { Subject = "example.test" };
        ConfigureMxDiscovery(analysis);
        var run = analysis.AnalyzeMxRecords(new[] { Mx("one"), Mx("two"), Mx("three") }, new InternalLogger());
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try { await allOwners.Task.WaitWithCancellation(guard.Token); }
        finally { release.TrySetResult(true); await run; }

        Assert.Equal(14, calls.Count);
        Assert.All(calls.Values, count => Assert.Equal(1, count));
        foreach (string host in new[] { "one", "two", "three" }) {
            foreach (string server in new[] { "192.0.2.1", "192.0.2.2" }) {
                Assert.Contains(server + "|" + host + ".example.test|A", calls.Keys);
                Assert.Contains(server + "|" + host + ".example.test|AAAA", calls.Keys);
            }
        }
        Assert.False(analysis.MxRrsetComparisonIncomplete);
        Assert.False(analysis.TargetAddressComparisonIncomplete);
        Assert.True(analysis.MxRrsetConsistentAcrossNs);
        Assert.True(analysis.TargetAddressConsistentAcrossNs);
    }

    [Fact]
    public async Task ResponsiveTtlServerContinuesWhileSiblingReachabilityIsPending() {
        var slowEntered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var recordRead = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = new ConcurrentDictionary<string, int>();
        var analysis = new DnsTtlAnalysis(async (server, owner, type, _, token, preflight) => {
            calls.AddOrUpdate(server + "|" + owner + "|" + type, 1, (_, count) => count + 1);
            if (server.Equals(IPAddress.Parse("192.0.2.2"))) {
                Assert.True(preflight);
                slowEntered.TrySetResult(true);
                await release.Task.WaitWithCancellation(token);
                return null;
            }
            if (!preflight && type == DnsRecordType.A) { recordRead.TrySetResult(true); }
            return Reply(type, type == DnsRecordType.A ? "192.0.2.100" : "ns.example.test");
        }) { DkimSelectors = new List<string> { "default", "selector1" }, UniformityMaxParallelism = 2 };
        ConfigureTtlDiscovery(analysis, "192.0.2.1", "192.0.2.2");
        var run = analysis.AnalyzeUniformityAcrossServers("example.test", new InternalLogger());
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try {
            await slowEntered.Task.WaitWithCancellation(guard.Token);
            await recordRead.Task.WaitWithCancellation(guard.Token);
            Assert.False(run.IsCompleted);
        } finally { release.TrySetResult(true); await run; }

        Assert.Equal(11, calls.Count);
        Assert.All(calls.Values, count => Assert.Equal(1, count));
        Assert.Equal(300, analysis.ServerTtlA["192.0.2.1"]);
        Assert.Equal(300, analysis.ServerTtlNs["192.0.2.1"]);
        Assert.Null(analysis.ServerTtlA["192.0.2.2"]);
        Assert.Equal(2, analysis.ServerTtlTxtPerName.Count);
        Assert.All(analysis.ServerTtlTxtPerName.Values, map => {
            Assert.Equal(300, map["192.0.2.1"]);
            Assert.Null(map["192.0.2.2"]);
        });
        Assert.True(analysis.UniformityIncomplete);
        Assert.False(analysis.AUniformAcrossServers);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task SuccessfulNsPreflightAvoidsDuplicateButUnusablePreflightIsRetried(bool authoritative) {
        int nsQueries = 0;
        var analysis = new DnsTtlAnalysis((_, _, type, _, _, _) => {
            if (type == DnsRecordType.NS) { Interlocked.Increment(ref nsQueries); }
            var response = Reply(type, "ns.example.test");
            response.IsAuthoritativeAnswer = authoritative;
            return Task.FromResult<DnsResponse?>(response);
        });
        ConfigureTtlDiscovery(analysis, "192.0.2.1");
        await analysis.AnalyzeUniformityAcrossServers("example.test", new InternalLogger());
        Assert.Equal(authoritative ? 1 : 2, nsQueries);
        Assert.Equal(authoritative ? (int?)300 : null, analysis.ServerTtlNs["192.0.2.1"]);
        Assert.Equal(!authoritative, analysis.UniformityIncomplete);
    }

    [Theory]
    [InlineData(DnsResponseCode.Refused)]
    [InlineData(DnsResponseCode.NoError)]
    public async Task UnusableNsPreflightDoesNotDiscardALaterAuthoritativeReply(DnsResponseCode preflightStatus) {
        int nsQueries = 0;
        var analysis = new DnsTtlAnalysis((_, _, type, _, _, preflight) => {
            if (type == DnsRecordType.NS) { Interlocked.Increment(ref nsQueries); }
            return Task.FromResult<DnsResponse?>(preflight ? new DnsResponse { Status = preflightStatus }
                : Reply(type, "ns.example.test"));
        });
        ConfigureTtlDiscovery(analysis, "192.0.2.1");
        await analysis.AnalyzeUniformityAcrossServers("example.test", new InternalLogger());
        Assert.Equal(2, nsQueries);
        Assert.Equal(300, analysis.ServerTtlNs["192.0.2.1"]);
        Assert.False(analysis.UniformityIncomplete);
    }

    [Fact]
    public async Task MxComparisonSharesItsQueryBoundAcrossManyOwners() {
        var admitted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int active = 0, maximum = 0, completed = 0;
        var analysis = new MXAnalysis(async (_, _, type, token) => {
            if (type == DnsRecordType.MX) { Interlocked.Increment(ref completed); return Reply(type, "10 mail.example.test"); }
            int current = Interlocked.Increment(ref active);
            int old;
            do { old = Volatile.Read(ref maximum); } while (current > old && Interlocked.CompareExchange(ref maximum, current, old) != old);
            if (current == 4) { admitted.TrySetResult(true); }
            try {
                await release.Task.WaitWithCancellation(token);
                Interlocked.Increment(ref completed);
                return Reply(type, type == DnsRecordType.A ? "192.0.2.100" : "2001:db8::100");
            } finally { Interlocked.Decrement(ref active); }
        }) { Subject = "example.test", AuthoritativeMaxParallelism = 8 };
        using var configuration = analysis.DnsConfiguration;
        configuration.ResolverMaxConcurrency = 4;
        ConfigureMxDiscovery(analysis);
        var run = analysis.AnalyzeMxRecords(Enumerable.Range(0, 20).Select(index => Mx("mail" + index)), new InternalLogger());
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try { await admitted.Task.WaitWithCancellation(guard.Token); }
        finally { release.TrySetResult(true); await run; }
        Assert.Equal(4, maximum);
        Assert.Equal(82, completed);
        Assert.Equal(0, active);
        Assert.False(analysis.TargetAddressComparisonIncomplete);
    }

    [Fact]
    public async Task TtlReachabilityAndRecordQueriesShareOneAdmissionBound() {
        var admitted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int active = 0, maximum = 0, completed = 0;
        var analysis = new DnsTtlAnalysis(async (_, _, type, _, token, preflight) => {
            int current = Interlocked.Increment(ref active);
            int old;
            do { old = Volatile.Read(ref maximum); } while (current > old && Interlocked.CompareExchange(ref maximum, current, old) != old);
            if (current == 2) { admitted.TrySetResult(true); }
            try {
                if (!preflight) { await release.Task.WaitWithCancellation(token); }
                Interlocked.Increment(ref completed);
                return Reply(type, "ns.example.test");
            } finally { Interlocked.Decrement(ref active); }
        }) { UniformityMaxParallelism = 2, DkimSelectors = new List<string> { "default", "selector1" } };
        using var configuration = analysis.DnsConfiguration;
        ConfigureTtlDiscovery(analysis, "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4");
        var run = analysis.AnalyzeUniformityAcrossServers("example.test", new InternalLogger());
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try { await admitted.Task.WaitWithCancellation(guard.Token); }
        finally { release.TrySetResult(true); await run; }
        Assert.Equal(2, maximum);
        Assert.Equal(40, completed);
        Assert.Equal(0, active);
        Assert.False(analysis.UniformityIncomplete);
        Assert.Equal(4, analysis.ServerTtlA.Count);
        Assert.All(analysis.ServerTtlTxtPerName.Values, map => Assert.Equal(4, map.Count));
    }

    private static DnsAnswer Mx(string host) => new() { Type = DnsRecordType.MX, DataRaw = "10 " + host + ".example.test" };

    internal static DnsResponse Reply(DnsRecordType type, string data) => new() {
        IsAuthoritativeAnswer = true,
        Answers = new[] { new DnsAnswer { Type = type, DataRaw = data, TTL = 300 } }
    };

    internal static void ConfigureMxDiscovery(MXAnalysis analysis) {
        analysis.DnsConfiguration.QueryDnsResponseOverride = (owner, type, _) => Task.FromResult(type switch {
            DnsRecordType.SOA => new DnsResponse { Authorities = new[] { new DnsAnswer { Type = type, Name = "example.test" } } },
            DnsRecordType.NS => Reply(type, "ns.example.test"),
            DnsRecordType.A when owner == "ns.example.test" => new DnsResponse { Answers = new[] {
                new DnsAnswer { Type = type, DataRaw = "192.0.2.1" }, new DnsAnswer { Type = type, DataRaw = "192.0.2.2" }
            } },
            DnsRecordType.A => Reply(type, "192.0.2.100"),
            DnsRecordType.AAAA when owner == "ns.example.test" => new DnsResponse(),
            DnsRecordType.AAAA => Reply(type, "2001:db8::100"),
            _ => new DnsResponse()
        });
    }

    internal static void ConfigureTtlDiscovery(DnsTtlAnalysis analysis, params string[] servers) {
        analysis.QueryDnsOverride = (_, type) => Task.FromResult(type == DnsRecordType.NS
            ? new[] { new DnsAnswer { Type = type, DataRaw = "ns.example.test" } }
            : type == DnsRecordType.A ? servers.Select(server => new DnsAnswer { Type = type, DataRaw = server }).ToArray()
            : Array.Empty<DnsAnswer>());
    }
}
