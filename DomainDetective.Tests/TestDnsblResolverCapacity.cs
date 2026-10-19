using System.Reflection;
using DnsClientX;

namespace DomainDetective.Tests;

[Collection("Performance proxy environment")]
public class TestDnsblResolverCapacity {
    [Theory]
    [InlineData(8, false)]
    [InlineData(8, true)]
    [InlineData(32, false)]
    [InlineData(64, false)]
    [InlineData(64, true)]
    public async Task ProvidersUseAvailableCapacityWhileLeavingForegroundRoom(int dnsParallelism, bool batch) {
        using var health = CreateHealth(MultiResolverStrategy.SequentialFallback);
        health.MultiResolverMaxParallelism = dnsParallelism;
        health.ResolverMaxConcurrency = dnsParallelism;
        health.DNSBLAnalysis.ClearDNSBL();
        for (int index = 0; index < dnsParallelism + 2; index++) {
            health.DNSBLAnalysis.AddDNSBL($"{index}.provider.example.test");
        }
        health.DNSBLAnalysis.AnalysisTimeout = Timeout.InfiniteTimeSpan;
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var capacityUsed = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int active = 0;
        int entered = 0;
        using var resolver = OverrideResolver(async (_, owner, type, token) => {
            if (!owner.EndsWith(".provider.example.test", StringComparison.Ordinal)) { return Discovery(owner, type); }
            Interlocked.Increment(ref active);
            try {
                if (Interlocked.Increment(ref entered) == dnsParallelism - 1) { capacityUsed.TrySetResult(true); }
                await release.Task.WaitWithCancellation(token);
                return new DnsResponse { Status = DnsResponseCode.NXDomain };
            } finally { Interlocked.Decrement(ref active); }
        });
        var options = new HealthCheckExecutionOptions { DnsParallelism = dnsParallelism };
        Task verification = batch
            ? DomainHealthCheck.ProcessBatchAsync(new[] { "capacity.example.test" }, (_, _) => Task.CompletedTask,
                new[] { HealthCheckType.DNSBL }, executionOptions: options, healthCheckFactory: _ => health, cancellationToken: guard.Token)
            : health.Verify("capacity.example.test", new[] { HealthCheckType.DNSBL }, executionOptions: options, cancellationToken: guard.Token);
        try {
            await capacityUsed.Task.WaitWithCancellation(guard.Token);
            Assert.Equal(dnsParallelism - 1, Volatile.Read(ref active));
            // Provider requests stay blocked while a foreground query uses the reserved slot.
            await health.DnsConfiguration.QueryDNS("foreground.example.test", DnsRecordType.CAA, cancellationToken: guard.Token);
        } finally {
            release.TrySetResult(true);
            await verification;
        }
        Assert.Equal(0, Volatile.Read(ref active));
        Assert.Equal(dnsParallelism + 2, health.DNSBLAnalysis.AllResults.Count(record => record.QueryKind == DnsblQueryKind.IpAddressV4));
        Assert.All(health.DNSBLAnalysis.AllResults, record => Assert.True(record.QuerySucceeded));
    }

    [Theory]
    [InlineData(1, MultiResolverStrategy.SequentialFallback)]
    [InlineData(2, MultiResolverStrategy.FirstSuccess)]
    [InlineData(2, MultiResolverStrategy.FastestWins)]
    public async Task SlowDiscoveryLeavesTimeForKnownTargetsAtTheActualResolverLimit(int resolverCap, MultiResolverStrategy strategy) {
        using var health = CreateHealth(strategy);
        health.MultiResolverMaxParallelism = resolverCap;
        health.ResolverMaxConcurrency = 4;
        health.DNSBLAnalysis.AnalysisTimeout = TimeSpan.FromMilliseconds(700);
        health.DNSBLAnalysis.DiscoveryTimeout = TimeSpan.FromSeconds(2);
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var resolver = OverrideResolver(async (_, owner, type, token) => {
            if (owner == "capacity.example.test" && type == DnsRecordType.AAAA) {
                try { await Task.Delay(Timeout.Infinite, token); }
                finally { await Task.Delay(20); }
            }
            return new DnsResponse {
                Status = DnsResponseCode.NoError,
                Answers = type == DnsRecordType.A ? new[] { new DnsAnswer {
                    Name = owner, Type = type, TTL = 60,
                    DataRaw = owner == "capacity.example.test" ? "192.0.2.1" : "127.0.0.2"
                } } : Array.Empty<DnsAnswer>()
            };
        });
        await health.DNSBLAnalysis.AnalyzeDNSBLRecordsMX("capacity.example.test", new InternalLogger(),
            scanMode: DomainIpScanMode.ApexOnly, cancellationToken: guard.Token);
        Assert.False(health.DNSBLAnalysis.DiscoverySucceeded);
        Assert.Contains(health.DNSBLAnalysis.AllResults, record => record.IpAddress == "192.0.2.1" && record.IsBlackListed && record.QuerySucceeded);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SmallerResolverCapLeavesRoomForForegroundQueries(bool batch) {
        using var health = CreateHealth(MultiResolverStrategy.SequentialFallback);
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var started = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var resolver = OverrideResolver(async (_, owner, type, token) => {
            if (owner.EndsWith(".provider.example.test", StringComparison.Ordinal)) {
                started.TrySetResult(true);
                await release.Task.WaitWithCancellation(token);
                return new DnsResponse { Status = DnsResponseCode.NXDomain };
            }
            return Discovery(owner, type);
        });
        var options = new HealthCheckExecutionOptions { DnsParallelism = 4 };
        Task verification = batch
            ? DomainHealthCheck.ProcessBatchAsync(new[] { "capacity.example.test" }, (_, _) => Task.CompletedTask,
                new[] { HealthCheckType.DNSBL }, executionOptions: options, healthCheckFactory: _ => health, cancellationToken: guard.Token)
            : health.Verify("capacity.example.test", new[] { HealthCheckType.DNSBL }, executionOptions: options, cancellationToken: guard.Token);
        try {
            await started.Task.WaitWithCancellation(guard.Token);
            using var foreground = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
            await health.DnsConfiguration.QueryDNS("foreground.example.test", DnsRecordType.CAA, cancellationToken: foreground.Token);
        } finally {
            release.TrySetResult(true);
            await verification;
        }
    }

    [Theory]
    [InlineData(MultiResolverStrategy.FirstSuccess)]
    [InlineData(MultiResolverStrategy.FastestWins)]
    public async Task FullEndpointFanoutDefersBulkUntilOtherChecksComplete(MultiResolverStrategy strategy) {
        using var health = CreateHealth(strategy);
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        bool foregroundCompleted = false;
        bool providerStartedBeforeForeground = false;
        using var resolver = OverrideResolver((_, owner, type, _) => {
            if (type == DnsRecordType.CAA) { foregroundCompleted = true; }
            if (owner.EndsWith(".provider.example.test", StringComparison.Ordinal) && !foregroundCompleted) {
                providerStartedBeforeForeground = true;
            }
            return Task.FromResult(Discovery(owner, type));
        });
        await health.Verify("capacity.example.test", new[] { HealthCheckType.DNSBL, HealthCheckType.CAA },
            executionOptions: new HealthCheckExecutionOptions { DnsParallelism = 4 }, cancellationToken: guard.Token);
        Assert.True(foregroundCompleted);
        Assert.NotEmpty(health.DNSBLAnalysis.AllResults);
        Assert.False(providerStartedBeforeForeground);
    }

    private static DomainHealthCheck CreateHealth(MultiResolverStrategy strategy) {
        DnsMultiResolver.ClearFastestCache();
        var health = new DomainHealthCheck { MultiResolverMaxParallelism = 2 };
        health.DnsConfiguration.EnableResponseCache = false;
        health.DnsConfiguration.DnsEndpoints.Add(DnsEndpoint.Cloudflare);
        health.DnsConfiguration.DnsEndpoints.Add(DnsEndpoint.Google);
        health.DnsConfiguration.MultiResolverStrategy = strategy;
        health.DNSBLAnalysis.ClearDNSBL();
        for (int index = 0; index < 4; index++) { health.DNSBLAnalysis.AddDNSBL($"{index}.provider.example.test"); }
        health.DNSBLAnalysis.ProviderTimeout = Timeout.InfiniteTimeSpan;
        return health;
    }

    private static DnsResponse Discovery(string owner, DnsRecordType type) => new() {
        Status = DnsResponseCode.NoError,
        Answers = type == DnsRecordType.MX ? new[] { new DnsAnswer { Name = owner, Type = type, DataRaw = "10 mail.capacity.example.test", TTL = 60 } }
            : type == DnsRecordType.A && owner == "mail.capacity.example.test"
                ? new[] { new DnsAnswer { Name = owner, Type = type, DataRaw = "192.0.2.1", TTL = 60 } } : Array.Empty<DnsAnswer>()
    };

    // This existing DnsClientX transport seam executes after its actual shared endpoint limiter.
    // The nonparallel collection prevents the process-wide override from affecting other tests.
    private static IDisposable OverrideResolver(Func<DnsResolverEndpoint, string, DnsRecordType, CancellationToken, Task<DnsResponse>> callback) {
        var field = typeof(DnsMultiResolver).GetField("ResolveOverride", BindingFlags.Static | BindingFlags.NonPublic)!;
        var previous = field.GetValue(null);
        field.SetValue(null, callback);
        return new Restore(() => field.SetValue(null, previous));
    }

    private sealed class Restore(Action restore) : IDisposable {
        public void Dispose() => restore();
    }
}
