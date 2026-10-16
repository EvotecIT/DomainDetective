using DnsClientX;

namespace DomainDetective.Tests;

[Collection("Performance proxy environment")]
public class TestDnsblPerformance {
    [Fact]
    public async Task SlowProviderWorkCannotPreventDiscoveryOfTheOtherAddressFamily() {
        using var health = new DomainHealthCheck();
        var ipv6Discovered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var analysis = health.DNSBLAnalysis;
        analysis.ClearDNSBL();
        for (int index = 0; index < 20; index++) { analysis.AddDNSBL($"provider{index}.example.test"); }
        analysis.AnalysisTimeout = TimeSpan.FromSeconds(1);
        int ipQueries = 0;
        health.DnsConfiguration.QueryDnsResponseOverride = async (owner, type, ct) => {
            if (owner == "example.com" && type == DnsRecordType.MX) {
                return Answer(type, "10 mail.example.com");
            }
            if (owner == "mail.example.com") {
                if (type == DnsRecordType.AAAA) {
                    ipv6Discovered.TrySetResult(true);
                    return Answer(type, "2001:db8::1");
                }
                return Answer(type, "192.0.2.1");
            }
            if (!owner.StartsWith("example.com.", StringComparison.Ordinal)) { Interlocked.Increment(ref ipQueries); }
            await ipv6Discovered.Task.WaitWithCancellation(ct);
            return new DnsResponse { Status = DnsResponseCode.NXDomain };
        };
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try {
            await health.Verify("example.com", new[] { HealthCheckType.DNSBL }, cancellationToken: guard.Token);
            Assert.True(ipv6Discovered.Task.IsCompleted);
            Assert.True(analysis.DiscoverySucceeded);
            Assert.Contains(analysis.AllResults, record => record.IpSource == DnsblIpSource.MxA && record.IpAddress == "192.0.2.1");
            Assert.Contains(analysis.AllResults, record => record.IpSource == DnsblIpSource.MxAAAA && record.IpAddress == "2001:db8::1");
            // Both IPv6 query types are checked, but their empty answers produce one provider result.
            Assert.Equal(60, ipQueries);
            Assert.Equal(40, analysis.AllResults.Count(record => record.IpAddress != null));
            Assert.All(analysis.AllResults, record => Assert.True(record.QuerySucceeded));
        } finally { ipv6Discovered.TrySetResult(true); }
    }

    [Fact]
    public async Task ExpiredProviderBudgetObservesOwnedCallbackCleanupBeforeReturning() {
        using var health = new DomainHealthCheck();
        var analysis = health.DNSBLAnalysis;
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        analysis.AnalysisTimeout = TimeSpan.FromMilliseconds(100);
        int active = 0;
        int started = 0;
        health.DnsConfiguration.QueryDnsResponseOverride = async (owner, type, ct) => {
            if (owner == "example.com" && type == DnsRecordType.MX) { return Answer(type, "10 mail.example.com"); }
            if (owner == "mail.example.com") {
                return type == DnsRecordType.A ? Answer(type, "192.0.2.1") : new DnsResponse { Status = DnsResponseCode.NoError };
            }
            Interlocked.Increment(ref active);
            Interlocked.Increment(ref started);
            try { await Task.Delay(Timeout.Infinite, ct); }
            finally {
                await Task.Delay(30);
                Interlocked.Decrement(ref active);
            }
            return new DnsResponse { Status = DnsResponseCode.NXDomain };
        };
        await health.Verify("example.com", new[] { HealthCheckType.DNSBL });
        Assert.True(started > 0);
        Assert.Equal(0, active);
        Assert.Null(health.DnsConfiguration.QueryAdmissionGate);
        Assert.NotEmpty(analysis.AllResults);
        Assert.All(analysis.AllResults, record => Assert.False(record.QuerySucceeded));
        var addresses = await health.DnsConfiguration.QueryDNS("mail.example.com", DnsRecordType.A);
        Assert.Equal("192.0.2.1", Assert.Single(addresses).Data);
    }

    [Fact]
    public async Task ConcurrentAppendRunsShareTheAnalysisProviderAdmissionCap() {
        using var configuration = new DnsConfiguration { ResolverMaxConcurrency = 32 };
        var analysis = new DNSBLAnalysis { DnsConfiguration = configuration, AnalysisTimeout = TimeSpan.FromSeconds(10) };
        analysis.ClearDNSBL();
        for (int index = 0; index < 8; index++) { analysis.AddDNSBL($"provider{index}.example.test"); }
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var barrier = new AdmissionBarrier(32, guard.Token);
        int active = 0;
        int peak = 0;
        analysis.QueryDnsFullOverride = async (_, _) => {
            int current = Interlocked.Increment(ref active);
            int previous;
            do { previous = peak; }
            while (current > previous && Interlocked.CompareExchange(ref peak, current, previous) != previous);
            try {
                await barrier.EnterAsync();
                await Task.Delay(10, guard.Token);
                return new[] { new DnsResponse { Status = DnsResponseCode.NXDomain } };
            } finally { Interlocked.Decrement(ref active); }
        };
        await Task.WhenAll(Enumerable.Range(1, 8).Select(index => analysis.AnalyzeDNSBLRecordsMany(
            new[] { $"192.0.2.{index}" }, new InternalLogger(), false, guard.Token)));
        Assert.Equal(32, peak);
        Assert.Equal(0, active);
        Assert.Equal(64, analysis.AllResults.Count);
    }

    private static DnsResponse Answer(DnsRecordType type, string data) => new() {
        Status = DnsResponseCode.NoError,
        Answers = new[] { new DnsAnswer { Type = type, DataRaw = data } }
    };
}
