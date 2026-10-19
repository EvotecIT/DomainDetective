using DnsClientX;

namespace DomainDetective.Tests;

[Collection("Performance proxy environment")]
public class TestDnsblPerformance {
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BulkProvidersLeaveSharedDnsCapacityForForegroundQueries(bool batch) {
        using var first = new DomainHealthCheck();
        using var second = new DomainHealthCheck();
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var providersStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int active = 0;
        int peak = 0;
        foreach (var health in new[] { first, second }) {
            health.DNSBLAnalysis.ClearDNSBL();
            for (int index = 0; index < 8; index++) { health.DNSBLAnalysis.AddDNSBL($"provider{index}.example.test"); }
            health.DnsConfiguration.QueryDnsResponseOverride = async (owner, type, ct) => {
                if (type == DnsRecordType.CAA) { return new DnsResponse { Status = DnsResponseCode.NoError }; }
                if (type == DnsRecordType.MX) { return Answer(type, "10 mail." + owner); }
                if (owner.StartsWith("mail.", StringComparison.Ordinal)) {
                    return type == DnsRecordType.A ? Answer(type, "192.0.2.1") : new DnsResponse { Status = DnsResponseCode.NoError };
                }
                int current = Interlocked.Increment(ref active);
                int previous;
                do { previous = peak; }
                while (current > previous && Interlocked.CompareExchange(ref peak, current, previous) != previous);
                if (current >= 2) { providersStarted.TrySetResult(true); }
                try { await release.Task.WaitWithCancellation(ct); }
                finally { Interlocked.Decrement(ref active); }
                return new DnsResponse { Status = DnsResponseCode.NXDomain };
            };
        }
        var options = new HealthCheckExecutionOptions { DnsParallelism = 4, MaxDomainParallelism = 2 };
        Task verification = batch
            ? DomainHealthCheck.ProcessBatchAsync(new[] { "one.example.com", "two.example.com" }, (_, _) => Task.CompletedTask,
                new[] { HealthCheckType.DNSBL }, executionOptions: options, healthCheckFactory: domain => domain.StartsWith("one.", StringComparison.Ordinal) ? first : second, cancellationToken: guard.Token)
            : first.Verify("one.example.com", new[] { HealthCheckType.DNSBL }, executionOptions: options, cancellationToken: guard.Token);
        try {
            await providersStarted.Task.WaitWithCancellation(guard.Token);
            using var foregroundGuard = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
            using var foreground = CancellationTokenSource.CreateLinkedTokenSource(guard.Token, foregroundGuard.Token);
            await first.DnsConfiguration.QueryDNS("foreground.example.com", DnsRecordType.CAA, cancellationToken: foreground.Token);
            Assert.InRange(peak, 1, options.DnsParallelism!.Value - 1);
        } finally { release.TrySetResult(true); await verification; }
        Assert.Equal(0, active);
    }

    [Theory]
    [InlineData(1, 3)]
    [InlineData(32, 3)]
    [InlineData(1, 1)]
    public async Task SlowDiscoveryRetainsListingForAnAlreadyResolvedFamily(int dnsParallelism, int analysisSeconds) {
        using var admission = new SemaphoreSlim(dnsParallelism);
        using var configuration = new DnsConfiguration {
            QueryAdmissionGate = admission,
            ResolverMaxConcurrency = dnsParallelism,
            QueryDnsResponseOverride = async (owner, type, ct) => {
                if (owner == "example.com") {
                    if (type == DnsRecordType.A) { return Answer(type, "192.0.2.1"); }
                    await Task.Delay(Timeout.Infinite, ct);
                }
                return Answer(DnsRecordType.A, "127.0.0.2");
            }
        };
        var analysis = new DNSBLAnalysis { DnsConfiguration = configuration, AnalysisTimeout = TimeSpan.FromSeconds(analysisSeconds) };
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        await analysis.AnalyzeDNSBLRecordsMX("example.com", new InternalLogger(), scanMode: DomainIpScanMode.ApexOnly);
        Assert.False(analysis.DiscoverySucceeded);
        Assert.Contains(analysis.AllResults, record => record.IpAddress == "192.0.2.1" && record.IsBlackListed && record.QuerySucceeded);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FallbackDiscoveryIsQueuedBeforeDomainProviders(bool emptyMx) {
        using var health = new DomainHealthCheck();
        var analysis = health.DNSBLAnalysis;
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        analysis.AnalysisTimeout = TimeSpan.FromMilliseconds(500);
        health.DnsConfiguration.QueryDnsResponseOverride = async (owner, type, ct) => {
            if (owner == "example.com") {
                if (type == DnsRecordType.MX) {
                    await Task.Delay(10, ct);
                    return emptyMx ? new DnsResponse { Status = DnsResponseCode.NoError } : Answer(type, "10 mail.example.com");
                }
                return Answer(type, type == DnsRecordType.A ? "192.0.2.1" : "2001:db8::1");
            }
            if (owner == "mail.example.com") {
                await Task.Delay(30, ct);
                return new DnsResponse { Status = DnsResponseCode.NoError };
            }
            if (owner.StartsWith("example.com.", StringComparison.Ordinal)) { await Task.Delay(Timeout.Infinite, ct); }
            return new DnsResponse { Status = DnsResponseCode.NXDomain };
        };
        await health.Verify("example.com", new[] { HealthCheckType.DNSBL }, executionOptions: new HealthCheckExecutionOptions { DnsParallelism = 1 });
        Assert.True(analysis.DiscoverySucceeded);
        Assert.Contains(analysis.AllResults, record => record.IpSource == DnsblIpSource.ApexA);
        Assert.Contains(analysis.AllResults, record => record.IpSource == DnsblIpSource.ApexAAAA);
    }

    [Fact]
    public async Task Ipv6RecordTypesShareOneProviderExecutionDeadline() {
        using var admission = new SemaphoreSlim(1);
        using var configuration = new DnsConfiguration {
            QueryAdmissionGate = admission,
            QueryDnsResponseOverride = async (_, type, ct) => {
                await Task.Delay(70, ct);
                return Answer(type, type == DnsRecordType.A ? "127.0.0.2" : "::1");
            }
        };
        var analysis = new DNSBLAnalysis {
            DnsConfiguration = configuration, ProviderTimeout = TimeSpan.FromMilliseconds(100), AnalysisTimeout = TimeSpan.FromSeconds(2)
        };
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        await analysis.AnalyzeDNSBLRecordsMany(new[] { "2001:db8::1" }, new InternalLogger());
        Assert.Contains(analysis.AllResults, record => !record.QuerySucceeded);
    }

    [Fact]
    public async Task DomainProvidersCannotTakeTheOnlyDnsSlotBeforeDiscovery() {
        using var health = new DomainHealthCheck();
        var analysis = health.DNSBLAnalysis;
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        analysis.AnalysisTimeout = TimeSpan.FromSeconds(1);
        health.DnsConfiguration.QueryDnsResponseOverride = async (owner, type, ct) => {
            if (owner == "example.com" && type == DnsRecordType.MX) { return Answer(type, "10 mail.example.com"); }
            if (owner == "mail.example.com") { return Answer(type, type == DnsRecordType.A ? "192.0.2.1" : "2001:db8::1"); }
            if (owner.StartsWith("example.com.", StringComparison.Ordinal)) { await Task.Delay(Timeout.Infinite, ct); }
            return new DnsResponse { Status = DnsResponseCode.NXDomain };
        };
        await health.Verify("example.com", new[] { HealthCheckType.DNSBL }, executionOptions: new HealthCheckExecutionOptions { DnsParallelism = 1 });
        Assert.True(analysis.DiscoverySucceeded);
        Assert.Contains(analysis.AllResults, record => record.IpSource == DnsblIpSource.MxA);
        Assert.Contains(analysis.AllResults, record => record.IpSource == DnsblIpSource.MxAAAA);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task IndependentDnsBorrowerCanOutliveVerificationAdmission(bool batch) {
        using var health = new DomainHealthCheck();
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var verificationStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var borrowerStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseVerification = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseBorrower = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        health.DnsConfiguration.QueryDnsResponseOverride = async (owner, _, ct) => {
            if (owner == "borrower.example") {
                borrowerStarted.TrySetResult(true);
                await releaseBorrower.Task.WaitWithCancellation(ct);
            } else {
                verificationStarted.TrySetResult(true);
                await releaseVerification.Task.WaitWithCancellation(ct);
            }
            return new DnsResponse { Status = DnsResponseCode.NoError };
        };
        try {
            Task verification = batch
                ? DomainHealthCheck.ProcessBatchAsync(new[] { "example.com" }, (_, _) => Task.CompletedTask,
                    new[] { HealthCheckType.CAA }, healthCheckFactory: _ => health, cancellationToken: guard.Token)
                : health.Verify("example.com", new[] { HealthCheckType.CAA }, cancellationToken: guard.Token);
            await verificationStarted.Task.WaitWithCancellation(guard.Token);
            var borrower = health.DnsConfiguration.QueryDNS("borrower.example", DnsRecordType.TXT, cancellationToken: guard.Token);
            await borrowerStarted.Task.WaitWithCancellation(guard.Token);
            releaseVerification.TrySetResult(true);
            await verification;
            releaseBorrower.TrySetResult(true);
            Assert.Empty(await borrower);
        } finally { releaseVerification.TrySetResult(true); releaseBorrower.TrySetResult(true); }
    }

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
