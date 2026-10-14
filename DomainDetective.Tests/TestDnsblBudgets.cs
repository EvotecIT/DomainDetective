using DnsClientX;
using DomainDetective.Views;

namespace DomainDetective.Tests;

public class TestDnsblBudgets {
    [Fact]
    public async Task AppendingAnIpPreservesTheEarlierDomainsIncompleteDiscovery() {
        using var health = new DomainHealthCheck();
        var analysis = health.DNSBLAnalysis;
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        analysis.QueryDnsFullOverride = (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] { new DnsResponse { Status = DnsResponseCode.NXDomain } });
        health.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) => Task.FromResult(new DnsResponse { Status = DnsResponseCode.ServerFailure });
        await health.VerifyDNSBLWithMode("example.test", DomainIpScanMode.MxOnly);
        Assert.False(analysis.DiscoverySucceeded);
        await analysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.1" }, new InternalLogger(), false);
        Assert.False(analysis.DiscoverySucceeded);
        Assert.NotEmpty(analysis.DiscoveryErrors);
        Assert.Equal("Incomplete", Converters.Convert(analysis).Status);
    }
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Ipv6KeepsListingsWhenTheOtherRecordTypeFails(bool failA) {
        var analysis = new DNSBLAnalysis();
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        var types = new List<DnsRecordType>();
        analysis.QueryDnsFullOverride = (names, type) => {
            types.Add(type);
            bool fails = failA == (type == DnsRecordType.A);
            return Task.FromResult<IEnumerable<DnsResponse>>(new[] { fails
                ? new DnsResponse { Status = DnsResponseCode.ServerFailure }
                : new DnsResponse { Answers = new[] { new DnsAnswer { Name = names[0], Type = type, DataRaw = "127.0.0.2" } } } });
        };
        await analysis.AnalyzeDNSBLRecordsMany(new[] { "2001:db8::1" }, new InternalLogger());
        Assert.Equal(new[] { DnsRecordType.A, DnsRecordType.AAAA }, types);
        Assert.Equal(1, analysis.Results["2001:db8::1"].Listed);
        Assert.Equal(1, analysis.Results["2001:db8::1"].NotChecked);
        Assert.Equal(0, analysis.Results["2001:db8::1"].NotListed);
    }

    [Fact]
    public async Task ReservedProviderErrorIsIncompleteRatherThanClean() {
        using var health = new DomainHealthCheck();
        var analysis = health.DNSBLAnalysis;
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        analysis.QueryDnsFullOverride = (names, type) => Task.FromResult<IEnumerable<DnsResponse>>(new[] {
            new DnsResponse { Answers = new[] { new DnsAnswer { Name = names[0], Type = type, DataRaw = "127.255.255.254" } } }
        });
        await analysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.1" }, new InternalLogger());
        Assert.Equal(1, analysis.Results["192.0.2.1"].NotChecked);
        Assert.Equal(0, analysis.NotBlacklisted);
        Assert.Equal("Incomplete", Converters.Convert(analysis).Status);
        Assert.DoesNotContain(analysis.Assessments, a => a.Code == DnsblCodes.NotListed);
        Assert.Equal("Incomplete", Assert.Single(Converters.ConvertDomainOverview(health, "example.test").WebRegistrationChecks,
            check => check.Key == "dnsbl").Value);
    }

    [Fact]
    public async Task AppendingResultsStartsAFreshBudgetAfterIdleTime() {
        var analysis = new DNSBLAnalysis { AnalysisTimeout = TimeSpan.FromMilliseconds(50) };
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        int queries = 0;
        analysis.QueryDnsFullOverride = (_, _) => {
            queries++;
            return Task.FromResult<IEnumerable<DnsResponse>>(new[] { new DnsResponse { Status = DnsResponseCode.NXDomain } });
        };
        await analysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.1" }, new InternalLogger());
        await Task.Delay(100);
        await analysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.2" }, new InternalLogger(), false);
        Assert.Equal(2, queries);
        Assert.Equal(2, analysis.Results.Count);
        Assert.All(analysis.AllResults, record => Assert.True(record.QuerySucceeded));
    }

    [Fact]
    public async Task PublicDomainScanBoundsDiscoveryAndRetainsUnknownCoverage() {
        using var health = new DomainHealthCheck();
        health.DNSBLAnalysis.AnalysisTimeout = TimeSpan.FromMilliseconds(50);
        health.DNSBLAnalysis.ClearDNSBL();
        health.DNSBLAnalysis.AddDNSBL("provider.example.test");
        health.DnsConfiguration.QueryDnsOverride = async (_, _) => { await Task.Delay(150); return Array.Empty<DnsAnswer>(); };
        await health.VerifyDNSBL("example.test");
        Assert.False(health.DNSBLAnalysis.DiscoverySucceeded);
        Assert.NotEmpty(health.DNSBLAnalysis.DiscoveryErrors);
        Assert.Equal("Incomplete", Converters.Convert(health.DNSBLAnalysis).Status);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task PublicDomainEntryPointsPropagateCancellationDuringDiscovery(bool array, bool fallback) {
        using var health = new DomainHealthCheck();
        using var cancellation = new CancellationTokenSource();
        health.DnsConfiguration.QueryDnsOverride = (_, type) => {
            if (!fallback || type == DnsRecordType.A) { cancellation.Cancel(); }
            return Task.FromResult(Array.Empty<DnsAnswer>());
        };
        if (array) {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => health.CheckDNSBL(new[] { "example.test" }, cancellation.Token));
        } else {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => health.VerifyDNSBL("example.test", cancellation.Token));
        }
    }
    [Fact]
    public async Task TimedOutProviderIsIncompleteRatherThanCleanAndOtherListingsSurvive() {
        var analysis = new DNSBLAnalysis { ProviderTimeout = TimeSpan.FromMilliseconds(50) };
        analysis.ClearDNSBL();
        analysis.AddDNSBL("slow.example.test");
        analysis.AddDNSBL("listed.example.test");
        analysis.QueryDnsFullOverride = async (names, type) => {
            if (names[0].EndsWith("slow.example.test", StringComparison.Ordinal)) {
                await Task.Delay(150);
                return new[] { new DnsResponse() };
            }
            return new[] { new DnsResponse { Answers = new[] { new DnsAnswer { Name = names[0], Type = type, DataRaw = "127.0.0.2" } } } };
        };
        await analysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.1" }, new InternalLogger());
        var result = analysis.Results["192.0.2.1"];
        Assert.Equal(1, result.Listed);
        Assert.Equal(1, result.NotChecked);
        Assert.Equal(0, result.NotListed);
        Assert.Contains(analysis.Assessments, a => a.Code == DnsblCodes.ProviderTimeout);
        Assert.DoesNotContain(analysis.Assessments, a => a.Code == DnsblCodes.NotListed);
        Assert.Equal("Incomplete", Converters.Convert(analysis).Status);
        Assert.Equal(1, Assert.Single(Converters.Convert(analysis).HostSummaries).NotChecked);
    }

    [Fact]
    public async Task FailedDnsResponseIsNotAValidNegativeListing() {
        var analysis = new DNSBLAnalysis();
        analysis.ClearDNSBL();
        analysis.AddDNSBL("unavailable.example.test");
        analysis.QueryDnsFullOverride = (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] { new DnsResponse { Status = DnsResponseCode.ServerFailure } });
        await analysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.2" }, new InternalLogger());
        Assert.Equal(1, analysis.Results["192.0.2.2"].NotChecked);
        Assert.Equal(0, analysis.NotBlacklisted);
        Assert.DoesNotContain(analysis.Assessments, a => a.Code == DnsblCodes.NotListed);
    }

    [Fact]
    public async Task Ipv6RetainsBothAddressTypesAndCallerCancellationPropagates() {
        var types = new List<DnsRecordType>();
        var analysis = new DNSBLAnalysis();
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        analysis.QueryDnsFullOverride = (_, type) => {
            types.Add(type);
            return Task.FromResult<IEnumerable<DnsResponse>>(new[] { new DnsResponse { Status = DnsResponseCode.NXDomain } });
        };
        await analysis.AnalyzeDNSBLRecordsMany(new[] { "2001:db8::1" }, new InternalLogger());
        Assert.Equal(new[] { DnsRecordType.A, DnsRecordType.AAAA }, types);
        Assert.Equal(1, analysis.Results["2001:db8::1"].NotListed);
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => analysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.1" }, new InternalLogger(), true, canceled.Token));
    }
}
