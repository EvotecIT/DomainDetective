using DnsClientX;
using DomainDetective.Views;
using DomainDetective.DesiredState;

namespace DomainDetective.Tests;

public class TestDnsblBudgets {
    [Fact]
    public async Task InfiniteProviderTimeoutStillHonorsTheAnalysisBudget() {
        var pending = new TaskCompletionSource<IEnumerable<DnsResponse>>(TaskCreationOptions.RunContinuationsAsynchronously);
        var analysis = new DNSBLAnalysis { ProviderTimeout = Timeout.InfiniteTimeSpan, AnalysisTimeout = TimeSpan.FromMilliseconds(100) };
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        analysis.QueryDnsFullOverride = (_, _) => pending.Task;
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try {
            await analysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.1" }, new InternalLogger(), true, guard.Token);
            Assert.False(guard.IsCancellationRequested);
            Assert.False(Assert.Single(analysis.AllResults).QuerySucceeded);
            Assert.Equal("Incomplete", Converters.Convert(analysis).Status);
        } finally { pending.TrySetResult(Array.Empty<DnsResponse>()); }
    }

    [Theory]
    [InlineData(DnsblIpSource.UserProvided)]
    [InlineData(DnsblIpSource.ApexA)]
    [InlineData(DnsblIpSource.MxA)]
    public async Task DesiredDnsblCoverageFollowsTheSelectedDiscoverySources(DnsblIpSource selectedSource) {
        using var health = new DomainHealthCheck();
        health.DNSBLAnalysis.ClearDNSBL();
        health.DNSBLAnalysis.AddDNSBL("provider.example.test");
        health.DNSBLAnalysis.QueryDnsFullOverride = (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] { new DnsResponse { Status = DnsResponseCode.NXDomain } });
        health.DnsConfiguration.QueryDnsResponseOverride = (_, type, _) => Task.FromResult(new DnsResponse {
            Status = type == DnsRecordType.MX ? DnsResponseCode.ServerFailure : DnsResponseCode.NoError,
            Answers = type == DnsRecordType.A ? new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.2" } } : Array.Empty<DnsAnswer>()
        });
        await health.DNSBLAnalysis.AnalyzeDNSBLRecordsMX("example.test", new InternalLogger(), scanMode: DomainIpScanMode.MxAndApex);
        await health.DNSBLAnalysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.1" }, new InternalLogger(), false);
        Assert.False(health.DNSBLAnalysis.DiscoverySucceeded);
        var profile = new DesiredStateProfile { Dnsbl = new DesiredStateDnsblPolicy {
            DisallowListings = true, RequireAtLeastOneResult = false, IncludeIpSources = new[] { selectedSource }
        } };
        var evaluated = DesiredStateEvaluator.Evaluate("example.test", health, profile);
        Assert.Equal(selectedSource == DnsblIpSource.MxA, evaluated.Assessments.Any(item => item.Code == "DesiredState.DNSBL.QueryFailed"));
        Assert.Equal(selectedSource != DnsblIpSource.MxA, evaluated.Conforms);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RetainedEvidenceRetractsAnOutdatedCleanPositive(bool listed) {
        var analysis = new DNSBLAnalysis();
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        bool first = true;
        analysis.QueryDnsFullOverride = (names, type) => Task.FromResult<IEnumerable<DnsResponse>>(new[] {
            first ? new DnsResponse { Status = DnsResponseCode.NXDomain } :
            listed ? new DnsResponse { Answers = new[] { new DnsAnswer { Name = names[0], Type = type, DataRaw = "127.0.0.2" } } } :
            new DnsResponse { Status = DnsResponseCode.ServerFailure }
        });
        await analysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.1" }, new InternalLogger());
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == DnsblCodes.NotListed);
        first = false;
        await analysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.1" }, new InternalLogger(), false);
        Assert.DoesNotContain(analysis.Assessments, assessment => assessment.Code == DnsblCodes.NotListed);
        Assert.DoesNotContain(Converters.Convert(analysis).Positives, advice => advice.Code == DnsblCodes.NotListed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DesiredDnsblPolicyCannotConformFromUnknownEvidence(bool discovery) {
        using var health = new DomainHealthCheck();
        health.DNSBLAnalysis.ClearDNSBL();
        health.DNSBLAnalysis.AddDNSBL("provider.example.test");
        health.DNSBLAnalysis.QueryDnsFullOverride = (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] {
            new DnsResponse { Status = discovery ? DnsResponseCode.NXDomain : DnsResponseCode.ServerFailure } });
        health.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) => Task.FromResult(new DnsResponse { Status = DnsResponseCode.ServerFailure });
        if (discovery) { await health.VerifyDNSBLWithMode("example.test", DomainIpScanMode.MxOnly); }
        else { await health.DNSBLAnalysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.1" }, new InternalLogger()); }
        var profile = new DesiredStateProfile { Dnsbl = new DesiredStateDnsblPolicy { RequireAtLeastOneResult = true, DisallowListings = true } };
        var evaluated = DesiredStateEvaluator.Evaluate("example.test", health, profile);
        Assert.False(evaluated.Conforms);
        Assert.Contains(evaluated.Assessments, item => item.Code == "DesiredState.DNSBL.QueryFailed");
        profile.Dnsbl.RequireAtLeastOneResult = false;
        if (discovery) { profile.Dnsbl.IncludeQueryKinds = new[] { DnsblQueryKind.Domain }; }
        else { profile.Dnsbl.IgnoredBlacklists = new[] { "provider.example.test" }; }
        Assert.True(DesiredStateEvaluator.Evaluate("example.test", health, profile).Conforms);
    }

    [Theory]
    [InlineData(DomainIpScanMode.MxOnly)]
    [InlineData(DomainIpScanMode.ApexAOnly)]
    [InlineData(DomainIpScanMode.MxThenApexFallback)]
    public async Task UnexpectedDiscoveryExceptionsRetainUnknownCoverage(DomainIpScanMode scanMode) {
        using var health = new DomainHealthCheck();
        health.DNSBLAnalysis.ClearDNSBL();
        health.DNSBLAnalysis.AddDNSBL("provider.example.test");
        health.DNSBLAnalysis.QueryDnsFullOverride = (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] { new DnsResponse { Status = DnsResponseCode.NXDomain } });
        health.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) => throw new FormatException("Malformed discovery reply.");
        await health.VerifyDNSBLWithMode("example.test", scanMode);
        Assert.False(health.DNSBLAnalysis.DiscoverySucceeded);
        Assert.Contains(health.DNSBLAnalysis.DiscoveryErrors, error => error.Contains("Malformed discovery reply."));
        Assert.Equal("Incomplete", Converters.Convert(health.DNSBLAnalysis).Status);
        Assert.DoesNotContain(health.DNSBLAnalysis.Assessments, assessment => assessment.Code == DnsblCodes.NotListed);
    }

    [Fact]
    public async Task CaseVariantAppendRetainsOneCoverageTarget() {
        var analysis = new DNSBLAnalysis();
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        analysis.QueryDnsFullOverride = (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] { new DnsResponse { Status = DnsResponseCode.NXDomain } });
        await analysis.AnalyzeDNSBLRecordsMany(new[] { "Mail.example.test" }, new InternalLogger());
        await analysis.AnalyzeDNSBLRecordsMany(new[] { "MAIL.example.test" }, new InternalLogger(), false);
        Assert.Equal(1, analysis.RecordChecked);
        Assert.Single(Converters.Convert(analysis).HostSummaries);
    }

    [Fact]
    public async Task Ipv6ListingSurvivesTheOtherFamilyUsingTheWholeDeadline() {
        var analysis = new DNSBLAnalysis { ProviderTimeout = TimeSpan.FromMilliseconds(50) };
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        var pending = new TaskCompletionSource<IEnumerable<DnsResponse>>(TaskCreationOptions.RunContinuationsAsynchronously);
        analysis.QueryDnsFullOverride = (names, type) => type == DnsRecordType.A ? pending.Task : Task.FromResult<IEnumerable<DnsResponse>>(
            new[] { new DnsResponse { Answers = new[] { new DnsAnswer { Name = names[0], Type = type, DataRaw = "127.0.0.2" } } } });
        try {
            await analysis.AnalyzeDNSBLRecordsMany(new[] { "2001:db8::1" }, new InternalLogger());
            Assert.Equal(1, analysis.Results["2001:db8::1"].Listed);
            Assert.Equal(1, analysis.Results["2001:db8::1"].NotChecked);
        } finally { pending.TrySetResult(Array.Empty<DnsResponse>()); }
    }

    [Fact]
    public async Task RetainedFailedRecordsKeepCoverageIncompleteAfterACleanRepeat() {
        var analysis = new DNSBLAnalysis();
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        bool fails = true;
        analysis.QueryDnsFullOverride = (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] {
            new DnsResponse { Status = fails ? DnsResponseCode.ServerFailure : DnsResponseCode.NXDomain } });
        await analysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.1" }, new InternalLogger());
        var failed = Converters.Convert(analysis);
        Assert.Equal(0, failed.ProvidersChecked);
        Assert.Contains("Providers checked: 0", DomainDetective.Narratives.DnsblNarrative.Build(analysis).Highlights);
        Assert.Equal(0, Assert.Single(failed.Pathways).ProvidersChecked);
        fails = false;
        await analysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.1" }, new InternalLogger(), false);
        var repeated = Converters.Convert(analysis);
        Assert.Equal("Incomplete", repeated.Status);
        Assert.Equal(0, analysis.NotBlacklisted);
        Assert.Equal(1, Assert.Single(repeated.HostSummaries).NotChecked);
        Assert.Equal(0, analysis.Results["192.0.2.1"].NotChecked); // Raw Results retains the latest-result contract.
        Assert.Equal(1, repeated.ProvidersChecked);
        Assert.Contains(analysis.AllResults, record => !record.QuerySucceeded);
        Assert.Contains(DomainDetective.Narratives.DnsblNarrative.Build(analysis).Details,
            detail => detail.Contains("192.0.2.1: listed 0/2; not checked 1"));
    }

    [Fact]
    public async Task OverlappingAppendRunCannotReplaceTheFirstCallersCancellation() {
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<IEnumerable<DnsResponse>>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var caller = new CancellationTokenSource();
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var analysis = new DNSBLAnalysis { ProviderTimeout = TimeSpan.FromSeconds(5) };
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        analysis.QueryDnsFullOverride = (names, _) => {
            if (names[0].StartsWith("1.2.0.192.", StringComparison.Ordinal)) {
                entered.TrySetResult(true);
                return release.Task;
            }
            return Task.FromResult<IEnumerable<DnsResponse>>(new[] { new DnsResponse { Status = DnsResponseCode.NXDomain } });
        };
        var logger = new InternalLogger();
        var first = analysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.1" }, logger, true, caller.Token);
        try {
            await entered.Task.WaitWithCancellation(guard.Token);
            await analysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.2" }, logger, false);
            caller.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);
            Assert.False(analysis.Results.ContainsKey("192.0.2.1"));
            Assert.True(analysis.Results.ContainsKey("192.0.2.2"));
            Assert.DoesNotContain(analysis.Assessments, item => item.Code == DnsblCodes.ProviderTimeout);
        } finally {
            release.TrySetResult(new[] { new DnsResponse { Status = DnsResponseCode.NXDomain } });
        }
    }

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
    [InlineData(true, false)]
    [InlineData(false, false)]
    [InlineData(true, true)]
    [InlineData(false, true)]
    public async Task Ipv6KeepsListingsWhenTheOtherRecordTypeFails(bool failA, bool throws) {
        var analysis = new DNSBLAnalysis();
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        var types = new List<DnsRecordType>();
        analysis.QueryDnsFullOverride = (names, type) => {
            types.Add(type);
            bool fails = failA == (type == DnsRecordType.A);
            if (fails && throws) { throw new FormatException("Malformed provider response."); }
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
        var analysis = new DNSBLAnalysis { AnalysisTimeout = TimeSpan.FromSeconds(1) };
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        int queries = 0;
        analysis.QueryDnsFullOverride = (_, _) => {
            queries++;
            return Task.FromResult<IEnumerable<DnsResponse>>(new[] { new DnsResponse { Status = DnsResponseCode.NXDomain } });
        };
        await analysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.1" }, new InternalLogger());
        await Task.Delay(1200);
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
