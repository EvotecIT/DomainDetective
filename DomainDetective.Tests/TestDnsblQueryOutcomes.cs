using DnsClientX;
using DomainDetective.Views;

namespace DomainDetective.Tests;

public class TestDnsblQueryOutcomes {
    [Theory]
    [InlineData(DomainIpScanMode.ApexAOnly, false)]
    [InlineData(DomainIpScanMode.ApexAOnly, true)]
    [InlineData(DomainIpScanMode.MxThenApexFallback, false)]
    [InlineData(DomainIpScanMode.MxThenApexFallback, true)]
    public async Task AliasAnswersDoNotBecomeIpCoverageOrPreventApexFallback(DomainIpScanMode mode, bool terminalAddress) {
        using var health = new DomainHealthCheck();
        var analysis = health.DNSBLAnalysis;
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        var queries = new List<string>();
        analysis.QueryDnsFullOverride = (names, _) => {
            queries.AddRange(names);
            return Task.FromResult<IEnumerable<DnsResponse>>(new[] { new DnsResponse { Status = DnsResponseCode.NXDomain } });
        };
        health.DnsConfiguration.QueryDnsResponseOverride = (owner, type, _) => {
            if (type == DnsRecordType.MX) { return Task.FromResult(new DnsResponse { Answers = new[] { new DnsAnswer { Type = type, DataRaw = "10 mail.example.test" } } }); }
            var answers = new List<DnsAnswer> { new() { Type = DnsRecordType.CNAME, DataRaw = "alias.example.test" } };
            if (type == DnsRecordType.A && (terminalAddress || mode == DomainIpScanMode.MxThenApexFallback && owner == "example.test")) {
                answers.Add(new DnsAnswer { Type = type, DataRaw = owner == "mail.example.test" ? "192.0.2.1" : "192.0.2.2" });
            }
            return Task.FromResult(new DnsResponse { Answers = answers.ToArray() });
        };
        await health.VerifyDNSBLWithMode("example.test", mode);
        Assert.True(analysis.DiscoverySucceeded);
        Assert.DoesNotContain(queries, query => query.StartsWith("alias.", StringComparison.Ordinal));
        Assert.DoesNotContain(analysis.Results.Keys, target => target == "alias.example.test");
        var ips = analysis.AllResults.Where(record => record.QueryKind != DnsblQueryKind.Domain).ToArray();
        if (mode == DomainIpScanMode.ApexAOnly && !terminalAddress) { Assert.Empty(ips); }
        else { Assert.Equal(mode == DomainIpScanMode.MxThenApexFallback && terminalAddress ? "192.0.2.1" : "192.0.2.2", Assert.Single(ips).IpAddress); }
    }

    [Fact]
    public async Task WrongFamilyAddressCannotBecomeCompletedDiscoveryEvidence() {
        using var health = new DomainHealthCheck();
        health.DNSBLAnalysis.ClearDNSBL();
        health.DNSBLAnalysis.QueryDnsFullOverride = (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] { new DnsResponse { Status = DnsResponseCode.NXDomain } });
        health.DnsConfiguration.QueryDnsResponseOverride = (_, type, _) => Task.FromResult(new DnsResponse {
            Answers = new[] { new DnsAnswer { Type = type, DataRaw = "2001:db8::1" } }
        });
        await health.VerifyDNSBLWithMode("example.test", DomainIpScanMode.ApexAOnly);
        Assert.False(health.DNSBLAnalysis.DiscoverySucceeded);
        Assert.DoesNotContain(health.DNSBLAnalysis.AllResults, record => record.IpAddress != null);
        Assert.Equal("Incomplete", Converters.Convert(health.DNSBLAnalysis).Status);
    }

    private static DNSBLAnalysis Analysis() {
        var analysis = new DNSBLAnalysis();
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        return analysis;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CleanTargetEvidenceSurvivesAnotherTargetsFailureInEitherOrder(bool failedFirst) {
        var analysis = Analysis();
        analysis.QueryDnsFullOverride = (names, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] {
            new DnsResponse { Status = names[0].StartsWith("2.", StringComparison.Ordinal) ? DnsResponseCode.ServerFailure : DnsResponseCode.NXDomain }
        });
        await analysis.AnalyzeDNSBLRecordsMany(failedFirst ? new[] { "192.0.2.2", "192.0.2.1" } : new[] { "192.0.2.1", "192.0.2.2" }, new InternalLogger());
        Assert.Equal("Incomplete", Converters.Convert(analysis).Status);
        Assert.Equal("192.0.2.1", Assert.Single(analysis.Assessments, item => item.Code == DnsblCodes.NotListed).Target);
        Assert.Equal("192.0.2.2", Assert.Single(analysis.Assessments, item => item.Code == DnsblCodes.QueryFailed).Target);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PartialIpv6FailureDoesNotMultiplyWithSuccessfulAnswers(bool reservedErrors) {
        var analysis = Analysis();
        analysis.QueryDnsFullOverride = (_, type) => Task.FromResult<IEnumerable<DnsResponse>>(new[] {
            type == DnsRecordType.A ? new DnsResponse { Answers = new[] {
                new DnsAnswer { Type = type, DataRaw = "127.0.0.2" }, new DnsAnswer { Type = type, DataRaw = "127.0.0.3" }
            }} : reservedErrors ? new DnsResponse { Answers = new[] {
                new DnsAnswer { Type = type, DataRaw = "127.255.255.254" }, new DnsAnswer { Type = type, DataRaw = "127.255.255.255" }
            }} : new DnsResponse { Status = DnsResponseCode.ServerFailure, Error = string.Empty }
        });
        await analysis.AnalyzeDNSBLRecordsMany(new[] { "2001:db8::1" }, new InternalLogger());
        Assert.Equal(2, analysis.Results["2001:db8::1"].Listed);
        Assert.Equal(1, analysis.Results["2001:db8::1"].NotChecked);
        Assert.All(analysis.AllResults.Where(item => item.IsBlackListed), item => Assert.True(item.QuerySucceeded));
        var failure = Assert.Single(analysis.AllResults, item => !item.QuerySucceeded);
        Assert.Contains("AAAA:", failure.Error);
        Assert.Contains(reservedErrors ? "127.255." : "ServerFailure", failure.Error);
        Assert.Single(analysis.Assessments, item => item.Code == DnsblCodes.QueryFailed);
    }

    [Fact]
    public async Task InfiniteAnalysisBudgetAllowsDiscoveryAndProviderQueries() {
        using var health = new DomainHealthCheck();
        var analysis = health.DNSBLAnalysis;
        analysis.AnalysisTimeout = Timeout.InfiniteTimeSpan;
        analysis.ProviderTimeout = Timeout.InfiniteTimeSpan;
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        health.DnsConfiguration.QueryDnsResponseOverride = (_, type, _) => Task.FromResult(new DnsResponse {
            Answers = type == DnsRecordType.A ? new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" } } : Array.Empty<DnsAnswer>()
        });
        analysis.QueryDnsFullOverride = (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] { new DnsResponse { Status = DnsResponseCode.NXDomain } });
        await health.VerifyDNSBLWithMode("example.test", DomainIpScanMode.ApexAOnly);
        Assert.True(analysis.DiscoverySucceeded);
        Assert.True(analysis.Results.ContainsKey("192.0.2.1"));
        Assert.All(analysis.AllResults, item => Assert.True(item.QuerySucceeded));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InfiniteAnalysisBudgetRetainsProviderAndCallerCancellation(bool infiniteProvider) {
        var analysis = Analysis();
        analysis.AnalysisTimeout = Timeout.InfiniteTimeSpan;
        analysis.ProviderTimeout = infiniteProvider ? Timeout.InfiniteTimeSpan : TimeSpan.FromMilliseconds(100);
        var pending = new TaskCompletionSource<IEnumerable<DnsResponse>>(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        analysis.QueryDnsFullOverride = (_, _) => { entered.TrySetResult(true); return pending.Task; };
        using var caller = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try {
            var run = analysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.1" }, new InternalLogger(), true, caller.Token);
            await Task.WhenAny(entered.Task, run);
            Assert.True(entered.Task.IsCompleted, "An infinite analysis budget must permit the provider query to start.");
            if (infiniteProvider) { caller.Cancel(); await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run); }
            else { await run; Assert.False(caller.IsCancellationRequested); Assert.False(Assert.Single(analysis.AllResults).QuerySucceeded); }
        } finally { pending.TrySetResult(Array.Empty<DnsResponse>()); }
    }

    [Fact]
    public async Task FailedDiscoveryRetainsDnsStatusWhenErrorIsEmpty() {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) => Task.FromResult(new DnsResponse { Status = DnsResponseCode.ServerFailure, Error = string.Empty });
        await health.DNSBLAnalysis.AnalyzeDNSBLRecordsMX("example.test", new InternalLogger(), scanMode: DomainIpScanMode.ApexAOnly);
        Assert.Contains("ServerFailure", Assert.Single(health.DNSBLAnalysis.DiscoveryErrors));
    }
}
