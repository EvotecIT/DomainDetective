using DnsClientX;
using DomainDetective.Narratives;
using DomainDetective.Views;

namespace DomainDetective.Tests;

public class TestNsEvidenceCompleteness {
    [Theory]
    [InlineData("example.com", "ns")]
    [InlineData("co.uk", "run")]
    [InlineData("example.com", "delegation")]
    [InlineData("co.uk", "combined")]
    public async Task FailedLookupIsUnknownAndAReusedInstanceRecovers(string domain, string route) {
        using var health = new DomainHealthCheck();
        Configure(health.NSAnalysis);
        bool failed = false;
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(
            failed && type == DnsRecordType.NS
                ? new DnsResponse { Status = DnsResponseCode.ServerFailure }
                : Response(name, type));
        await health.Verify(domain, new[] { HealthCheckType.NS, HealthCheckType.DELEGATION });
        Assert.NotEmpty(health.NSAnalysis.ParentNsRecords);
        failed = true;
        if (route == "ns") { await health.VerifyNS(domain); }
        else if (route == "delegation") { await health.VerifyDelegation(domain); }
        else { await health.Verify(domain, route == "combined"
            ? new[] { HealthCheckType.NS, HealthCheckType.DELEGATION } : new[] { HealthCheckType.NS }); }
        var analysis = health.NSAnalysis;
        Assert.Empty(analysis.NsRecords);
        Assert.Empty(analysis.ParentNsRecords);
        Assert.False(analysis.GlueRecordsComplete);
        Assert.False(analysis.GlueRecordsConsistent);
        Assert.Contains(analysis.Assessments, item => item.Code == "NS.Query.Failed");
        Assert.False(analysis.NsLookupComplete);
        Assert.False(analysis.DelegationAnalysisComplete);
        Assert.Contains(analysis.DnsQueryErrors, error => error.Contains("ServerFailure"));
        Assert.DoesNotContain(analysis.Assessments, item => item.Code == NSCodes.Missing || item.Code == NSCodes.TooFewRecords);
        Assert.Equal("Incomplete", Converters.Convert(analysis).Status);
        Assert.Equal("Unknown", Converters.Convert(analysis).RecordPresence);
        Assert.DoesNotContain(NSNarrative.Build(analysis).Highlights, item => item == "No NS records are published.");
        failed = false;
        await health.Verify(domain, new[] { HealthCheckType.NS, HealthCheckType.DELEGATION });
        Assert.NotEmpty(analysis.NsRecords);
        Assert.True(analysis.GlueRecordsComplete);
        Assert.True(analysis.GlueRecordsConsistent);
        Assert.True(analysis.NsLookupComplete);
        Assert.True(analysis.DelegationAnalysisComplete);
        Assert.False(analysis.DnsQueryFailed);
        Assert.DoesNotContain(analysis.Assessments, item => item.Code == "NS.Query.Failed");
    }

    [Fact]
    public async Task ChildOnlyRefreshLeavesParentGlueUnverifiedUntilParentCheck() {
        using var health = new DomainHealthCheck();
        Configure(health.NSAnalysis);
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(Response(name, type));
        await health.Verify("example.com", new[] { HealthCheckType.NS, HealthCheckType.DELEGATION });
        Assert.True(health.NSAnalysis.GlueRecordsComplete);
        await health.NSAnalysis.AnalyzeNsRecords(new[] { NsAnswer("example.com") }, new InternalLogger());
        Assert.False(health.NSAnalysis.GlueRecordsComplete);
        Assert.False(health.NSAnalysis.GlueRecordsConsistent);
        Assert.Empty(health.NSAnalysis.ParentNsRecords);
        Assert.Contains("unverified", Converters.Convert(health.NSAnalysis).Summary);
        Assert.DoesNotContain(NSNarrative.Build(health.NSAnalysis).Highlights, item => item.StartsWith("Parent zone missing glue", StringComparison.Ordinal));
        await health.NSAnalysis.AnalyzeParentDelegation("example.com", new InternalLogger());
        Assert.True(health.NSAnalysis.GlueRecordsComplete);
        Assert.True(health.NSAnalysis.GlueRecordsConsistent);
    }

    [Fact]
    public async Task ParentFailureRetainsChildEvidenceAndDoesNotClaimConsistentGlue() {
        using var configuration = new DnsConfiguration();
        var analysis = new NSAnalysis { DnsConfiguration = configuration };
        Configure(analysis);
        bool failed = false;
        configuration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(Response(name, type));
        analysis.QueryDnsFullOverride = (name, type) => Task.FromResult<IEnumerable<DnsResponse>>(new[] {
            failed ? new DnsResponse { Status = DnsResponseCode.ServerFailure } : Response(name, type)
        });
        await analysis.AnalyzeNsRecords(new[] { NsAnswer("example.com") }, new InternalLogger());
        await analysis.AnalyzeParentDelegation("example.com", new InternalLogger());
        Assert.True(analysis.GlueRecordsConsistent);
        failed = true;
        await analysis.AnalyzeParentDelegation("example.com", new InternalLogger());
        Assert.Single(analysis.NsRecords);
        Assert.False(analysis.GlueRecordsComplete);
        Assert.False(analysis.GlueRecordsConsistent);
        Assert.Contains(analysis.Assessments, item => item.Code == "NS.Query.Failed");
        Assert.Equal("Incomplete", Converters.Convert(analysis).Status);
        failed = false;
        await analysis.AnalyzeParentDelegation("example.com", new InternalLogger());
        Assert.True(analysis.GlueRecordsComplete);
        Assert.True(analysis.GlueRecordsConsistent);
        Assert.DoesNotContain(analysis.Assessments, item => item.Code == "NS.Query.Failed");
    }

    [Fact]
    public async Task FailedAddressQueriesRetainNsWithoutClaimingMissingAddresses() {
        using var health = new DomainHealthCheck();
        Configure(health.NSAnalysis);
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(
            type == DnsRecordType.A || type == DnsRecordType.AAAA
                ? new DnsResponse { Status = DnsResponseCode.ServerFailure } : Response(name, type));
        await health.VerifyNS("example.com");
        Assert.Single(health.NSAnalysis.NsRecords);
        Assert.Contains(health.NSAnalysis.Assessments, item => item.Code == "NS.Query.Failed");
        Assert.DoesNotContain(health.NSAnalysis.Assessments, item => item.Code == NSCodes.MissingAddressRecords);
        Assert.DoesNotContain(NSNarrative.Build(health.NSAnalysis).Highlights, item => item == "Some NS hostnames lack A/AAAA addresses.");
        Assert.Equal("Incomplete", Converters.Convert(health.NSAnalysis).Status);
    }

    [Theory]
    [InlineData(DnsResponseCode.NoError)]
    [InlineData(DnsResponseCode.NXDomain)]
    public async Task ConclusiveEmptyLookupStillReportsMissingNs(DnsResponseCode code) {
        using var health = new DomainHealthCheck();
        Configure(health.NSAnalysis);
        health.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) => Task.FromResult(new DnsResponse { Status = code });
        await health.VerifyNS("example.com");
        Assert.True(health.NSAnalysis.NsLookupComplete);
        Assert.False(health.NSAnalysis.DnsQueryFailed);
        Assert.Contains(health.NSAnalysis.Assessments, item => item.Code == NSCodes.Missing);
        Assert.Equal("No", Converters.Convert(health.NSAnalysis).RecordPresence);
    }

    [Fact]
    public async Task CallerCancellationAndTransportTimeoutRemainDistinct() {
        using var health = new DomainHealthCheck();
        Configure(health.NSAnalysis);
        health.DnsConfiguration.QueryDnsResponseOverride = async (_, _, token) => {
            await Task.Delay(Timeout.Infinite, token);
            return new DnsResponse();
        };
        using (var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(50))) {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => health.VerifyNS("example.com", cancel.Token));
        }
        Assert.False(health.NSAnalysis.NsLookupComplete);
        Assert.False(health.NSAnalysis.DnsQueryFailed);
        Assert.Empty(health.NSAnalysis.Assessments);
        health.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) => throw new TimeoutException("synthetic DNS timeout");
        await health.VerifyNS("example.com");
        Assert.True(health.NSAnalysis.DnsQueryFailed);
        Assert.Contains(health.NSAnalysis.DnsQueryErrors, item => item.Contains("synthetic DNS timeout"));
        Assert.Equal("Unknown", Converters.Convert(health.NSAnalysis).RecordPresence);
    }

    [Fact]
    public async Task FailedGlueComparisonIsUnverifiedAndCanRecoverWithoutLosingChildEvidence() {
        using var configuration = new DnsConfiguration();
        var analysis = new NSAnalysis { DnsConfiguration = configuration };
        Configure(analysis);
        bool failed = false;
        configuration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(
            failed && type == DnsRecordType.AAAA ? new DnsResponse { Status = DnsResponseCode.ServerFailure } : Response(name, type));
        var child = new DnsAnswer { Name = "example.com", Type = DnsRecordType.NS, DataRaw = "ns1.example.com" };
        analysis.QueryDnsFullOverride = (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] {
            new DnsResponse { Status = DnsResponseCode.NoError, Answers = new[] { child },
                Additional = new[] { new DnsAnswer { Name = "ns1.example.com", Type = DnsRecordType.A, DataRaw = "192.0.2.1" } } }
        });
        await analysis.AnalyzeNsRecords(new[] { child }, new InternalLogger());
        failed = true;
        await analysis.AnalyzeParentDelegation("example.com", new InternalLogger());
        Assert.Single(analysis.NsRecords);
        Assert.True(analysis.GlueRecordsComplete);
        Assert.False(analysis.GlueRecordsConsistent);
        Assert.False(analysis.DelegationAnalysisComplete);
        Assert.True(analysis.DnsQueryFailed);
        Assert.DoesNotContain(analysis.Assessments, item => item.Code == NSCodes.GlueInconsistent);
        failed = false;
        await analysis.AnalyzeParentDelegation("example.com", new InternalLogger());
        Assert.True(analysis.DelegationAnalysisComplete);
        Assert.True(analysis.GlueRecordsConsistent);
        Assert.False(analysis.DnsQueryFailed);
        Assert.DoesNotContain(analysis.Assessments, item => item.Code == NSCodes.QueryFailed);
    }

    private static void Configure(NSAnalysis analysis) {
        analysis.EnableChaosFingerprinting = false;
        analysis.LookupAsnOverride = _ => Task.FromResult<int?>(null);
    }

    private static DnsAnswer NsAnswer(string name) => new() { Name = name, Type = DnsRecordType.NS, DataRaw = "ns1.example.test" };

    private static DnsResponse Response(string name, DnsRecordType type) => new() {
        Status = DnsResponseCode.NoError,
        Answers = type == DnsRecordType.NS ? new[] { NsAnswer(name) }
            : type == DnsRecordType.A ? new[] { new DnsAnswer { Name = name, Type = type, DataRaw = "192.0.2.1" } }
            : Array.Empty<DnsAnswer>()
    };
}
