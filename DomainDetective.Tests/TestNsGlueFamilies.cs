using DnsClientX;
using DomainDetective.DesiredState;
using DomainDetective.Views;

namespace DomainDetective.Tests;

public class TestNsGlueFamilies {
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task MatchingSingleFamilyGlueDoesNotRequireTheOtherChildFamily(bool ipv6Glue, bool unusedFamilyFails) {
        using var health = CreateHealth();
        await health.VerifyNS("example.com");
        var queries = new System.Collections.Concurrent.ConcurrentQueue<DnsRecordType>();
        var requiredType = ipv6Glue ? DnsRecordType.AAAA : DnsRecordType.A;
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => {
            queries.Enqueue(type);
            return Task.FromResult(unusedFamilyFails && type != requiredType
                ? new DnsResponse { Status = DnsResponseCode.ServerFailure } : ChildResponse(name, type));
        };
        health.NSAnalysis.QueryDnsFullOverride = (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] { ParentResponse(requiredType) });
        await health.NSAnalysis.AnalyzeParentDelegation("example.com", new InternalLogger());
        Assert.True(health.NSAnalysis.GlueRecordsComplete);
        Assert.True(health.NSAnalysis.GlueRecordsConsistent);
        Assert.True(health.NSAnalysis.GlueConsistencyKnown);
        Assert.True(health.NSAnalysis.DelegationAnalysisComplete);
        Assert.False(health.NSAnalysis.DnsQueryFailed);
        Assert.Equal(new[] { requiredType }, queries.ToArray());
        Assert.DoesNotContain(health.NSAnalysis.Assessments, item => item.Code == NSCodes.GlueInconsistent);
        Assert.Contains("glue complete/consistent", Converters.Convert(health.NSAnalysis).Summary);
        Assert.True(Evaluate(health).Conforms);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AdvertisedFamilyFailureStillLeavesConsistencyUnknown(bool ipv6Glue) {
        using var health = CreateHealth();
        await health.VerifyNS("example.com");
        var requiredType = ipv6Glue ? DnsRecordType.AAAA : DnsRecordType.A;
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(type == requiredType
            ? new DnsResponse { Status = DnsResponseCode.ServerFailure } : ChildResponse(name, type));
        health.NSAnalysis.QueryDnsFullOverride = (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] { ParentResponse(requiredType) });
        await health.NSAnalysis.AnalyzeParentDelegation("example.com", new InternalLogger());
        Assert.True(health.NSAnalysis.GlueRecordsComplete);
        Assert.False(health.NSAnalysis.GlueConsistencyKnown);
        Assert.False(health.NSAnalysis.DelegationAnalysisComplete);
        Assert.True(health.NSAnalysis.DnsQueryFailed);
        var result = Evaluate(health);
        Assert.Contains(result.Assessments, item => item.Code == DesiredStateCodes.DelegationEvidenceIncomplete);
        Assert.DoesNotContain(result.Assessments, item => item.Code == DesiredStateCodes.DelegationGlueInconsistent);
    }

    private static DesiredStateAnalysis Evaluate(DomainHealthCheck health) => DesiredStateEvaluator.Evaluate("example.com", health,
        new DesiredStateProfile { Delegation = new DesiredStateDelegationPolicy() });

    private static DomainHealthCheck CreateHealth() {
        var health = new DomainHealthCheck();
        health.NSAnalysis.EnableChaosFingerprinting = false;
        health.NSAnalysis.LookupAsnOverride = _ => Task.FromResult<int?>(64500);
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(ChildResponse(name, type));
        return health;
    }

    private static DnsResponse ChildResponse(string name, DnsRecordType type) => new() {
        Answers = type == DnsRecordType.NS ? new[] { Answer(name, type, "ns1.example.com") }
            : type == DnsRecordType.A ? new[] { Answer(name, type, "192.0.2.53") }
            : type == DnsRecordType.AAAA ? new[] { Answer(name, type, "2001:db8::53") } : Array.Empty<DnsAnswer>()
    };

    private static DnsResponse ParentResponse(DnsRecordType type) => new() {
        Authorities = new[] { Answer("example.com", DnsRecordType.NS, "ns1.example.com") },
        Additional = new[] { Answer("ns1.example.com", type, type == DnsRecordType.A ? "192.0.2.53" : "2001:db8::53") }
    };

    private static DnsAnswer Answer(string name, DnsRecordType type, string data) => new() { Name = name, Type = type, DataRaw = data };
}
