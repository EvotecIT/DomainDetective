using System.Net.Sockets;
using DnsClientX;
using DomainDetective.DesiredState;
using DomainDetective.Narratives;

namespace DomainDetective.Tests;

public class TestNsPhaseEvidence {
    [Fact]
    public async Task ParentFailureRetainsConfirmedChildPolicyFindings() {
        using var health = CreateHealth();
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(Response(name, type, noAddresses: true));
        health.NSAnalysis.QueryDnsFullOverride = (_, _) => throw new TimeoutException("Parent unavailable");
        await health.VerifyDelegation("example.com");
        var result = Evaluate(health, new DesiredStateNsPolicy {
            RequireRecord = true, RequireAllHaveAOrAaaa = true, RequireDiversity = true, MinAsnDiversity = 2
        });
        Assert.True(health.NSAnalysis.DnsQueryFailed);
        Assert.False(health.NSAnalysis.ChildDnsQueryFailed);
        var view = Views.Converters.Convert(health.NSAnalysis);
        Assert.True(view.AddressResultKnown);
        Assert.True(view.CnameResultKnown);
        Assert.True(view.DiversityResultKnown);
        Assert.Contains(result.Assessments, item => item.Code == DesiredStateCodes.NsMissingAddress);
        Assert.Contains(result.Assessments, item => item.Code == DesiredStateCodes.NsDiversityRequired);
        Assert.Contains(result.Assessments, item => item.Code == DesiredStateCodes.NsAsnDiversityTooLow);
        Assert.DoesNotContain(result.Assessments, item => item.Code == DesiredStateCodes.NsEvidenceIncomplete);
        Assert.Contains(NSNarrative.Build(health.NSAnalysis).Highlights, text => text.Contains("lack A/AAAA"));
    }

    [Theory]
    [InlineData("cname")]
    [InlineData("a-with-aaaa")]
    public async Task UnrelatedChildQueryFailureDoesNotInvalidateKnownRequestedFacts(string failed) {
        using var health = CreateHealth();
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(
            type == (failed == "cname" ? DnsRecordType.CNAME : DnsRecordType.A)
                ? new DnsResponse { Status = DnsResponseCode.ServerFailure }
                : failed == "a-with-aaaa" && type == DnsRecordType.AAAA
                    ? new DnsResponse { Answers = new[] { new DnsAnswer { Name = name, Type = type, DataRaw = "2001:db8::1" } } }
                    : Response(name, type));
        await health.VerifyNS("example.com");
        var result = Evaluate(health, new DesiredStateNsPolicy { RequireRecord = true, RequireAllHaveAOrAaaa = true, DisallowCnameTargets = false });
        Assert.True(health.NSAnalysis.DnsQueryFailed);
        Assert.True(health.NSAnalysis.AllHaveAOrAaaa);
        Assert.True(result.Conforms);
        Assert.DoesNotContain(result.Assessments, item => item.Code == DesiredStateCodes.NsEvidenceIncomplete);
    }

    [Fact]
    public async Task ConfirmedMissingHostSurvivesAnotherHostsFailedAddressQuery() {
        using var health = CreateHealth();
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(
            name == "ns2.provider.test" && type == DnsRecordType.A
                ? new DnsResponse { Status = DnsResponseCode.ServerFailure } : Response(name, type, noAddresses: true));
        await health.VerifyNS("example.com");
        var result = Evaluate(health, new DesiredStateNsPolicy { RequireAllHaveAOrAaaa = true });
        Assert.True(health.NSAnalysis.DnsQueryFailed);
        Assert.Contains(health.NSAnalysis.Assessments, item => item.Code == NSCodes.MissingAddressRecords && item.Target == "ns1.provider.test");
        Assert.Contains(result.Assessments, item => item.Code == DesiredStateCodes.NsMissingAddress);
        Assert.DoesNotContain(result.Assessments, item => item.Code == DesiredStateCodes.NsEvidenceIncomplete);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnavailableAsnEnrichmentDoesNotInventLowAsnDiversity(bool partial) {
        using var health = CreateHealth();
        health.NSAnalysis.LookupAsnOverride = ip => Task.FromResult<int?>(partial && ip.EndsWith("53", StringComparison.Ordinal) ? 64500 : null);
        await health.VerifyNS("example.com");
        Assert.True(Evaluate(health, new DesiredStateNsPolicy { RequireRecord = true }).Conforms);
        var result = Evaluate(health, new DesiredStateNsPolicy { MinAsnDiversity = 2 });
        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, item => item.Code == DesiredStateCodes.NsEvidenceIncomplete);
        Assert.DoesNotContain(result.Assessments, item => item.Code == DesiredStateCodes.NsAsnDiversityTooLow);
        Assert.False(health.NSAnalysis.AsnDiversityComplete);
        if (partial) { Assert.True(Evaluate(health, new DesiredStateNsPolicy { MinAsnDiversity = 1 }).Conforms); }
    }

    [Theory]
    [InlineData("socket", false)]
    [InlineData("io", false)]
    [InlineData("canceled", false)]
    [InlineData("socket", true)]
    public async Task UnavailableParentTransportDoesNotCancelUsableSibling(string failure, bool allFail) {
        using var health = CreateHealth();
        health.NSAnalysis.QueryResponseOverride = (server, query, _) => {
            if (allFail || server.ToString() == "192.0.2.53") { throw TransportFailure(failure); }
            return Task.FromResult<DnsResponse?>(new DnsResponse {
                Authorities = new[] { "ns1.provider.test", "ns2.provider.test" }
                    .Select(name => new DnsAnswer { Name = query.Name, Type = DnsRecordType.NS, DataRaw = name }).ToArray()
            });
        };
        await health.VerifyDelegation("example.com");
        Assert.True(health.NSAnalysis.NsLookupComplete);
        Assert.Equal(!allFail, health.NSAnalysis.DelegationAnalysisComplete);
        Assert.Equal(allFail, health.NSAnalysis.DnsQueryFailed);
        if (!allFail) {
            Assert.Equal("192.0.2.54", health.NSAnalysis.ParentAuthorityServer);
            Assert.True(health.NSAnalysis.DelegationMatches);
        } else { Assert.Empty(health.NSAnalysis.ParentNsRecords); }
    }

    [Theory]
    [InlineData("child")]
    [InlineData("parent-full")]
    public async Task ExpectedTransportFailuresRemainIncompleteAtOtherNsBoundaries(string phase) {
        using var health = CreateHealth();
        if (phase == "child") {
            health.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) => throw new SocketException((int)SocketError.NetworkUnreachable);
        } else { health.NSAnalysis.QueryDnsFullOverride = (_, _) => throw new System.IO.IOException("No DNS transport"); }
        await health.VerifyDelegation("example.com");
        Assert.True(health.NSAnalysis.DnsQueryFailed);
        Assert.Equal(phase != "child", health.NSAnalysis.NsLookupComplete);
        Assert.False(health.NSAnalysis.DelegationAnalysisComplete);
    }

    [Fact]
    public async Task ParentTransportProgrammingFailureStillPropagates() {
        using var health = CreateHealth();
        health.NSAnalysis.QueryResponseOverride = (_, _, _) => throw new InvalidOperationException("Invalid custom transport state");
        await Assert.ThrowsAsync<InvalidOperationException>(() => health.VerifyDelegation("example.com"));
    }

    [Theory]
    [InlineData("child")]
    [InlineData("parent-full")]
    [InlineData("parent-direct")]
    public async Task TransportFailureCannotReplaceCallerCancellation(string phase) {
        using var health = CreateHealth();
        using var caller = new CancellationTokenSource();
        Exception CancelAndFail() {
            caller.Cancel();
            return new SocketException((int)SocketError.OperationAborted);
        }
        if (phase == "child") { health.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) => throw CancelAndFail(); }
        else if (phase == "parent-full") { health.NSAnalysis.QueryDnsFullOverride = (_, _) => throw CancelAndFail(); }
        else { health.NSAnalysis.QueryResponseOverride = (_, _, _) => throw CancelAndFail(); }
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => health.VerifyDelegation("example.com", caller.Token));
    }

    private static Exception TransportFailure(string name) => name == "socket"
        ? new SocketException((int)SocketError.NetworkUnreachable)
        : name == "io" ? new System.IO.IOException("No DNS transport") : new OperationCanceledException("Transport-local timeout");

    private static DesiredStateAnalysis Evaluate(DomainHealthCheck health, DesiredStateNsPolicy policy) =>
        DesiredStateEvaluator.Evaluate("example.com", health, new DesiredStateProfile { Ns = policy });

    private static DomainHealthCheck CreateHealth() {
        var health = new DomainHealthCheck();
        health.NSAnalysis.EnableChaosFingerprinting = false;
        health.NSAnalysis.LookupAsnOverride = _ => Task.FromResult<int?>(64500);
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(Response(name, type));
        return health;
    }

    private static DnsResponse Response(string owner, DnsRecordType type, bool noAddresses = false) => new() {
        Answers = type == DnsRecordType.NS ? new[] { "ns1.provider.test", "ns2.provider.test" }
                .Select(name => new DnsAnswer { Name = owner, Type = type, DataRaw = name }).ToArray()
            : type == DnsRecordType.SOA ? new[] { new DnsAnswer { Name = owner, Type = type, DataRaw = "ns1.provider.test hostmaster.provider.test 1 2 3 4 5" } }
            : type == DnsRecordType.A && !noAddresses ? new[] { "192.0.2.53", "192.0.2.54" }
                .Select(ip => new DnsAnswer { Name = owner, Type = type, DataRaw = ip }).ToArray() : Array.Empty<DnsAnswer>()
    };
}
