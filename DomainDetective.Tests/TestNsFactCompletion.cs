using DnsClientX;
using DomainDetective.DesiredState;
using DomainDetective.Narratives;
using DomainDetective.Views;

namespace DomainDetective.Tests;

public class TestNsFactCompletion {
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OverviewsAndPositiveAssessmentQualifyIncompleteAsnCounts(bool partial) {
        using var health = CreateHealth();
        health.NSAnalysis.LookupAsnOverride = ip => Task.FromResult<int?>(partial && ip == "192.0.2.53" ? 64500 : null);
        await health.VerifyNS("example.com");
        Assert.True(health.NSAnalysis.HasDiverseLocations);
        Assert.False(health.NSAnalysis.AsnDiversityComplete);
        string qualifier = partial ? "partial" : "unverified";
        var domain = Converters.ConvertDomainOverview(health, "example.com").MailDnsChecks.Single(item => item.Key == "ns");
        var tenant = Converters.ConvertMicrosoft365Overview(health, "example.com").MailDnsChecks.Single(item => item.Key == "ns");
        Assert.All(new[] { domain, tenant }, item => Assert.Contains(qualifier, item.Detail));
        Assert.Contains(qualifier, Assert.Single(health.NSAnalysis.Assessments, item => item.Code == NSCodes.HighDiversity).Message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConfirmedGlueDefectSurvivesAnotherHostsUnavailableComparison(bool mismatch) {
        using var health = CreateHealth();
        await health.VerifyNS("example.com");
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(
            name == "ns2.example.com" && type == DnsRecordType.A
                ? new DnsResponse { Status = DnsResponseCode.ServerFailure } : Response(name, type));
        health.NSAnalysis.QueryDnsFullOverride = (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] { ParentResponse(mismatch ? "203.0.113.99" : null) });
        await health.NSAnalysis.AnalyzeParentDelegation("example.com", new InternalLogger());
        Assert.False(health.NSAnalysis.DelegationAnalysisComplete);
        Assert.Contains(health.NSAnalysis.Assessments, item => item.Code == (mismatch ? NSCodes.GlueInconsistent : NSCodes.GlueIncomplete));
        var desired = new DesiredStateDelegationPolicy {
            RequireMatchesParent = false, RequireGlueComplete = !mismatch, RequireGlueConsistent = mismatch
        };
        var result = DesiredStateEvaluator.Evaluate("example.com", health, new DesiredStateProfile { Delegation = desired });
        Assert.Contains(result.Assessments, item => item.Code == (mismatch
            ? DesiredStateCodes.DelegationGlueInconsistent : DesiredStateCodes.DelegationGlueIncomplete));
        Assert.DoesNotContain(result.Assessments, item => item.Code == DesiredStateCodes.DelegationEvidenceIncomplete);
        Assert.Contains(NSNarrative.Build(health.NSAnalysis).Highlights, text => text.Contains(mismatch ? "differ from child" : "missing glue"));
        var view = Converters.Convert(health.NSAnalysis);
        Assert.True(view.GluePresenceKnown);
        Assert.Equal(mismatch, view.GlueConsistencyKnown);
        Assert.Contains(mismatch ? "/mixed" : "glue incomplete", view.Summary);
    }

    [Fact]
    public async Task NetworkAliasChainRetainsTerminalAddresses() {
        using var health = CreateHealth();
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(type == DnsRecordType.A
            ? new DnsResponse { Answers = new[] {
                Answer(name, DnsRecordType.CNAME, "alias.provider.test"),
                Answer("alias.provider.test", DnsRecordType.A, "192.0.2.53")
            } } : Response(name, type));
        await health.VerifyNS("example.com");
        Assert.True(health.NSAnalysis.AllHaveAOrAaaa);
        Assert.True(health.NSAnalysis.AddressResultKnown);
        Assert.Contains("192.0.2.53", health.NSAnalysis.AsnByIp.Keys);
    }

    [Fact]
    public async Task UnusedParentAddressFailureDoesNotInvalidateSuccessfulGlueComparisons() {
        using var health = CreateHealth();
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(
            name == "parent.provider.test" && type == DnsRecordType.AAAA
                ? new DnsResponse { Status = DnsResponseCode.ServerFailure }
                : name == "com" && type == DnsRecordType.NS
                    ? new DnsResponse { Answers = new[] { Answer(name, type, "parent.provider.test") } }
                    : type == DnsRecordType.SOA
                        ? new DnsResponse { Answers = new[] { Answer("com", type, "parent.provider.test hostmaster.provider.test 1 2 3 4 5") } }
                        : Response(name, type));
        health.NSAnalysis.QueryResponseOverride = (_, _, _) => Task.FromResult<DnsResponse?>(ParentResponse("192.0.2.53"));
        await health.VerifyDelegation("example.com");
        Assert.True(health.NSAnalysis.DnsQueryFailed);
        Assert.True(health.NSAnalysis.GlueRecordsConsistent);
        Assert.True(health.NSAnalysis.DelegationAnalysisComplete);
        Assert.True(DesiredStateEvaluator.Evaluate("example.com", health, new DesiredStateProfile {
            Delegation = new DesiredStateDelegationPolicy()
        }).Conforms);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task CnameOnlyNetworkAnswerCannotCertifyNsOrAddressPresence(bool root) {
        using var health = CreateHealth();
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(
            root && type == DnsRecordType.NS || !root && type == DnsRecordType.A
                ? new DnsResponse { Answers = new[] { Answer(name, DnsRecordType.CNAME, "absent.provider.test") } }
                : Response(name, type));
        await health.VerifyNS("example.com");
        if (root) { Assert.False(health.NSAnalysis.NsRecordExists); }
        else {
            Assert.False(health.NSAnalysis.AllHaveAOrAaaa);
            Assert.True(health.NSAnalysis.AddressResultKnown);
            var result = DesiredStateEvaluator.Evaluate("example.com", health, new DesiredStateProfile {
                Ns = new DesiredStateNsPolicy { RequireAllHaveAOrAaaa = true, DisallowCnameTargets = false }
            });
            Assert.Contains(result.Assessments, item => item.Code == DesiredStateCodes.NsMissingAddress);
        }
    }

    private static DomainHealthCheck CreateHealth() {
        var health = new DomainHealthCheck();
        health.NSAnalysis.EnableChaosFingerprinting = false;
        health.NSAnalysis.LookupAsnOverride = _ => Task.FromResult<int?>(64500);
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(Response(name, type));
        return health;
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ConfirmedFamilyMismatchSurvivesSameHostsOtherFamilyFailure(bool failedIpv6) {
        using var health = CreateHealth();
        await health.VerifyNS("example.com");
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(name != "ns1.example.com"
            ? Response(name, type)
            : type == (failedIpv6 ? DnsRecordType.AAAA : DnsRecordType.A)
                ? new DnsResponse { Status = DnsResponseCode.ServerFailure }
                : !failedIpv6 && type == DnsRecordType.AAAA
                    ? new DnsResponse { Answers = new[] { Answer(name, type, "2001:db8::53") } }
                    : Response(name, type));
        var parent = ParentResponse(null);
        parent.Additional = parent.Additional.Concat(new[] {
            Answer("ns1.example.com", DnsRecordType.A, failedIpv6 ? "203.0.113.99" : "192.0.2.53"),
            Answer("ns1.example.com", DnsRecordType.AAAA, failedIpv6 ? "2001:db8::53" : "2001:db8:1::53")
        }).ToArray();
        health.NSAnalysis.QueryDnsFullOverride = (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] { parent });
        await health.NSAnalysis.AnalyzeParentDelegation("example.com", new InternalLogger());
        Assert.False(health.NSAnalysis.DelegationAnalysisComplete);
        Assert.Contains(health.NSAnalysis.Assessments, item => item.Code == NSCodes.GlueInconsistent);
        var result = DesiredStateEvaluator.Evaluate("example.com", health, new DesiredStateProfile {
            Delegation = new DesiredStateDelegationPolicy { RequireMatchesParent = false, RequireGlueComplete = false, RequireGlueConsistent = true }
        });
        Assert.Contains(result.Assessments, item => item.Code == DesiredStateCodes.DelegationGlueInconsistent);
        Assert.DoesNotContain(result.Assessments, item => item.Code == DesiredStateCodes.DelegationEvidenceIncomplete);
        Assert.Contains("/mixed", Converters.Convert(health.NSAnalysis).Summary);
    }

    private static DnsResponse Response(string name, DnsRecordType type) => new() {
        Answers = type == DnsRecordType.NS ? new[] { Answer(name, type, "ns1.example.com"), Answer(name, type, "ns2.example.com") }
            : type == DnsRecordType.A ? new[] { Answer(name, type, name == "ns2.example.com" ? "198.51.100.54" : "192.0.2.53") }
            : Array.Empty<DnsAnswer>()
    };

    private static DnsResponse ParentResponse(string? firstGlue) => new() {
        Authorities = new[] { Answer("example.com", DnsRecordType.NS, "ns1.example.com"), Answer("example.com", DnsRecordType.NS, "ns2.example.com") },
        Additional = (firstGlue == null ? Array.Empty<DnsAnswer>() : new[] { Answer("ns1.example.com", DnsRecordType.A, firstGlue) })
            .Concat(new[] { Answer("ns2.example.com", DnsRecordType.A, "198.51.100.54") }).ToArray()
    };

    private static DnsAnswer Answer(string name, DnsRecordType type, string data) => new() { Name = name, Type = type, DataRaw = data };
}
