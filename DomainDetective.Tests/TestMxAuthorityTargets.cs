using DnsClientX;

namespace DomainDetective.Tests;

public class TestMxAuthorityTargets {
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExternalAndDelegatedMxOwnersUseTheirOwnAuthorities(bool childZone) {
        var analysis = new MXAnalysis();
        string targetZone = childZone ? "mail.example.test" : "provider.test";
        string target = "mx." + targetZone;
        var nsQueries = new List<string>();
        analysis.DnsConfiguration.QueryDnsResponseOverride = (owner, type, _) => {
            if (type == DnsRecordType.SOA) { return Task.FromResult(new DnsResponse {
                Authorities = new[] { new DnsAnswer { Type = type, Name = owner == "example.test" ? "example.test" : targetZone } }
            }); }
            if (type == DnsRecordType.NS) {
                lock (nsQueries) { nsQueries.Add(owner); }
                return Task.FromResult(new DnsResponse { Answers = new[] { new DnsAnswer { Type = type, DataRaw = "ns." + owner } } });
            }
            return Task.FromResult(new DnsResponse { Answers = type == DnsRecordType.A
                ? new[] { new DnsAnswer { Type = type, DataRaw = owner == "ns.example.test" ? "192.0.2.1" : "192.0.2.2" } }
                : Array.Empty<DnsAnswer>() });
        };
        var result = await analysis.DiscoverComparisonAuthoritiesAsync("example.test", new[] { target, "backup." + targetZone });
        Assert.Equal("192.0.2.1", Assert.Single(result["example.test"].Addresses));
        Assert.Equal("192.0.2.2", Assert.Single(result[target].Addresses));
        Assert.Equal(result[target].Addresses, result["backup." + targetZone].Addresses);
        Assert.False(result[target].Incomplete);
        Assert.Equal(1, nsQueries.Count(zone => zone == targetZone));
        Assert.DoesNotContain(target, nsQueries);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ClosestEnclosingSoaIsSelectedFromAnswersAndAuthority(bool answerSection) {
        var analysis = new MXAnalysis();
        var soa = new[] {
            new DnsAnswer { Type = DnsRecordType.SOA, Name = "test" },
            new DnsAnswer { Type = DnsRecordType.SOA, Name = "provider.test." },
            new DnsAnswer { Type = DnsRecordType.SOA, Name = "notprovider.test" }
        };
        analysis.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) => Task.FromResult(new DnsResponse {
            Answers = answerSection ? soa : Array.Empty<DnsAnswer>(), Authorities = answerSection ? Array.Empty<DnsAnswer>() : soa
        });
        Assert.Equal("provider.test", await analysis.FindAuthoritativeZoneAsync("MX.Provider.Test."));
    }

    [Theory]
    [InlineData(DnsResponseCode.NoError)]
    [InlineData(DnsResponseCode.ServerFailure)]
    public async Task MissingOrFailedZoneDiscoveryDoesNotBorrowTheSubjectServers(DnsResponseCode status) {
        var analysis = new MXAnalysis();
        analysis.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) => Task.FromResult(new DnsResponse {
            Status = status, Authorities = new[] { new DnsAnswer { Type = DnsRecordType.SOA, Name = "unrelated.test" } }
        });
        var plan = await analysis.DiscoverComparisonAuthoritiesAsync("example.test", new[] { "mx.provider.test" });
        Assert.All(plan.Values, evidence => { Assert.Empty(evidence.Addresses); Assert.True(evidence.Incomplete); });
    }

    [Fact]
    public void IncompleteTargetDiscoverySurvivesSuccessfulAuthoritativeReplies() {
        var analysis = new MXAnalysis();
        var reply = new DnsResponse { IsAuthoritativeAnswer = true };
        analysis.RecordTargetAddressEvidence("mx.provider.test", new[] { (A: (DnsResponse?)reply, Aaaa: (DnsResponse?)reply) }, new InternalLogger(), discoveryIncomplete: true);
        Assert.True(analysis.TargetAddressComparisonIncomplete);
        Assert.Single(analysis.Assessments, item => item.Code == "MX.TargetAddress.ComparisonIncomplete");
    }
}
