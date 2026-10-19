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

    [Theory]
    [InlineData(DnsRecordType.SOA, false)]
    [InlineData(DnsRecordType.SOA, true)]
    [InlineData(DnsRecordType.NS, false)]
    [InlineData(DnsRecordType.NS, true)]
    [InlineData(DnsRecordType.A, false)]
    [InlineData(DnsRecordType.A, true)]
    [InlineData(DnsRecordType.AAAA, false)]
    [InlineData(DnsRecordType.AAAA, true)]
    public async Task TransportFailureRetainsOtherOwnersAndKnownAuthorityAddresses(DnsRecordType failingType, bool httpFailure) {
        var analysis = new MXAnalysis();
        analysis.DnsConfiguration.QueryDnsResponseOverride = (owner, type, _) => {
            if (owner.EndsWith("other.test", StringComparison.Ordinal) && type == failingType) {
                throw httpFailure ? new System.Net.Http.HttpRequestException("Synthetic transport failure")
                    : new System.IO.IOException("Synthetic transport failure");
            }
            string zone = owner.EndsWith("other.test", StringComparison.Ordinal) ? "other.test" : "example.test";
            DnsAnswer[] answers = type == DnsRecordType.SOA ? new[] { new DnsAnswer { Type = type, Name = zone } }
                : type == DnsRecordType.NS ? new[] { new DnsAnswer { Type = type, DataRaw = "ns." + zone } }
                : type == DnsRecordType.A ? new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" } }
                : type == DnsRecordType.AAAA ? new[] { new DnsAnswer { Type = type, DataRaw = "2001:db8::1" } }
                : Array.Empty<DnsAnswer>();
            return Task.FromResult(new DnsResponse { Answers = answers });
        };
        var plan = await analysis.DiscoverComparisonAuthoritiesAsync("example.test", new[] { "mx.example.test", "mx.other.test" });
        Assert.False(plan["example.test"].Incomplete);
        Assert.Equal(new[] { "192.0.2.1", "2001:db8::1" }, plan["mx.example.test"].Addresses.OrderBy(value => value));
        var affected = plan["mx.other.test"];
        Assert.True(affected.Incomplete);
        if (failingType == DnsRecordType.A) { Assert.Equal("2001:db8::1", Assert.Single(affected.Addresses)); }
        else if (failingType == DnsRecordType.AAAA) { Assert.Equal("192.0.2.1", Assert.Single(affected.Addresses)); }
        else { Assert.Empty(affected.Addresses); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AliasTransportFailureRetainsHealthySiblingEvidence(bool httpFailure) {
        var analysis = new MXAnalysis();
        analysis.DnsConfiguration.QueryDnsResponseOverride = (owner, type, _) => {
            if (owner == "unavailable.example.test" && type == DnsRecordType.CNAME) {
                throw httpFailure ? new System.Net.Http.HttpRequestException("Synthetic transport failure")
                    : new System.IO.IOException("Synthetic transport failure");
            }
            var answers = type == DnsRecordType.CNAME
                ? new[] { new DnsAnswer { Type = type, DataRaw = "alias.example.test" } }
                : type == DnsRecordType.A ? new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" } }
                : Array.Empty<DnsAnswer>();
            return Task.FromResult(new DnsResponse { Answers = answers });
        };
        await analysis.AnalyzeMxRecords(new[] {
            new DnsAnswer { Type = DnsRecordType.MX, DataRaw = "10 unavailable.example.test" },
            new DnsAnswer { Type = DnsRecordType.MX, DataRaw = "20 healthy.example.test" }
        }, new InternalLogger());
        Assert.True(analysis.CnameQueryFailed);
        Assert.True(analysis.PointsToCname);
        Assert.False(analysis.AddressQueryFailed);
        Assert.Contains(analysis.Assessments, item => item.Code == "MX.Cname.QueryFailed");
        Assert.Contains(analysis.Assessments, item => item.Code == "MX.CNAME.Target");
    }
}
