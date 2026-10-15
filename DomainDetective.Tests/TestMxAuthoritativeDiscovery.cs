using DnsClientX;

namespace DomainDetective.Tests;

public class TestMxAuthoritativeDiscovery {
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task RecursiveAliasAnswersDoNotClaimAddressFamilies(bool legacyOverride, bool terminalAddress) {
        using var health = new DomainHealthCheck();
        DnsAnswer[] Answers(DnsRecordType type) {
            if (type == DnsRecordType.NS) { return Array.Empty<DnsAnswer>(); }
            var answers = new List<DnsAnswer> { new() { Type = DnsRecordType.CNAME, DataRaw = "alias.example.test" } };
            if (type == DnsRecordType.A && terminalAddress) { answers.Add(new DnsAnswer { Type = type, DataRaw = "192.0.2.1" }); }
            return answers.ToArray();
        }
        if (legacyOverride) { health.MXAnalysis.QueryDnsOverride = (_, type) => Task.FromResult(Answers(type)); }
        else { health.DnsConfiguration.QueryDnsResponseOverride = (_, type, _) => Task.FromResult(new DnsResponse { Answers = Answers(type) }); }
        health.MXAnalysis.Subject = "example.test";
        await health.MXAnalysis.AnalyzeMxRecords(new[] { new DnsAnswer { Type = DnsRecordType.MX, DataRaw = "10 mail.example.test" } }, new InternalLogger());
        Assert.False(health.MXAnalysis.Ipv6Supported);
        Assert.False(health.MXAnalysis.AddressQueryFailed);
        Assert.Equal(!terminalAddress, health.MXAnalysis.PointsToDomainWithoutAOrAaaaRecord);
        Assert.True(health.MXAnalysis.PointsToCname);
    }

    [Theory]
    [InlineData(DnsResponseCode.NoError, false)]
    [InlineData(DnsResponseCode.NoError, true)]
    [InlineData(DnsResponseCode.NXDomain, false)]
    [InlineData(DnsResponseCode.NXDomain, true)]
    public void NonAuthoritativeRepliesCannotCompleteAddressComparison(DnsResponseCode status, bool authoritative) {
        using var health = new DomainHealthCheck();
        var response = new DnsResponse { Status = status, IsAuthoritativeAnswer = authoritative };
        Assert.True(Helpers.AuthoritativeDnsProbes.IsUsableResponse(response));
        Assert.Equal(authoritative, Helpers.AuthoritativeDnsProbes.IsAuthoritativeResponse(response));
        health.MXAnalysis.RecordTargetAddressEvidence("mail.example.test", new[] { (A: (DnsResponse?)response, Aaaa: (DnsResponse?)response) }, new InternalLogger());
        Assert.Equal(!authoritative, health.MXAnalysis.TargetAddressComparisonIncomplete);
        var profile = new DesiredState.DesiredStateProfile { Mx = new DesiredState.DesiredStateMxPolicy { RequireRecord = false, RequireTargetAddressConsistentAcrossNs = true } };
        Assert.Equal(authoritative, DesiredState.DesiredStateEvaluator.Evaluate("example.test", health, profile).Conforms);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnresolvedPublishedServerPreventsCompleteComparison(bool throws) {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsResponseOverride = (owner, type, _) => {
            if (type == DnsRecordType.NS) { return Task.FromResult(new DnsResponse { Answers = new[] {
                new DnsAnswer { Type = type, DataRaw = "ns1.example.test" }, new DnsAnswer { Type = type, DataRaw = "ns2.example.test" }
            }}); }
            if (owner == "ns2.example.test") {
                if (throws) { throw new DnsClientException("Unusable DNS reply."); }
                return Task.FromResult(new DnsResponse { Status = DnsResponseCode.ServerFailure });
            }
            return Task.FromResult(new DnsResponse { Answers = type == DnsRecordType.A
                ? new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" } } : Array.Empty<DnsAnswer>() });
        };
        var discovery = await health.MXAnalysis.DiscoverAuthoritativeServersAsync("example.test");
        Assert.Equal("192.0.2.1", Assert.Single(discovery.Addresses));
        Assert.True(discovery.Incomplete);
        health.MXAnalysis.RecordRrsetCompleteness(1, 1, "example.test", new InternalLogger(), discoveryIncomplete: discovery.Incomplete);
        Assert.True(health.MXAnalysis.MxRrsetComparisonIncomplete);
        Assert.Single(health.MXAnalysis.Assessments, item => item.Code == "MX.Rrset.ComparisonIncomplete");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EmptyOrFailedDiscoveryRemainsIncompleteThroughThePublicScan(bool failed) {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsResponseOverride = (_, type, _) => Task.FromResult(new DnsResponse {
            Status = type == DnsRecordType.NS && failed ? DnsResponseCode.ServerFailure : DnsResponseCode.NoError,
            Answers = type == DnsRecordType.A ? new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" } } : Array.Empty<DnsAnswer>()
        });
        health.MXAnalysis.Subject = "example.test";
        await health.MXAnalysis.AnalyzeMxRecords(new[] { new DnsAnswer { Type = DnsRecordType.MX, DataRaw = "10 mail.example.test" } }, new InternalLogger());
        Assert.True(health.MXAnalysis.MxRrsetComparisonIncomplete);
        Assert.True(health.MXAnalysis.TargetAddressComparisonIncomplete);
    }
}
