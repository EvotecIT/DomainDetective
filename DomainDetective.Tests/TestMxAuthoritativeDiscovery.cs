using DnsClientX;

namespace DomainDetective.Tests;

public class TestMxAuthoritativeDiscovery {
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
