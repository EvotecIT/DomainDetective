using System.Collections.Concurrent;
using DnsClientX;

namespace DomainDetective.Tests;

public class TestPerformancePublicationFeedback {
    [Theory]
    [InlineData("direct")]
    [InlineData("run")]
    [InlineData("combined")]
    [InlineData("ns")]
    public async Task DelegationForPublicSuffixRefreshesPreviouslyUsedAnalysis(string route) {
        using var health = new DomainHealthCheck();
        var queried = new ConcurrentQueue<(string Owner, DnsRecordType Type)>();
        health.NSAnalysis.EnableChaosFingerprinting = false;
        health.NSAnalysis.LookupAsnOverride = _ => Task.FromResult<int?>(null);
        health.DnsConfiguration.QueryDnsResponseOverride = (owner, type, _) => {
            queried.Enqueue((owner, type));
            bool suffix = owner == "co.uk" || owner == "uk";
            return Task.FromResult(new DnsResponse {
                Status = DnsResponseCode.NoError,
                Answers = type == DnsRecordType.NS ? new[] { new DnsAnswer {
                    Name = owner, Type = type, DataRaw = suffix ? "suffix-ns.example.test" : "previous-ns.example.test"
                } } : Array.Empty<DnsAnswer>()
            });
        };
        await health.Verify("example.com", new[] { HealthCheckType.NS, HealthCheckType.DELEGATION });
        while (queried.TryDequeue(out _)) { }
        if (route == "direct") { await health.VerifyDelegation("co.uk"); }
        else if (route == "ns") { await health.VerifyNS("co.uk"); }
        else { await health.Verify("co.uk", route == "combined"
            ? new[] { HealthCheckType.NS, HealthCheckType.DELEGATION } : new[] { HealthCheckType.DELEGATION }); }
        Assert.Equal("co.uk", health.NSAnalysis.Subject);
        Assert.Equal(new[] { "suffix-ns.example.test" }, health.NSAnalysis.NsRecords);
        if (route == "ns") {
            Assert.Empty(health.NSAnalysis.ParentNsRecords);
            Assert.False(health.NSAnalysis.DelegationMatches);
        } else {
            Assert.Equal(new[] { "suffix-ns.example.test" }, health.NSAnalysis.ParentNsRecords);
            Assert.True(health.NSAnalysis.DelegationMatches);
        }
        Assert.Equal(route == "ns" ? 1 : 2, queried.Count(query => query.Owner == "co.uk" && query.Type == DnsRecordType.NS)); // child plus parent referral
        Assert.Single(queried, query => query.Owner == "suffix-ns.example.test" && query.Type == DnsRecordType.CNAME);
    }

    [Fact]
    public async Task SharedDnsblTargetsReuseProviderWorkWithoutLosingProvenanceOrFreshRuns() {
        using var configuration = new DnsConfiguration();
        int providerQueries = 0;
        bool listed = true;
        configuration.QueryDnsResponseOverride = async (owner, type, token) => {
            await Task.Delay(2, token);
            string[] values;
            if (owner.EndsWith(".provider.example.test", StringComparison.Ordinal)) {
                Interlocked.Increment(ref providerQueries);
                values = listed && type == DnsRecordType.A ? new[] { "127.0.0.2" } : Array.Empty<string>();
            } else if (type == DnsRecordType.MX) { values = new[] { "10 mail1.example.test", "20 mail2.example.test" }; }
            else if (owner == "example.com" || owner.StartsWith("mail", StringComparison.Ordinal)) {
                values = type == DnsRecordType.A ? new[] { "192.0.2.10", "192.0.2.10" }
                    : new[] { "2001:db8::10", "2001:0db8:0:0:0:0:0:10" };
            } else { values = Array.Empty<string>(); }
            return new DnsResponse { Status = DnsResponseCode.NoError,
                Answers = values.Select(value => new DnsAnswer { Name = owner, Type = type, DataRaw = value }).ToArray() };
        };
        var analysis = new DNSBLAnalysis(configuration);
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        for (int run = 1; run <= 2; run++) {
            await analysis.AnalyzeDNSBLRecordsMX("example.com", new InternalLogger(), scanMode: DomainIpScanMode.MxAndApex);
            var records = analysis.AllResults.Where(record => record.BlackList == "provider.example.test").ToArray();
            Assert.Equal(run * 3, providerQueries); // IPv4 A plus IPv6 A/AAAA, once per canonical IP and run.
            Assert.Equal(6, records.Length); // Two families, each retaining both MX hosts and apex provenance.
            Assert.Equal(6, records.Distinct().Count());
            Assert.Equal(2, records.Select(record => record.IpAddress).Distinct().Count());
            Assert.All(records, record => Assert.True(record.QuerySucceeded));
            Assert.All(records, record => Assert.Equal(listed, record.IsBlackListed));
            Assert.Equal(new[] { "example.com", "mail1.example.test", "mail2.example.test" },
                records.Select(record => record.SourceHost).Distinct().OrderBy(value => value));
            Assert.Equal(listed ? 3 : 0, analysis.Assessments.Count(assessment => assessment.Code == DnsblCodes.Listed));
            listed = false;
        }
    }
}
