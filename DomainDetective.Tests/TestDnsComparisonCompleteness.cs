using DnsClientX;
using DomainDetective.DesiredState;
using DomainDetective.Views;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestDnsComparisonCompleteness {
    [Fact]
    public void MissingMxReplyCannotSatisfyAnRrsetOnlyPolicy() {
        using var health = new DomainHealthCheck();
        health.MXAnalysis.RecordRrsetCompleteness(2, 1, "example.test", new InternalLogger());
        Assert.True(Converters.Convert(health.MXAnalysis).MxRrsetComparisonIncomplete);
        var result = DesiredStateEvaluator.Evaluate("example.test", health, new DesiredStateProfile {
            Mx = new DesiredStateMxPolicy { RequireRrsetConsistentAcrossNs = true }
        });
        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, item => item.Code == "DesiredState.MX.Rrset.QueryFailed");
    }

    [Fact]
    public void IncompleteMxAddressDiagnosticsNameOnlyTheAffectedHost() {
        var analysis = new MXAnalysis();
        var logger = new InternalLogger();
        analysis.RecordTargetAddressEvidence("failed.example.test", new[] { ((DnsResponse?)null, (DnsResponse?)new DnsResponse()) }, logger);
        analysis.RecordTargetAddressEvidence("complete.example.test", new[] { ((DnsResponse?)new DnsResponse(), (DnsResponse?)new DnsResponse()) }, logger);
        Assert.True(analysis.TargetAddressComparisonIncomplete);
        var message = Assert.Single(analysis.Assessments, item => item.Code == "MX.TargetAddress.ComparisonIncomplete");
        Assert.Contains("failed.example.test", message.Message);
        Assert.DoesNotContain("complete.example.test", message.Message);
    }

    [Fact]
    public async Task AliasQueriesFinishBeforeCompetingAddressWorkStarts() {
        var analysis = new MXAnalysis();
        var queries = new List<DnsRecordType>();
        analysis.QueryDnsOverride = (_, type) => {
            queries.Add(type);
            return Task.FromResult(type == DnsRecordType.A
                ? new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" } } : Array.Empty<DnsAnswer>());
        };
        await analysis.AnalyzeMxRecords(new[] {
            new DnsAnswer { Type = DnsRecordType.MX, DataRaw = "0 one.example.test" },
            new DnsAnswer { Type = DnsRecordType.MX, DataRaw = "10 two.example.test" }
        }, new InternalLogger());
        Assert.Equal(new[] { DnsRecordType.CNAME, DnsRecordType.CNAME }, queries.Take(2));
        Assert.False(analysis.CnameQueryFailed);
    }

    [Fact]
    public async Task MissingAuthoritativeTtlValuesRemainIncompleteInViewsAndPolicy() {
        using var health = new DomainHealthCheck();
        var analysis = health.DnsTtlAnalysis;
        analysis.UniformityQueryTimeoutMs = 20;
        analysis.QueryDnsOverride = (_, type) => Task.FromResult(type switch {
            DnsRecordType.NS => new[] { new DnsAnswer { Type = type, DataRaw = "ns.example.test" } },
            DnsRecordType.A => new[] { new DnsAnswer { Type = type, DataRaw = "127.0.0.254" } },
            _ => Array.Empty<DnsAnswer>()
        });
        await analysis.AnalyzeUniformityAcrossServers("example.test", new InternalLogger());
        Assert.True(analysis.UniformityIncomplete);
        Assert.False(analysis.AUniformAcrossServers);
        Assert.Equal("Incomplete", Converters.Convert(analysis).Status);
        Assert.Contains(analysis.Assessments, item => item.Code == "TTL.Uniformity.Incomplete");
        Assert.DoesNotContain(analysis.Assessments, item => item.Code == TtlCodes.UniformAcrossNS_A);
        analysis.ServerTtlA["192.0.2.1"] = 300;
        var result = DesiredStateEvaluator.Evaluate("example.test", health, new DesiredStateProfile {
            Ttl = new DesiredStateTtlPolicy { RequireAUniformAcrossNs = true }
        });
        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, item => item.Code == DesiredStateCodes.TtlAUniformityRequired);
    }
}
