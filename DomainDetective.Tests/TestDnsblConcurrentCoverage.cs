using DnsClientX;
using DomainDetective.DesiredState;
using DomainDetective.Views;

namespace DomainDetective.Tests;

public class TestDnsblConcurrentCoverage {
    [Fact]
    public async Task ReturnedViewKeepsItsAssessmentsWhenLaterCoverageChanges() {
        var analysis = new DNSBLAnalysis();
        analysis.ClearDNSBL();
        analysis.AddDNSBL("provider.example.test");
        bool fail = false;
        analysis.QueryDnsFullOverride = (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] {
            new DnsResponse { Status = fail ? DnsResponseCode.ServerFailure : DnsResponseCode.NXDomain }
        });
        await analysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.1" }, new InternalLogger());
        var original = Converters.Convert(analysis);
        var codes = original.Assessments.Select(item => item.Code).ToArray();
        using var reader = original.Assessments.GetEnumerator();
        Assert.True(reader.MoveNext());
        fail = true;
        await analysis.AnalyzeDNSBLRecordsMany(new[] { "192.0.2.2" }, new InternalLogger(), false);
        while (reader.MoveNext()) { }
        Assert.Equal(codes, original.Assessments.Select(item => item.Code));
        Assert.Contains(original.Assessments, item => item.Code == DnsblCodes.NotListed);
        var current = Converters.Convert(analysis);
        Assert.Equal("Incomplete", current.Status);
        Assert.Contains(current.Assessments, item => item.Code == DnsblCodes.NotListed && item.Target == "192.0.2.1");
        Assert.DoesNotContain(current.Assessments, item => item.Code == DnsblCodes.NotListed && item.Target == "192.0.2.2");
        Assert.Contains(current.Assessments, item => item.Code == DnsblCodes.QueryFailed);
    }

    [Fact]
    public async Task ConcurrentAppendsRetainEveryProviderAndConsistentViews() {
        // This exercises atomic publication under append concurrency. Provider timing
        // has separate coverage; thread-pool contention must not change this fixture's replies.
        var analysis = new DNSBLAnalysis { AnalysisTimeout = TimeSpan.FromSeconds(20), ProviderTimeout = Timeout.InfiniteTimeSpan };
        analysis.ClearDNSBL();
        for (int provider = 0; provider < 8; provider++) { analysis.AddDNSBL($"provider{provider}.example.test"); }
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        analysis.QueryDnsFullOverride = async (_, _) => {
            await release.Task;
            await Task.Yield();
            return new[] { new DnsResponse { Status = DnsResponseCode.NXDomain } };
        };
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var runs = Enumerable.Range(0, 8).Select(run => analysis.AnalyzeDNSBLRecordsMany(
            Enumerable.Range(1, 8).Select(host => $"192.0.2.{run * 8 + host}"), new InternalLogger(), false, guard.Token)).ToArray();
        release.TrySetResult(true);
        var completed = Task.WhenAll(runs);
        for (int sample = 0; sample < 8; sample++) {
            var current = Converters.Convert(analysis);
            Assert.Equal(current.HostsChecked, current.HostSummaries.Count);
            await Task.Yield();
        }
        await completed;
        Assert.Equal(64, analysis.Results.Count);
        Assert.Equal(512, analysis.AllResults.Count);
        Assert.All(analysis.AllResults, record => Assert.True(record.QuerySucceeded));
        Assert.Equal(64, analysis.RecordChecked);
        Assert.Equal(64, analysis.NotBlacklisted);
        var view = Converters.Convert(analysis);
        Assert.Equal(8, view.ProvidersChecked);
        Assert.Equal(64, view.HostSummaries.Count);
        Assert.All(view.HostSummaries, host => { Assert.Equal(8, host.Total); Assert.Equal(0, host.NotChecked); });
        Assert.Equal(64, analysis.Assessments.Count(item => item.Code == DnsblCodes.NotListed));
    }

    [Theory]
    [InlineData(DomainIpScanMode.MxAOnly, DnsblIpSource.MxA, DnsblIpSource.MxAAAA)]
    [InlineData(DomainIpScanMode.MxAAAAOnly, DnsblIpSource.MxAAAA, DnsblIpSource.MxA)]
    public async Task DiscoveryFailuresOnlyAffectTheSelectedAddressFamily(DomainIpScanMode mode, DnsblIpSource selected, DnsblIpSource excluded) {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) => Task.FromResult(new DnsResponse { Status = DnsResponseCode.ServerFailure });
        await health.DNSBLAnalysis.AnalyzeDNSBLRecordsMX("example.test", new InternalLogger(), scanMode: mode);
        foreach (var source in new[] { selected, excluded }) {
            var desired = DesiredStateEvaluator.Evaluate("example.test", health, new DesiredStateProfile {
                Dnsbl = new DesiredStateDnsblPolicy { DisallowListings = true, RequireAtLeastOneResult = false, IncludeIpSources = new[] { source } }
            });
            Assert.Equal(source == excluded, desired.Conforms);
            Assert.Equal(source == selected, desired.Assessments.Any(item => item.Code == "DesiredState.DNSBL.QueryFailed"));
        }
    }
}
