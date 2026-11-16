using System;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

// A feed that didn't answer must never read as a clean answer: the risk profile counts clean answers as evidence.
public class TestThreatQueryStates {
    private static string Unique(string label) => label + "-" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".example";

    private static async Task<ThreatIntelQueryState> UrlHaus(Func<string, Task<string>> answer) {
        var analysis = new ThreatIntelAnalysis { UrlHausOverride = answer };
        await analysis.Analyze(Unique("urlhaus"), null, null, null, new InternalLogger());
        return analysis.Listings.Single(l => l.Source == ThreatIntelSource.UrlHaus).State;
    }

    [Fact]
    public async Task UrlHausFailuresAreFailedNotClean() {
        Assert.Equal(ThreatIntelQueryState.Failed, await UrlHaus(_ => throw new System.Net.Http.HttpRequestException("unreachable")));
        Assert.Equal(ThreatIntelQueryState.Failed, await UrlHaus(_ => Task.FromResult("{\"query_status\":\"invalid_host\"}")));
        Assert.Equal(ThreatIntelQueryState.Failed, await UrlHaus(_ => Task.FromResult("not json")));
        Assert.Equal(ThreatIntelQueryState.Clean, await UrlHaus(_ => Task.FromResult("{\"query_status\":\"no_results\"}")));
        Assert.Equal(ThreatIntelQueryState.Listed, await UrlHaus(_ => Task.FromResult("{\"query_status\":\"ok\",\"url_count\":2}")));
    }

    [Fact]
    public async Task OpenPhishWithoutASourceIsNotQueriedAndAFailingSourceIsFailed() {
        var none = new ThreatIntelAnalysis { EnableUrlHaus = false, EnableOpenPhish = true };
        await none.Analyze(Unique("openphish"), null, null, null, new InternalLogger());
        Assert.Equal(ThreatIntelQueryState.NotQueried, none.Listings.Single(l => l.Source == ThreatIntelSource.OpenPhish).State);

        var failing = new ThreatIntelAnalysis { EnableUrlHaus = false, EnableOpenPhish = true, OpenPhishOverride = _ => throw new InvalidOperationException("feed down") };
        await failing.Analyze(Unique("openphish"), null, null, null, new InternalLogger());
        Assert.Equal(ThreatIntelQueryState.Failed, failing.Listings.Single(l => l.Source == ThreatIntelSource.OpenPhish).State);
    }

    [Fact]
    public async Task VirusTotalWithoutAnalysisStatisticsIsFailed() {
        var intel = new ThreatIntelAnalysis { EnableUrlHaus = false, VirusTotalObjectOverride = _ => Task.FromResult<VirusTotalObject?>(new VirusTotalObject()) };
        await intel.Analyze(Unique("vt"), null, null, "key", new InternalLogger());
        Assert.Equal(ThreatIntelQueryState.Failed, intel.Listings.Single(l => l.Source == ThreatIntelSource.VirusTotal).State);

        var feed = new ThreatFeedAnalysis { VirusTotalObjectOverride = _ => Task.FromResult<VirusTotalObject?>(new VirusTotalObject()) };
        await feed.Analyze("192.0.2.10", "key", null, new InternalLogger());
        Assert.Equal(ThreatIntelQueryState.Failed, feed.Listings.Single(l => l.Source == ThreatIntelSource.VirusTotal).State);
    }

    [Fact]
    public async Task AbuseIpDbWithoutAScoreIsFailedAndAZeroScoreIsClean() {
        var empty = new ThreatFeedAnalysis { AbuseIpDbOverride = _ => Task.FromResult("{}") };
        await empty.Analyze("192.0.2.11", null, "key", new InternalLogger());
        Assert.Equal(ThreatIntelQueryState.Failed, empty.Listings.Single(l => l.Source == ThreatIntelSource.AbuseIpDb).State);

        var zero = new ThreatFeedAnalysis { AbuseIpDbOverride = _ => Task.FromResult("{\"data\":{\"abuseConfidenceScore\":0}}") };
        await zero.Analyze("192.0.2.12", null, "key", new InternalLogger());
        Assert.Equal(ThreatIntelQueryState.Clean, zero.Listings.Single(l => l.Source == ThreatIntelSource.AbuseIpDb).State);
    }
}
