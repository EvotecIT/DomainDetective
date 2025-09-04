using System.Threading.Tasks;
using DomainDetective;

namespace DomainDetective.Tests;

public class TestThreatIntelScoring {
    [Fact]
    public async Task HighRiskWhenGSBAndHighVT() {
        var ti = new ThreatIntelAnalysis();
        ti.EnableUrlHaus = false;
        ti.EnableOpenPhish = false;
        ti.GoogleSafeBrowsingOverride = _ => Task.FromResult("{ \"matches\": [ { } ] }");
        ti.VirusTotalObjectOverride = _ => Task.FromResult<VirusTotalObject?>(new VirusTotalObject {
            Attributes = new VirusTotalAttributes {
                Reputation = 85,
                LastAnalysisStats = new VirusTotalStats { Malicious = 3 }
            }
        });
        await ti.Analyze("example.com", googleApiKey: "x", phishTankApiKey: null, virusTotalApiKey: "x", logger: new InternalLogger());
        Assert.True((ti.CompositeScore ?? 0) >= 60);
        Assert.Equal("Critical", ti.Severity);
        Assert.NotNull(ti.Confidence);
    }

    [Fact]
    public async Task LowRiskSingleListingUrlHaus() {
        var ti = new ThreatIntelAnalysis();
        ti.EnableUrlHaus = true;
        ti.EnableOpenPhish = false;
        // Simulate listed entry via reflection cache injection
        var cacheField = typeof(ThreatIntelAnalysis).GetField("_cacheUrlHaus", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        var cache = (System.Collections.Generic.Dictionary<string, (System.DateTime ts, bool listed)>)cacheField!.GetValue(ti)!;
        var host = "mal.example";
        cache[host] = (System.DateTime.UtcNow, true);
        await ti.Analyze(host, null, null, null, new InternalLogger());
        Assert.True((ti.CompositeScore ?? 0) >= 20);
        Assert.Equal("Low", ti.Severity);
    }
}
