using System.Threading.Tasks;
using DomainDetective;

namespace DomainDetective.Tests;

public class TestThreatIntelAnalysis
{
    [Fact]
    public async Task FlagsListings()
    {
        var analysis = new ThreatIntelAnalysis
        {
            GoogleSafeBrowsingOverride = _ => Task.FromResult("{\"matches\":[{}] }"),
            PhishTankOverride = _ => Task.FromResult("{\"results\":{\"valid\":\"true\",\"in_database\":\"true\"}}"),
            VirusTotalOverride = _ => Task.FromResult("{\"data\":{\"attributes\":{\"last_analysis_stats\":{\"malicious\":1}}}}")
        };

        await analysis.Analyze("example.com", "g", "p", "v", new InternalLogger());

        Assert.True(analysis.ListedByGoogle);
        Assert.True(analysis.ListedByPhishTank);
        Assert.True(analysis.ListedByVirusTotal);
    }

    [Fact]
    public async Task IntegratesWithHealthCheck()
    {
        var health = new DomainHealthCheck();
        health.GoogleSafeBrowsingApiKey = "g";
        health.PhishTankApiKey = "p";
        health.VirusTotalApiKey = "v";
        health.ThreatIntelAnalysis.GoogleSafeBrowsingOverride = _ => Task.FromResult("{\"matches\":[{}]}");
        health.ThreatIntelAnalysis.PhishTankOverride = _ => Task.FromResult("{\"results\":{\"valid\":\"true\",\"in_database\":\"true\"}}");
        health.ThreatIntelAnalysis.VirusTotalOverride = _ => Task.FromResult("{\"data\":{\"attributes\":{\"last_analysis_stats\":{\"malicious\":1}}}}");

        await health.VerifyThreatIntel("example.com");

        Assert.True(health.ThreatIntelAnalysis.ListedByGoogle);
        Assert.True(health.ThreatIntelAnalysis.ListedByPhishTank);
        Assert.True(health.ThreatIntelAnalysis.ListedByVirusTotal);
    }

    [Fact]
    public void ReusesHttpClient()
    {
        var a1 = new ThreatIntelAnalysis();
        var a2 = new ThreatIntelAnalysis();

        Assert.Same(a1.Client, a2.Client);
    }
}
