using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestSpfRecommendations
{
    [Fact]
    public async Task EmitsPositiveRecommendations()
    {
        var hc = new DomainHealthCheck();
        hc.SpfAnalysis.TestSpfRecords["a.example.com"] = "v=spf1 -all";
        await hc.CheckSPF("v=spf1 include:a.example.com -all");
        var positives = RecommendationEngine.FromPositives(hc.SpfAnalysis.Assessments);
        Assert.Contains(positives, p => p.Code == SpfCodes.IncludeChainValid);
        Assert.Contains(positives, p => p.Code == SpfCodes.LookupsWithinLimit);
        Assert.Contains(positives, p => p.Code == SpfCodes.AllEnforced);
    }
}
