using System.Collections.Generic;
using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Recommendations;
using Xunit;

namespace DomainDetective.Tests;

public class TestDnssecRecommendations
{
    [Fact]
    public void RegistersSuccessCodes()
    {
        var map = new Dictionary<string, RecommendationAdvice>();
        new DnssecRecommendations().Register(map);
        Assert.Contains(DnssecCodes.SignaturesValid, map.Keys);
        Assert.Contains(DnssecCodes.ChainValid, map.Keys);
    }

    [Fact]
    public async Task EmitsPositiveRecommendations()
    {
        var hc = new DomainHealthCheck { Verbose = false };
        await hc.Verify("cloudflare.com", [HealthCheckType.DNSSEC]);
        var positives = RecommendationEngine.FromPositives(hc.DnsSecAnalysis.Assessments);
        Assert.Contains(positives, p => p.Code == DnssecCodes.SignaturesValid);
        Assert.Contains(positives, p => p.Code == DnssecCodes.ChainValid);
    }
}
