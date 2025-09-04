using DomainDetective.Recommendations;
using System.Collections.Generic;
using Xunit;

namespace DomainDetective.Tests;

public class TestSoaRecommendations
{
    [Fact]
    public void RegistersPositiveCodes()
    {
        var map = new Dictionary<string, RecommendationAdvice>();
        new SOARecommendations().Register(map);
        Assert.Contains(SOACodes.RefreshSane, map.Keys);
        Assert.Contains(SOACodes.RetrySane, map.Keys);
        Assert.Contains(SOACodes.ExpireSane, map.Keys);
        Assert.Contains(SOACodes.MnameMatchesNs, map.Keys);
    }
}
