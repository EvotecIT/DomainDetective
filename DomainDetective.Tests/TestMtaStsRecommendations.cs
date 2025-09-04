using DomainDetective.Recommendations;
using System.Collections.Generic;
using Xunit;

namespace DomainDetective.Tests;

public class TestMtaStsRecommendations
{
    [Fact]
    public void RegistersPositiveCodes()
    {
        var map = new Dictionary<string, RecommendationAdvice>();
        new MtaStsRecommendations().Register(map);
        Assert.Contains(MtaStsCodes.PolicyValid, map.Keys);
        Assert.Contains(MtaStsCodes.HttpsAvailable, map.Keys);
    }
}
