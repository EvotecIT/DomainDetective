using DomainDetective.Recommendations;
using System.Collections.Generic;
using Xunit;

namespace DomainDetective.Tests;

public class TestWildcardRecommendations
{
    [Fact]
    public void RegistersPositiveCode()
    {
        var map = new Dictionary<string, RecommendationAdvice>();
        new WildcardRecommendations().Register(map);
        Assert.Contains(WildcardCodes.NotDetected, map.Keys);
    }
}
