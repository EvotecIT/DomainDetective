using DomainDetective.Recommendations;
using System.Collections.Generic;
using Xunit;

namespace DomainDetective.Tests;

public class TestRobotsTxtRecommendations
{
    [Fact]
    public void RegistersPositiveCodes()
    {
        var map = new Dictionary<string, RecommendationAdvice>();
        new RobotsTxtRecommendations().Register(map);
        Assert.Contains(RobotsTxtCodes.Available, map.Keys);
        Assert.Contains(RobotsTxtCodes.DisallowPresent, map.Keys);
        Assert.Contains(RobotsTxtCodes.SitemapPresent, map.Keys);
    }
}

