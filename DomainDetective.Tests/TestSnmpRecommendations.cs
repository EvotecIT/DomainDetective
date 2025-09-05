using System.Collections.Generic;
using DomainDetective.Recommendations;
using Xunit;

namespace DomainDetective.Tests;

public class TestSnmpRecommendations
{
    [Fact]
    public void RegistersDisabledCode()
    {
        var map = new Dictionary<string, RecommendationAdvice>();
        new SnmpRecommendations().Register(map);
        Assert.Contains(SnmpCodes.Disabled, map.Keys);
    }
}

