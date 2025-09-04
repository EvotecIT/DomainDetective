using System.Collections.Generic;
using DomainDetective.Recommendations;
using Xunit;

namespace DomainDetective.Tests;

public class TestOpenResolverRecommendations
{
    [Fact]
    public void RegistersClosedCode()
    {
        var map = new Dictionary<string, RecommendationAdvice>();
        new OpenResolverRecommendations().Register(map);
        Assert.Contains(OpenResolverCodes.RecursionClosed, map.Keys);
    }
}

