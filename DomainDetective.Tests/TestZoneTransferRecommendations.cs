using DomainDetective.Recommendations;
using System.Collections.Generic;
using Xunit;

namespace DomainDetective.Tests;

public class TestZoneTransferRecommendations
{
    [Fact]
    public void RegistersPositiveCode()
    {
        var map = new Dictionary<string, RecommendationAdvice>();
        new ZoneTransferRecommendations().Register(map);
        Assert.Contains(ZoneTransferCodes.Restricted, map.Keys);
        Assert.Equal("Zone transfers restricted", map[ZoneTransferCodes.Restricted].Title);
    }
}
