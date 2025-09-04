using DomainDetective.Recommendations;
using System.Collections.Generic;
using Xunit;

namespace DomainDetective.Tests;

public class TestAutodiscoverRecommendations {
    [Fact]
    public void RegistersPositiveCodes() {
        var map = new Dictionary<string, RecommendationAdvice>();
        new AutodiscoverRecommendations().Register(map);
        Assert.Contains(AutodiscoverCodes.EndpointDiscovered, map.Keys);
        Assert.Equal("Autodiscover endpoint discovered", map[AutodiscoverCodes.EndpointDiscovered].Title);
        Assert.Contains(AutodiscoverCodes.XmlValid, map.Keys);
        Assert.Contains(AutodiscoverCodes.JsonValid, map.Keys);
    }
}
