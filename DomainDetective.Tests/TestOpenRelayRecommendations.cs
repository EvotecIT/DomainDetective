using System.Collections.Generic;
using DomainDetective.Recommendations;
using Xunit;

namespace DomainDetective.Tests;

public class TestOpenRelayRecommendations
{
    [Fact]
    public void RegistersSuccessCodes()
    {
        var map = new Dictionary<string, RecommendationAdvice>();
        new OpenRelayRecommendations().Register(map);
        Assert.Contains(OpenRelayCodes.Denied, map.Keys);
        Assert.Contains(OpenRelayCodes.ConnectionFailed, map.Keys);
    }
}
