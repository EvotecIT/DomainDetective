using DomainDetective.Recommendations;
using System.Collections.Generic;
using Xunit;

namespace DomainDetective.Tests;

public class TestTlsRecommendations
{
    [Fact]
    public void RegistersPositiveCodes()
    {
        var map = new Dictionary<string, RecommendationAdvice>();
        new TlsRecommendations().Register(map);
        Assert.Contains(TlsCodes.StrongProtocol, map.Keys);
        Assert.Contains(TlsCodes.PfsCipher, map.Keys);
    }
}

