using DomainDetective.Recommendations;
using System.Collections.Generic;

namespace DomainDetective.Tests;

public class TestWhoisRecommendations
{
    [Fact]
    public void RegistersSuccessCodes()
    {
        var map = new Dictionary<string, RecommendationAdvice>();
        new WhoisRecommendations().Register(map);
        Assert.Contains(WhoisCodes.ContactValid, map.Keys);
        Assert.Equal("WHOIS contact details available", map[WhoisCodes.ContactValid].Title);
        Assert.Contains(WhoisCodes.ExpiryFuture, map.Keys);
    }
}
