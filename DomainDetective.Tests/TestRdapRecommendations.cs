using DomainDetective.Recommendations;
using System.Collections.Generic;

namespace DomainDetective.Tests;

public class TestRdapRecommendations
{
    [Fact]
    public void RegistersSuccessCodes()
    {
        var map = new Dictionary<string, RecommendationAdvice>();
        new RdapRecommendations().Register(map);
        Assert.Contains(RdapCodes.ContactValid, map.Keys);
        Assert.Equal("RDAP contact details available", map[RdapCodes.ContactValid].Title);
        Assert.Contains(RdapCodes.ExpiryFuture, map.Keys);
    }
}
