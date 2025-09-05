using DomainDetective.Recommendations;
using System.Collections.Generic;
using Xunit;

namespace DomainDetective.Tests;

public class TestContactRecommendations
{
    [Fact]
    public void RegistersCodes()
    {
        var map = new Dictionary<string, RecommendationAdvice>();
        new ContactRecommendations().Register(map);
        Assert.Contains(ContactCodes.RecordFound, map.Keys);
        Assert.Contains(ContactCodes.FieldsWellFormed, map.Keys);
    }
}
