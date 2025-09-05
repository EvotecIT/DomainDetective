using DomainDetective;
using DomainDetective.Recommendations;
using System.Collections.Generic;
using Xunit;

namespace DomainDetective.Tests;

public class TestNtpRecommendations {
    [Fact]
    public void RegistersPositiveCodes() {
        var map = new Dictionary<string, RecommendationAdvice>();
        new NtpRecommendations().Register(map);
        Assert.Contains(NtpCodes.ReasonableOffset, map.Keys);
        Assert.Contains(NtpCodes.TrustedStratum, map.Keys);
    }
}

