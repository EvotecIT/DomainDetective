using DomainDetective.Recommendations;
using System.Collections.Generic;
using Xunit;

namespace DomainDetective.Tests;

public class TestDmarcRecommendations {
    [Fact]
    public void RegistersPositiveCodes() {
        Dictionary<string, RecommendationAdvice> map = new();
        new DmarcRecommendations().Register(map);
        Assert.Contains(DmarcCodes.Present, map.Keys);
        Assert.Contains(DmarcCodes.StartsV1, map.Keys);
        Assert.Contains(DmarcCodes.PolicyReject, map.Keys);
        Assert.Contains(DmarcCodes.PolicyQuarantine, map.Keys);
        Assert.Contains(DmarcCodes.AlignmentStrictDkim, map.Keys);
        Assert.Contains(DmarcCodes.AlignmentStrictSpf, map.Keys);
        Assert.Contains(DmarcCodes.RuaPresent, map.Keys);
        Assert.Contains(DmarcCodes.RufPresent, map.Keys);
        Assert.Contains(DmarcCodes.Percent100, map.Keys);
        Assert.Equal("DMARC policy set to reject", map[DmarcCodes.PolicyReject].Title);
        Assert.Equal("DMARC record present", map[DmarcCodes.Present].Title);
    }
}

