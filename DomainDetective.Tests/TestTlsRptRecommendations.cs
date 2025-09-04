using DomainDetective.Recommendations;
using System.Collections.Generic;

namespace DomainDetective.Tests;

public class TestTlsRptRecommendations
{
    [Fact]
    public void RegistersPositiveCodes()
    {
        var map = new Dictionary<string, RecommendationAdvice>();
        new TlsRptRecommendations().Register(map);
        Assert.Contains(TlsRptCodes.RecordPresent, map.Keys);
        Assert.Contains(TlsRptCodes.RecordStartsV1, map.Keys);
        Assert.Contains(TlsRptCodes.RuaMailtoPresent, map.Keys);
        Assert.Contains(TlsRptCodes.PolicyValid, map.Keys);
    }
}
