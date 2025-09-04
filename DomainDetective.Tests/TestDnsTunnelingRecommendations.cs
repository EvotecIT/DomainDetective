using System;
using System.Collections.Generic;
using DomainDetective;
using DomainDetective.Recommendations;
using Xunit;

namespace DomainDetective.Tests;

public class TestDnsTunnelingRecommendations
{
    [Fact]
    public void RegistersSuccessCodes()
    {
        var map = new Dictionary<string, RecommendationAdvice>();
        new DnsTunnelingRecommendations().Register(map);
        Assert.Contains(DnsTunnelingCodes.NoIndicators, map.Keys);
    }

    [Fact]
    public void EmitsPositiveRecommendation()
    {
        var analysis = new DnsTunnelingAnalysis();
        analysis.Analyze("example.com", Array.Empty<string>());
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        Assert.Contains(positives, p => p.Code == DnsTunnelingCodes.NoIndicators);
    }
}
