using System.Collections.Generic;
using System.IO;
using DomainDetective.Recommendations;
using Xunit;

namespace DomainDetective.Tests;

public class TestMessageHeaderRecommendations
{
    [Fact]
    public void RegistersCodes()
    {
        var map = new Dictionary<string, RecommendationAdvice>();
        new MessageHeaderRecommendations().Register(map);
        Assert.Contains(MessageHeaderCodes.DkimPass, map.Keys);
        Assert.Contains(MessageHeaderCodes.SpfPass, map.Keys);
        Assert.Contains(MessageHeaderCodes.DmarcPass, map.Keys);
        Assert.Contains(MessageHeaderCodes.ArcPass, map.Keys);
        Assert.Contains(MessageHeaderCodes.DirectToExchangeOnlineObserved, map.Keys);
        Assert.Contains(MessageHeaderCodes.AuthenticationFailedDeliveredToInbox, map.Keys);
        Assert.Contains(MessageHeaderCodes.SelfSpoofDeliveredToInbox, map.Keys);
        Assert.Contains(MessageHeaderCodes.GatewayLoopDetected, map.Keys);
        Assert.Contains(MessageHeaderCodes.ExpectedMxBypassed, map.Keys);
    }

    [Fact]
    public void EmitsPositiveAdvice()
    {
        var raw = File.ReadAllText("Data/sample-headers.txt");
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        Assert.Contains(positives, p => p.Code == MessageHeaderCodes.DkimPass);
        Assert.Contains(positives, p => p.Code == MessageHeaderCodes.SpfPass);
        Assert.Contains(positives, p => p.Code == MessageHeaderCodes.DmarcPass);
        Assert.Contains(positives, p => p.Code == MessageHeaderCodes.ArcPass);
    }
}
