using System.Threading.Tasks;
using DomainDetective.Narratives;

namespace DomainDetective.Tests;

public class TestSpfFlattenedNarrative {
    [Fact]
    public async Task NarrativeShowsIpAndPositiveCode() {
        var hc = new DomainHealthCheck();
        await hc.CheckSPF("v=spf1 ip4:192.0.2.1 -all");
        await hc.SpfAnalysis.GetFlattenedIpAnalysis("example.com", new InternalLogger());

        var sections = SpfFlattenedNarrative.Build(hc.SpfAnalysis, hc.SpfAnalysis.Assessments);

        Assert.Contains("Unique IPs: 1", string.Join(" ", sections.Highlights));
        Assert.Contains("DNS lookups used: 0/10", string.Join(" ", sections.Highlights));

        var positives = RecommendationEngine.FromPositives(hc.SpfAnalysis.Assessments);
        Assert.Contains(positives, p => p.Code == SpfCodes.FlattenedIpSetOptimized);
    }
}
