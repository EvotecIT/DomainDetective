using System.Threading.Tasks;
using DomainDetective;
using Xunit;

namespace DomainDetective.Tests;

public class TestThreatFeedRecommendations
{
    [Fact]
    public async Task EmitsPositiveRecommendations()
    {
        var analysis = new ThreatFeedAnalysis
        {
            VirusTotalObjectOverride = _ => Task.FromResult<VirusTotalObject?>(new VirusTotalObject
            {
                Attributes = new VirusTotalAttributes
                {
                    LastAnalysisStats = new VirusTotalStats { Malicious = 0 }
                }
            }),
            AbuseIpDbOverride = _ => Task.FromResult("{\"data\":{\"abuseConfidenceScore\":0}}")
        };

        await analysis.Analyze("8.8.8.8", "v", "a", new InternalLogger());
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        Assert.Contains(positives, p => p.Code == ThreatFeedCodes.NoListings);
    }
}
