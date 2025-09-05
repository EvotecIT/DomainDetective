using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests;

public class TestThreatFeedNarrative
{
    [Fact]
    public async Task BuildsNarrativeWithPositives()
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
        var sections = ThreatFeedNarrative.Build(analysis);
        Assert.Contains(sections.Highlights, h => h.Contains("No threat feed listings"));
        Assert.Contains(sections.Positives, p => p.Contains("No threat feed listings"));
    }
}
