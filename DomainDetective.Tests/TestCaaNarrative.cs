using DomainDetective;
using DomainDetective.Narratives;
using DomainDetective.Recommendations;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestCaaNarrative
{
    [Fact]
    public async Task BuildsNarrativeAndPositives()
    {
        var records = new List<string>
        {
            "0 issue \"letsencrypt.org\"",
            "0 issuewild \"letsencrypt.org\"",
            "0 iodef \"mailto:security@example.com\""
        };
        var hc = new DomainHealthCheck { Verbose = false };
        await hc.CheckCAA(records);
        var sections = CaaNarrative.Build(hc.CAAAnalysis);
        Assert.Contains(sections.Highlights, h => h.Contains("letsencrypt.org"));
        Assert.Contains(sections.Highlights, h => h.Contains("Wildcard", System.StringComparison.OrdinalIgnoreCase));
        Assert.Contains(sections.Highlights, h => h.Contains("security@example.com"));
        var positives = RecommendationEngine.FromPositives(hc.CAAAnalysis.Assessments);
        Assert.Contains(positives, p => p.Code == CaaCodes.RecordPresent);
        Assert.Contains(positives, p => p.Code == CaaCodes.IodefPresent);
    }
}
