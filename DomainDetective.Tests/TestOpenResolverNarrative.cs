using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests;

public class TestOpenResolverNarrative
{
    [Fact]
    public async Task OpenResolverNarrativeShowsClosedAndPositive()
    {
        var analysis = new OpenResolverAnalysis
        {
            RecursionTestOverride = (_, _) => Task.FromResult(false)
        };
        var logger = new InternalLogger();
        await analysis.AnalyzeServer("1.1.1.1", 53, logger);
        var narrative = OpenResolverNarrative.Build(analysis, analysis.Assessments);
        Assert.Contains("No open resolvers detected.", narrative.Highlights);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        Assert.Contains(positives, p => p.Code == OpenResolverCodes.RecursionClosed);
    }
}

