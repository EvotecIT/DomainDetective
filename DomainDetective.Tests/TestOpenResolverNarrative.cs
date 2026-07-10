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

    [Fact]
    public async Task OpenResolverNarrativeDoesNotCallFailedProbeClosed()
    {
        var analysis = new OpenResolverAnalysis
        {
            RecursionDetailOverride = (host, port, _) => Task.FromResult(new OpenResolverResult
            {
                Host = host,
                Port = port,
                Status = OpenResolverStatus.Failed,
                Error = "timeout"
            })
        };
        await analysis.AnalyzeServer("192.0.2.1", 53, new InternalLogger());

        var narrative = OpenResolverNarrative.Build(analysis, analysis.Assessments);

        Assert.DoesNotContain("No open resolvers detected.", narrative.Highlights);
        Assert.Contains(narrative.Highlights, h => h.Contains("failed", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(narrative.Details, d => d.Contains("probe failed", StringComparison.OrdinalIgnoreCase));
    }
}

