using System.Threading.Tasks;
using DomainDetective.Narratives;
using DomainDetective;
using Xunit;

namespace DomainDetective.Tests;

public class TestDaneNarrative
{
    [Fact]
    public async Task BuildsNarrativeAndPositives()
    {
        var daneRecord = "3 1 1 " + new string('A', 64);
        var healthCheck = new DomainHealthCheck { Verbose = false };
        await healthCheck.CheckDANE(daneRecord);

        var sections = DaneNarrative.Build(healthCheck.DaneAnalysis, healthCheck.DaneAnalysis.Assessments);
        Assert.Contains(sections.Highlights, h => h.Contains("TLSA record"));
        Assert.NotEmpty(sections.Positives);

        var positives = RecommendationEngine.FromPositives(healthCheck.DaneAnalysis.Assessments);
        Assert.Contains(positives, p => p.Code == DaneCodes.RecordValid);
        Assert.Contains(positives, p => p.Code == DaneCodes.CertificateMatches);
    }
}
