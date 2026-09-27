using System.IO;
using System.Threading.Tasks;
using DomainDetective.Narratives;

namespace DomainDetective.Tests;

public class TestArcNarrative
{
    [Fact]
    public async Task ArcNarrativeHighlightsValidChain()
    {
        var raw = File.ReadAllText("Data/arc-valid.txt");
        var hc = new DomainHealthCheck();
        var result = await hc.VerifyARCAsync(raw);
        var sections = ArcNarrative.Build(result);
        Assert.Contains("ARC header structure is complete and sequential; cryptographic verification is separate.", sections.Highlights);
        Assert.Contains("ARC header structure complete", sections.Positives);
        Assert.Contains("ARC seals contain signature values", sections.Positives);
    }
}
