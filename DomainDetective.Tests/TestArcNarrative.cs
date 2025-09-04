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
        Assert.Contains("ARC chain is valid and sequential.", sections.Highlights);
        Assert.Contains("ARC chain validated", sections.Positives);
        Assert.Contains("ARC seals include signatures", sections.Positives);
    }
}
