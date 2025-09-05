using System.Linq;
using System.Threading.Tasks;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests;

public class TestSnmpNarrative
{
    [Fact]
    public async Task NarrativeReportsAndPositives()
    {
        var analysis = new SnmpAnalysis { SnmpTestOverride = (_, _) => Task.FromResult(false) };
        await analysis.AnalyzeServer("host", 161, new InternalLogger());
        var narrative = SnmpNarrative.Build(analysis);
        Assert.Contains("did not respond", narrative.Highlights.First());
        Assert.Contains(SnmpCodes.Disabled, analysis.Recommendations.Select(r => r.Code));
        Assert.Contains("SNMP disabled or secured", narrative.Positives);
    }
}

