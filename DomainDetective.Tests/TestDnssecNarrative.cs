using System.Linq;
using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests;

public class TestDnssecNarrative
{
    [Fact]
    public async Task BuildsNarrativeWithHighlightsAndPositives()
    {
        var hc = new DomainHealthCheck { Verbose = false };
        await hc.Verify("cloudflare.com", [HealthCheckType.DNSSEC]);
        var sections = DnssecNarrative.Build(hc.DnsSecAnalysis, hc.DnsSecAnalysis.Assessments);
        Assert.Contains(sections.Highlights, h => h.Contains("DS record"));
        Assert.Contains(sections.Highlights, h => h.Contains("Key algorithms"));
        Assert.Contains(sections.Highlights, h => h.Contains("authenticated", System.StringComparison.OrdinalIgnoreCase));
        Assert.NotEmpty(sections.Positives);
    }
}
