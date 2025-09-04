using System.Threading.Tasks;
using DnsClientX;
using DomainDetective;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests;

public class TestWildcardNarrative
{
    [Fact]
    public async Task BuildsNarrativeWhenCatchAllDetected()
    {
        var analysis = new WildcardDnsAnalysis
        {
            QueryDnsOverride = (_, _) => Task.FromResult(new[] { new DnsAnswer { Type = DnsRecordType.A, DataRaw = "192.0.2.1" } })
        };

        await analysis.Analyze("example.com", new InternalLogger(), sampleCount: 1);

        var sections = WildcardNarrative.Build(analysis);
        Assert.Contains(sections.Highlights, h => h.Contains("Wildcard DNS detected"));
        Assert.Contains("SOA", string.Join(" ", sections.Details));
    }
}
