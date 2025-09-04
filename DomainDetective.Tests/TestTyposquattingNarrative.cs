using System.Threading.Tasks;
using DomainDetective.Narratives;
using DnsClientX;

namespace DomainDetective.Tests;

public class TestTyposquattingNarrative
{
    [Fact]
    public async Task TyposquattingNarrativeHighlightsActiveAndDefensive()
    {
        var analysis = new TyposquattingAnalysis
        {
            DnsConfiguration = new DnsConfiguration(),
            QueryDnsOverride = (name, type) =>
            {
                if (name == "examp1e.com" && type == DnsRecordType.A)
                {
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1", Type = DnsRecordType.A } });
                }
                return Task.FromResult(System.Array.Empty<DnsAnswer>());
            }
        };

        await analysis.Analyze("example.com", new InternalLogger());

        var sections = TyposquattingNarrative.Build(analysis);
        Assert.Contains("Active typosquat domains: examp1e.com", sections.Highlights);
        Assert.Contains(sections.Details, d => d.StartsWith("Available for defensive registration:"));
    }
}
