using DnsClientX;
using DomainDetective.Narratives;
using System;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestTtlNarrative
{
    [Fact]
    public async Task BuildsNarrativeWithPositives()
    {
        var analysis = new DnsTtlAnalysis
        {
            DnsConfiguration = new DnsConfiguration(),
            QueryDnsOverride = (_, type) =>
            {
                if (type == DnsRecordType.DS) return Task.FromResult(Array.Empty<DnsAnswer>());
                return Task.FromResult(new[] { new DnsAnswer { TTL = 3600, Type = type } });
            }
        };
        await analysis.Analyze("example.com", new InternalLogger());
        var sections = TtlNarrative.Build(analysis, analysis.Assessments);
        Assert.Contains(sections.Highlights, h => h.Contains("SOA TTL"));
        Assert.Contains(sections.Positives, p => p.Contains("within recommended range"));
        Assert.Contains(sections.Positives, p => p.Contains("aligned"));
    }
}
