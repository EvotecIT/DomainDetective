using System.Linq;
using System.Threading.Tasks;
using DnsClientX;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests;

public class TestRpkiNarrative
{
    [Fact]
    public async Task BuildsNarrativeAndPositiveAdvice()
    {
        var analysis = new RPKIAnalysis
        {
            DnsConfiguration = new DnsConfiguration(),
            QueryDnsOverride = (n, t) => t == DnsRecordType.A
                ? Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1" } })
                : Task.FromResult(Array.Empty<DnsAnswer>()),
            QueryRpkiOverride = _ => Task.FromResult(("1.1.1.0/24", 64512, true))
        };
        await analysis.Analyze("example.com", new InternalLogger());
        var sections = RpkiNarrative.Build(analysis, analysis.Assessments);
        Assert.Contains("AS64512", string.Join(" ", sections.Highlights));
        Assert.NotEmpty(sections.Positives);
        var pos = RecommendationEngine.FromPositives(analysis.Assessments)
            .Select(r => r.Code)
            .ToList();
        Assert.Contains(RpkiCodes.ValidRoa, pos);
        Assert.Contains(RpkiCodes.PrefixCovered, pos);
    }
}

