using System.Threading.Tasks;
using DnsClientX;

namespace DomainDetective.Tests;

public class TestTyposquattingRecommendations
{
    [Fact]
    public async Task EmitsPositiveWhenNoActiveVariants()
    {
        var log = new InternalLogger();
        var analysis = new TyposquattingAnalysis
        {
            DnsConfiguration = new DnsConfiguration(),
            QueryDnsOverride = (_, _) => Task.FromResult(System.Array.Empty<DnsAnswer>())
        };

        await analysis.Analyze("example.com", log);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        Assert.Contains(positives, p => p.Code == TyposquattingCodes.VariantNone);
    }

    [Fact]
    public async Task EmitsPositiveWhenDefensiveRegistered()
    {
        var log = new InternalLogger();
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

        await analysis.Analyze("example.com", log);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        Assert.Contains(positives, p => p.Code == TyposquattingCodes.DefensiveRegistered);
    }
}
