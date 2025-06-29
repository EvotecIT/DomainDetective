using DnsClientX;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestWildcardDnsAnalysis
{
    [Fact]
    public async Task DetectsCatchAll()
    {
        var analysis = new WildcardDnsAnalysis
        {
            QueryDnsOverride = (_, _) => Task.FromResult(new[] { new DnsAnswer { Type = DnsRecordType.A } })
        };

        await analysis.Analyze("example.com", new InternalLogger(), sampleCount: 2);

        Assert.True(analysis.CatchAll);
    }

    [Fact]
    public async Task NoCatchAllWhenNoRecords()
    {
        var analysis = new WildcardDnsAnalysis
        {
            QueryDnsOverride = (_, _) => Task.FromResult(System.Array.Empty<DnsAnswer>())
        };

        await analysis.Analyze("example.com", new InternalLogger(), sampleCount: 2);

        Assert.False(analysis.CatchAll);
    }
}
