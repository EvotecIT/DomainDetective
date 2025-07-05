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

    [Fact]
    public async Task DetectsCatchAllIpv6()
    {
        var analysis = new WildcardDnsAnalysis
        {
            QueryDnsOverride = (_, type) =>
            {
                return type switch
                {
                    DnsRecordType.A => Task.FromResult(System.Array.Empty<DnsAnswer>()),
                    DnsRecordType.AAAA => Task.FromResult(new[] { new DnsAnswer { DataRaw = "2001:0db8::1", Type = DnsRecordType.AAAA } }),
                    _ => Task.FromResult(System.Array.Empty<DnsAnswer>())
                };
            }
        };

        await analysis.Analyze("example.com", new InternalLogger(), sampleCount: 2);

        Assert.True(analysis.CatchAll);
    }

    [Fact]
    public async Task NoCatchAllForDeeperWildcardOnly()
    {
        var analysis = new WildcardDnsAnalysis
        {
            QueryDnsOverride = (name, _) =>
            {
                // respond only when two random labels are present
                var labels = name.Split('.');
                return Task.FromResult(labels.Length == 4
                    ? new[] { new DnsAnswer { Type = DnsRecordType.A } }
                    : System.Array.Empty<DnsAnswer>());
            }
        };

        await analysis.Analyze("example.com", new InternalLogger(), sampleCount: 1);

        Assert.False(analysis.CatchAll);
    }

    [Fact]
    public async Task FallsBackToNsWhenSoaMissing()
    {
        var analysis = new WildcardDnsAnalysis
        {
            QueryDnsOverride = (_, type) =>
            {
                return type switch
                {
                    DnsRecordType.SOA => Task.FromResult(System.Array.Empty<DnsAnswer>()),
                    DnsRecordType.NS => Task.FromResult(new[] { new DnsAnswer { Type = DnsRecordType.NS } }),
                    _ => Task.FromResult(System.Array.Empty<DnsAnswer>())
                };
            }
        };

        await analysis.Analyze("example.com", new InternalLogger(), sampleCount: 1);

        Assert.False(analysis.SoaExists);
        Assert.True(analysis.NsExists);
    }
}
