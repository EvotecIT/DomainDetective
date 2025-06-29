using DnsClientX;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestEdnsSupportAnalysis
{
    private static EdnsSupportAnalysis Create(bool support)
    {
        return new EdnsSupportAnalysis
        {
            QueryDnsOverride = (name, type) =>
            {
                if (type == DnsRecordType.NS)
                {
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "ns.example.com", Type = DnsRecordType.NS } });
                }
                return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1", Type = DnsRecordType.A } });
            },
            QueryServerOverride = _ => Task.FromResult(support)
        };
    }

    [Fact]
    public async Task ReportsSupport()
    {
        var analysis = Create(true);
        await analysis.Analyze("example.com", new InternalLogger());
        Assert.Contains(analysis.ServerSupport.Values, v => v);
    }

    [Fact]
    public async Task ReportsNoSupport()
    {
        var analysis = Create(false);
        await analysis.Analyze("example.com", new InternalLogger());
        Assert.Contains(analysis.ServerSupport.Values, v => !v);
    }
}
