using DnsClientX;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestEdnsRecommendations
{
    [Fact]
    public async Task EmitsPositiveRecommendations()
    {
        var log = new InternalLogger();
        var analysis = new EdnsSupportAnalysis
        {
            QueryDnsOverride = (name, type) =>
            {
                if (type == DnsRecordType.NS)
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "ns.example.com", Type = DnsRecordType.NS } });
                return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.2.3.4", Type = DnsRecordType.A } });
            },
            QueryServerOverride = _ => Task.FromResult(new EdnsSupportInfo { Supported = true, UdpPayloadSize = 1232, DoBit = true, Version = 0 })
        };

        await analysis.Analyze("example.com", log);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        Assert.Contains(positives, p => p.Code == EdnsCodes.Supported);
        Assert.Contains(positives, p => p.Code == EdnsCodes.UdpSizeOk);
        Assert.Contains(positives, p => p.Code == EdnsCodes.VersionZero);
    }
}

