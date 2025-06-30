using DnsClientX;
using System;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestEdnsSupportHealthCheck
{
    private static DomainHealthCheck Create(bool support)
    {
        var hc = new DomainHealthCheck();
        hc.EdnsSupportAnalysis.QueryDnsOverride = (name, type) =>
        {
            if (type == DnsRecordType.NS)
            {
                return Task.FromResult(new[] { new DnsAnswer { DataRaw = "ns.example.com", Type = DnsRecordType.NS } });
            }
            return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1", Type = DnsRecordType.A } });
        };
        hc.EdnsSupportAnalysis.QueryServerOverride = _ => Task.FromResult(new EdnsSupportInfo { Supported = support, UdpPayloadSize = 4096, DoBit = true });
        return hc;
    }

    [Fact]
    public async Task VerifyEdnsSupportReportsSupport()
    {
        var hc = Create(true);
        await hc.VerifyEdnsSupport("example.com");
        Assert.Contains(hc.EdnsSupportAnalysis.ServerSupport.Values, v => v.Supported);
    }

    [Fact]
    public async Task VerifyEdnsSupportReportsNoSupport()
    {
        var hc = Create(false);
        await hc.VerifyEdnsSupport("example.com");
        Assert.Contains(hc.EdnsSupportAnalysis.ServerSupport.Values, v => !v.Supported);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public async Task VerifyEdnsSupportThrowsIfDomainNullOrWhitespace(string domain)
    {
        var hc = new DomainHealthCheck();
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await hc.VerifyEdnsSupport(domain));
    }
}
