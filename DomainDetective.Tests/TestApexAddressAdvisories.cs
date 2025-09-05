using DnsClientX;
using System.Collections.Generic;
using System.Threading.Tasks;
using DomainDetective;
using Xunit;

namespace DomainDetective.Tests;

public class TestApexAddressAdvisories
{
    [Fact]
    public async Task LogsPublicAndFcrDns()
    {
        var map = new Dictionary<(string, DnsRecordType), DnsAnswer[]>
        {
            [("example.com", DnsRecordType.A)] = new[] { new DnsAnswer { DataRaw = "8.8.8.8", Type = DnsRecordType.A } },
            [("8.8.8.8.in-addr.arpa", DnsRecordType.PTR)] = new[] { new DnsAnswer { DataRaw = "apex.example.com.", Type = DnsRecordType.PTR } },
            [("apex.example.com", DnsRecordType.A)] = new[] { new DnsAnswer { DataRaw = "8.8.8.8", Type = DnsRecordType.A } }
        };
        var infos = new List<LogEventArgs>();
        var logger = new InternalLogger();
        logger.OnInformationMessage += (_, e) => infos.Add(e);
        var analysis = new ApexAddressAnalysis
        {
            DnsConfiguration = new DnsConfiguration(),
            QueryDnsOverride = (name, type) => Task.FromResult(map.TryGetValue((name, type), out var v) ? v : System.Array.Empty<DnsAnswer>())
        };
        await analysis.AnalyzeAsync("example.com", logger);
        Assert.Contains(infos, i => i.Code == ApexAddressCodes.PubliclyRoutable);
        Assert.Contains(infos, i => i.Code == ApexAddressCodes.FcrDnsValid);
    }
}
