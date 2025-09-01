using DnsClientX;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestEdnsSupportAdvisories
{
    [Fact]
    public async Task WarnsOnBufferTooLarge()
    {
        var log = new InternalLogger();
        var warns = new List<LogEventArgs>();
        log.OnWarningMessage += (_, e) => warns.Add(e);

        var analysis = new EdnsSupportAnalysis
        {
            QueryDnsOverride = (name, type) =>
            {
                if (type == DnsRecordType.NS)
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "ns.example.com", Type = DnsRecordType.NS } });
                return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.2.3.4", Type = DnsRecordType.A } });
            },
            QueryServerOverride = _ => Task.FromResult(new EdnsSupportInfo { Supported = true, UdpPayloadSize = 2048, DoBit = true })
        };

        await analysis.Analyze("example.com", log);
        Assert.Contains(warns, w => string.Equals(w.Code, EdnsCodes.BufferTooLarge));
    }

    [Fact]
    public async Task InfoOnTruncatedFallback()
    {
        var log = new InternalLogger();
        var infos = new List<LogEventArgs>();
        log.OnInformationMessage += (_, e) => infos.Add(e);

        var analysis = new EdnsSupportAnalysis
        {
            QueryDnsOverride = (name, type) =>
            {
                if (type == DnsRecordType.NS)
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "ns.example.com", Type = DnsRecordType.NS } });
                return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.2.3.4", Type = DnsRecordType.A } });
            },
            QueryServerOverride = _ => Task.FromResult(new EdnsSupportInfo { Supported = true, UdpPayloadSize = 1232, DoBit = false, TruncatedUdp = true })
        };

        await analysis.Analyze("example.com", log);
        Assert.Contains(infos, i => string.Equals(i.Code, EdnsCodes.TruncatedFallback));
    }
}

