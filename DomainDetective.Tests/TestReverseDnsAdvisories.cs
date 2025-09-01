using DnsClientX;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestReverseDnsAdvisories
{
    [Fact]
    public async Task WarnsOnForwardMismatch()
    {
        var map = new Dictionary<(string, DnsRecordType), DnsAnswer[]>
        {
            [("host.example.com", DnsRecordType.A)] = new[] { new DnsAnswer { DataRaw = "203.0.113.10", Type = DnsRecordType.A } },
            [("10.113.0.203.in-addr.arpa", DnsRecordType.PTR)] = new[] { new DnsAnswer { DataRaw = "ptr.example.net.", Type = DnsRecordType.PTR } },
            [("ptr.example.net", DnsRecordType.A)] = new[] { new DnsAnswer { DataRaw = "203.0.113.11", Type = DnsRecordType.A } }
        };

        var warns = new List<LogEventArgs>();
        var logger = new InternalLogger();
        logger.OnWarningMessage += (_, e) => warns.Add(e);

        var analysis = new ReverseDnsAnalysis
        {
            DnsConfiguration = new DnsConfiguration(),
            QueryDnsOverride = (name, type) => Task.FromResult(map.TryGetValue((name, type), out var v) ? v : System.Array.Empty<DnsAnswer>())
        };

        await analysis.AnalyzeHosts(new[] { "host.example.com" }, logger);
        Assert.Contains(warns, w => string.Equals(w.Code, ReverseDnsCodes.ForwardMismatch));
    }
}

