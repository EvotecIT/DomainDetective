using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestFCrDnsAnalysis
{
    private static FCrDnsAnalysis CreateAnalysis(Dictionary<(string, DnsRecordType), DnsAnswer[]> map)
    {
        return new FCrDnsAnalysis
        {
            DnsConfiguration = new DnsConfiguration(),
            QueryDnsOverride = (name, type) => Task.FromResult(map.TryGetValue((name, type), out var v) ? v : Array.Empty<DnsAnswer>())
        };
    }

    private static ReverseDnsAnalysis CreateReverse(Dictionary<(string, DnsRecordType), DnsAnswer[]> map)
    {
        return new ReverseDnsAnalysis
        {
            DnsConfiguration = new DnsConfiguration(),
            QueryDnsOverride = (name, type) => Task.FromResult(map.TryGetValue((name, type), out var v) ? v : Array.Empty<DnsAnswer>())
        };
    }

    [Fact]
    public async Task ValidForwardConfirmation()
    {
        var map = new Dictionary<(string, DnsRecordType), DnsAnswer[]>
        {
            [("mail.example.com", DnsRecordType.A)] = new[] { new DnsAnswer { DataRaw = "1.1.1.1" } },
            [("1.1.1.1.in-addr.arpa", DnsRecordType.PTR)] = new[] { new DnsAnswer { DataRaw = "mail.example.com." } },
            [("mail.example.com", DnsRecordType.AAAA)] = Array.Empty<DnsAnswer>()
        };
        var rdns = CreateReverse(map);
        await rdns.AnalyzeHosts(new[] { "mail.example.com" });
        var analysis = CreateAnalysis(map);
        await analysis.Analyze(rdns.Results);
        var result = Assert.Single(analysis.Results);
        Assert.True(result.ForwardConfirmed);
    }

    [Fact]
    public async Task InvalidForwardConfirmation()
    {
        var map = new Dictionary<(string, DnsRecordType), DnsAnswer[]>
        {
            [("mail.example.com", DnsRecordType.A)] = new[] { new DnsAnswer { DataRaw = "1.1.1.2" } },
            [("1.1.1.2.in-addr.arpa", DnsRecordType.PTR)] = new[] { new DnsAnswer { DataRaw = "ptr.example.com." } },
            [("ptr.example.com", DnsRecordType.A)] = new[] { new DnsAnswer { DataRaw = "9.9.9.9" } }
        };
        var rdns = CreateReverse(map);
        await rdns.AnalyzeHosts(new[] { "mail.example.com" });
        var analysis = CreateAnalysis(map);
        await analysis.Analyze(rdns.Results);
        var result = Assert.Single(analysis.Results);
        Assert.False(result.ForwardConfirmed);
    }

    [Fact]
    public async Task TrailingDotInPtrRecordIsHandled()
    {
        var map = new Dictionary<(string, DnsRecordType), DnsAnswer[]>
        {
            [("mail.example.com", DnsRecordType.A)] = new[] { new DnsAnswer { DataRaw = "1.1.1.3" } },
            [("mail.example.com", DnsRecordType.AAAA)] = Array.Empty<DnsAnswer>()
        };
        var analysis = CreateAnalysis(map);
        var reverse = new[]
        {
            new ReverseDnsAnalysis.ReverseDnsResult
            {
                IpAddress = "1.1.1.3",
                PtrRecord = "mail.example.com.",
                ExpectedHost = "mail.example.com"
            }
        };
        await analysis.Analyze(reverse);
        var result = Assert.Single(analysis.Results);
        Assert.True(result.ForwardConfirmed);
    }
}
