using System;
using System.Threading.Tasks;
using DnsClientX;
using DomainDetective;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests;

public class TestDnsHealthNarrative
{
    [Fact]
    public async Task BuildsNarrativeWithPositives()
    {
        var analysis = new DnsHealthAnalysis
        {
            DnsConfiguration = new DnsConfiguration
            {
                QueryDnsOverride = (name, type) =>
                {
                    return (name, type) switch
                    {
                        ("example.com", DnsRecordType.NS) => Task.FromResult(new[]
                        {
                            new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS },
                            new DnsAnswer { DataRaw = "ns2.example.com", Type = DnsRecordType.NS }
                        }),
                        ("ns1.example.com", DnsRecordType.A) => Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1", Type = DnsRecordType.A } }),
                        ("ns1.example.com", DnsRecordType.AAAA) => Task.FromResult(Array.Empty<DnsAnswer>()),
                        ("ns2.example.com", DnsRecordType.A) => Task.FromResult(new[] { new DnsAnswer { DataRaw = "2.2.2.2", Type = DnsRecordType.A } }),
                        ("ns2.example.com", DnsRecordType.AAAA) => Task.FromResult(Array.Empty<DnsAnswer>()),
                        ("example.com", DnsRecordType.SOA) => Task.FromResult(new[] { new DnsAnswer { DataRaw = "ns1.example.com hostmaster.example.com 12345 7200 900 1209600 3600", Type = DnsRecordType.SOA } }),
                        ("example.com", DnsRecordType.A) => Task.FromResult(new[] { new DnsAnswer { DataRaw = "9.9.9.9", Type = DnsRecordType.A } }),
                        ("example.com", DnsRecordType.AAAA) => Task.FromResult(Array.Empty<DnsAnswer>()),
                        _ => Task.FromResult(Array.Empty<DnsAnswer>())
                    };
                }
            }
        };
        await analysis.Analyze("example.com", new InternalLogger());
        var sections = DnsHealthNarrative.Build(analysis);
        Assert.Contains(sections.Highlights, h => h.Contains("SOA serial numbers match", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(sections.Highlights, h => h.Contains("authoritative servers responded", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(sections.Positives, p => p.Contains("SOA serial numbers", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(sections.Positives, p => p.Contains("name servers responded", StringComparison.OrdinalIgnoreCase));
    }
}
