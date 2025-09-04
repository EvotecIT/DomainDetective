using DnsClientX;
using DomainDetective.Narratives;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestNSNarrative
{
    [Fact]
    public async Task BuildsNarrativeWithPositives()
    {
        var answers = new List<DnsAnswer>
        {
            new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS },
            new DnsAnswer { DataRaw = "ns2.example.com", Type = DnsRecordType.NS }
        };
        var analysis = new NSAnalysis
        {
            DnsConfiguration = new DnsConfiguration(),
            QueryDnsOverride = (name, type) =>
            {
                return (name, type) switch
                {
                    ("ns1.example.com", DnsRecordType.A) => Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1" } }),
                    ("ns2.example.com", DnsRecordType.A) => Task.FromResult(new[] { new DnsAnswer { DataRaw = "2.2.2.2" } }),
                    _ => Task.FromResult(Array.Empty<DnsAnswer>())
                };
            }
        };
        await analysis.AnalyzeNsRecords(answers, new InternalLogger());

        var sections = NSNarrative.Build(analysis);

        Assert.Contains(sections.Highlights, h => h.IndexOf("geographically", System.StringComparison.OrdinalIgnoreCase) >= 0);
        Assert.Contains(sections.Positives, p => p.IndexOf("geographically", System.StringComparison.OrdinalIgnoreCase) >= 0);
    }
}
