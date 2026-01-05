using System.Linq;
using System.Threading.Tasks;
using DnsClientX;
using DomainDetective;
using Xunit;

namespace DomainDetective.Tests;

public class TestNSAsnDiversity
{
    [Fact]
    public async Task EmitsHighDiversityWhenAsnDiffers()
    {
        var logger = new InternalLogger();
        var analysis = new NSAnalysis
        {
            Subject = "example.com",
            EnableChaosFingerprinting = false,
            // Return A records for NS hosts
            QueryDnsOverride = (name, type) =>
            {
                if (type == DnsRecordType.NS && name == "example.com")
                {
                    return Task.FromResult(new[] {
                        new DnsAnswer { Type = DnsRecordType.NS, DataRaw = "ns1.example.net." },
                        new DnsAnswer { Type = DnsRecordType.NS, DataRaw = "ns2.example.net." }
                    });
                }
                if (type == DnsRecordType.A && name == "ns1.example.net.")
                {
                    return Task.FromResult(new[] { new DnsAnswer { Type = DnsRecordType.A, DataRaw = "198.51.100.10" } });
                }
                if (type == DnsRecordType.A && name == "ns2.example.net.")
                {
                    return Task.FromResult(new[] { new DnsAnswer { Type = DnsRecordType.A, DataRaw = "198.51.100.20" } });
                }
                return Task.FromResult(Array.Empty<DnsAnswer>());
            },
            // Force different ASNs so diversity triggers even if subnet key would match
            LookupAsnOverride = ip => Task.FromResult<int?>(ip.EndsWith(".10") ? 64512 : 64513)
        };

        var nsAnswers = new[] {
            new DnsAnswer { Type = DnsRecordType.NS, DataRaw = "ns1.example.net." },
            new DnsAnswer { Type = DnsRecordType.NS, DataRaw = "ns2.example.net." }
        };

        await analysis.AnalyzeNsRecords(nsAnswers, logger);

        Assert.True(analysis.HasDiverseLocations);
        Assert.True(analysis.AsnDistinctCount >= 2);
        Assert.Contains(analysis.Assessments, a => a.Code == NSCodes.HighDiversity && a.Severity == AssessmentSeverity.Info);
    }
}

