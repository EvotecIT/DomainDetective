using DnsClientX;
using System.Collections.Generic;
using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests;

public class TestApexAddressNarrative
{
    [Fact]
    public async Task BuildsNarrative()
    {
        var map = new Dictionary<(string, DnsRecordType), DnsAnswer[]>
        {
            [("example.com", DnsRecordType.A)] = new[] { new DnsAnswer { DataRaw = "8.8.8.8", Type = DnsRecordType.A } },
            [("8.8.8.8.in-addr.arpa", DnsRecordType.PTR)] = new[] { new DnsAnswer { DataRaw = "apex.example.com.", Type = DnsRecordType.PTR } },
            [("apex.example.com", DnsRecordType.A)] = new[] { new DnsAnswer { DataRaw = "8.8.8.8", Type = DnsRecordType.A } }
        };
        var analysis = new ApexAddressAnalysis
        {
            DnsConfiguration = new DnsConfiguration(),
            QueryDnsOverride = (name, type) => Task.FromResult(map.TryGetValue((name, type), out var v) ? v : System.Array.Empty<DnsAnswer>())
        };
        await analysis.AnalyzeAsync("example.com");
        var sections = ApexAddressNarrative.Build(analysis);
        Assert.Contains(sections.Highlights, h => h.Contains("A records"));
        Assert.Contains(sections.Highlights, h => h.Contains("Reverse DNS"));
        Assert.Contains(sections.Details, d => d.Contains("8.8.8.8"));
    }

    [Fact]
    public void GeneratesPositiveAdvice()
    {
        var assessments = new List<Assessment>
        {
            new Assessment { Code = ApexAddressCodes.PubliclyRoutable, Severity = AssessmentSeverity.Info },
            new Assessment { Code = ApexAddressCodes.FcrDnsValid, Severity = AssessmentSeverity.Info }
        };
        var positives = RecommendationEngine.FromPositives(assessments);
        Assert.Contains(positives, p => p.Code == ApexAddressCodes.PubliclyRoutable);
        Assert.Contains(positives, p => p.Code == ApexAddressCodes.FcrDnsValid);
    }
}
