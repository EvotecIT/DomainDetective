using DnsClientX;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestApexAddressAnalysisDebug
{
    [Fact]
    public async Task AnalyzeApexAnswers_PopulatesARecords()
    {
        var analysis = new DomainDetective.ApexAddressAnalysis();
        var a = new[] { new DnsAnswer { DataRaw = "203.0.113.5", Type = DnsRecordType.A } };
        await analysis.AnalyzeApexAnswers(a, System.Array.Empty<DnsAnswer>());
        Assert.True(analysis.HasAnyAddress);
        Assert.True(analysis.HasARecord);
        Assert.False(analysis.HasAaaaRecord);
    }
}

