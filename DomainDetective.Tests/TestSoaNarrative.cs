using DnsClientX;
using DomainDetective.Narratives;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestSoaNarrative
{
    [Fact]
    public async Task BuildsNarrativeWithPositives()
    {
        var soaRecords = new List<DnsAnswer>
        {
            new DnsAnswer { DataRaw = "ns1.example.com. hostmaster.example.com. 2023102301 3600 600 1209600 300", Type = DnsRecordType.SOA }
        };
        var nsRecords = new List<DnsAnswer>
        {
            new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS }
        };
        var analysis = new SOAAnalysis();
        await analysis.AnalyzeSoaRecords(soaRecords, new InternalLogger(), nsRecords);
        var sections = SoaNarrative.Build(analysis);
        Assert.Contains(sections.Highlights, h => h.Contains("Primary NS"));
        Assert.Contains(sections.Highlights, h => h.Contains("Serial"));
        Assert.Contains(sections.Positives, p => p.Contains("Refresh interval within recommended range"));
        Assert.Contains(sections.Positives, p => p.Contains("primary NS matches"));
    }
}
