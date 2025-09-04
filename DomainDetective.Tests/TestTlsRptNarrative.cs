using System.Threading.Tasks;
using DomainDetective.Narratives;
using DnsClientX;

namespace DomainDetective.Tests;

public class TestTlsRptNarrative
{
    [Fact]
    public async Task TlsRptNarrativeHighlightsAndPositives()
    {
        var analysis = new TLSRPTAnalysis { Subject = "example.com" };
        await analysis.AnalyzeTlsRptRecords(new[]
        {
            new DnsAnswer { DataRaw = "v=TLSRPTv1;rua=mailto:reports@example.com", Type = DnsRecordType.TXT }
        }, new InternalLogger());
        var sections = TlsRptNarrative.Build(analysis);
        Assert.Contains("TLS-RPT record is published.", sections.Highlights);
        Assert.Contains("Report URIs: 1 mailto, 0 https", sections.Highlights);
        Assert.Contains("TLSRPT record present", sections.Positives);
        Assert.Contains("TLSRPT starts with v=TLSRPTv1", sections.Positives);
    }
}
