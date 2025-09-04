using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;
using DnsClientX;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Demonstrates building a TLS-RPT narrative from a DNS record.
    /// </summary>
    public static async Task ExampleTlsRptNarrative()
    {
        var analysis = new TLSRPTAnalysis { Subject = "example.com" };
        await analysis.AnalyzeTlsRptRecords(new[]
        {
            new DnsAnswer { DataRaw = "v=TLSRPTv1;rua=mailto:reports@example.com", Type = DnsRecordType.TXT }
        }, new InternalLogger());
        var narrative = TlsRptNarrative.Build(analysis);
        Helpers.ShowPropertiesTable("TLS-RPT Narrative", narrative);
    }
}
