using System.Threading.Tasks;
using DomainDetective.Narratives;
using DnsClientX;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Demonstrates building a typosquatting narrative.
    /// </summary>
    public static async Task ExampleTyposquattingNarrative()
    {
        var hc = new DomainHealthCheck();
        hc.TyposquattingAnalysis.QueryDnsOverride = (name, type) =>
        {
            if (name == "examp1e.com" && type == DnsRecordType.A)
            {
                return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1", Type = DnsRecordType.A } });
            }
            return Task.FromResult(System.Array.Empty<DnsAnswer>());
        };
        await hc.VerifyTyposquatting("example.com");
        var narrative = TyposquattingNarrative.Build(hc.TyposquattingAnalysis);
        Helpers.ShowPropertiesTable("Typosquatting Narrative", narrative);
    }
}
