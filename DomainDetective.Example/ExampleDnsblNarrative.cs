using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Demonstrates building a DNSBL narrative.
    /// </summary>
    public static async Task ExampleDnsblNarrative()
    {
        var health = new DomainHealthCheck();
        await health.CheckDNSBL("example.com");
        var sections = DnsblNarrative.Build(health.DNSBLAnalysis);
        Helpers.ShowPropertiesTable("DNSBL Narrative", sections);
    }
}

