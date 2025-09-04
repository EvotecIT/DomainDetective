using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Demonstrates building a DNS health narrative from live data.
    /// </summary>
    public static async Task ExampleDnsHealthNarrative()
    {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.Verify("evotec.pl", new[] { HealthCheckType.DNSHEALTH });
        var narrative = DnsHealthNarrative.Build(healthCheck.DnsHealthAnalysis);
        Helpers.ShowPropertiesTable("DNS Health Narrative", narrative);
    }
}
