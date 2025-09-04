using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Demonstrates building an NS narrative from live data.
    /// </summary>
    public static async Task ExampleNSNarrative()
    {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.Verify("evotec.pl", new[] { HealthCheckType.NS });
        var narrative = NSNarrative.Build(healthCheck.NSAnalysis);
        Helpers.ShowPropertiesTable("NS Narrative", narrative);
    }
}
