using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Demonstrates building an SOA narrative from live data.
    /// </summary>
    public static async Task ExampleSoaNarrative()
    {
        var healthCheck = new DomainHealthCheck { Verbose = false };
        await healthCheck.Verify("evotec.pl", new[] { HealthCheckType.SOA });
        var narrative = SoaNarrative.Build(healthCheck.SOAAnalysis);
        Helpers.ShowPropertiesTable("SOA Narrative", narrative);
    }
}
