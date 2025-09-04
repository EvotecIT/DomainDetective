using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Example performing MTA-STS analysis by querying a domain.
    /// </summary>
    public static async Task ExampleAnalyseMTASTS()
    {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.Verify("example.com", [HealthCheckType.MTASTS]);
        Helpers.ShowPropertiesTable("MTA-STS for example.com", healthCheck.MTASTSAnalysis);
    }
}
