using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    /// <summary>
    /// Example demonstrating DNS TTL analysis.
    /// </summary>
    public static async Task ExampleAnalyseDnsTtl() {
        var healthCheck = new DomainHealthCheck { Verbose = false };
        await healthCheck.Verify("evotec.pl", new[] { HealthCheckType.TTL });
        Helpers.ShowPropertiesTable(analysisOf: "DNS TTL", objs: healthCheck.DnsTtlAnalysis);
    }
}
