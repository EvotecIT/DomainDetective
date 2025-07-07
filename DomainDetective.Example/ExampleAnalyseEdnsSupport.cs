using System.Threading.Tasks;

namespace DomainDetective.Example;

/// <summary>
/// Demonstrates EDNS support analysis.
/// </summary>
public static partial class Program {
    /// <summary>Runs the EDNS support example.</summary>
    public static async Task ExampleAnalyseEdnsSupport() {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.VerifyEdnsSupport("example.com");
        Helpers.ShowPropertiesTable("EDNS support", healthCheck.EdnsSupportAnalysis.ServerSupport);
    }
}
