using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    /// <summary>
    /// Shows how to run a simple HTTP analysis for a single URL.
    /// </summary>
    public static async Task ExampleAnalyseHTTP() {
        var analysis = await HttpAnalysis.CheckUrl("https://www.google.com", true);
        Helpers.ShowPropertiesTable("HTTP Analysis for google.com", analysis);
    }

    /// <summary>
    /// Demonstrates running the HTTP check via <see cref="DomainHealthCheck"/>.
    /// </summary>
    public static async Task ExampleAnalyseHTTPByHealthCheck() {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.Verify("google.com", new[] { HealthCheckType.HTTP });
        Helpers.ShowPropertiesTable("HTTP Analysis via HealthCheck", healthCheck.HttpAnalysis);
    }
}