using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task ExampleAnalyseHTTP() {
        var analysis = await HttpAnalysis.CheckUrl("https://www.google.com", true);
        Helpers.ShowPropertiesTable("HTTP Analysis for google.com", analysis);
    }

    public static async Task ExampleAnalyseHTTPByHealthCheck() {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.Verify("google.com", new[] { HealthCheckType.HTTP });
        Helpers.ShowPropertiesTable("HTTP Analysis via HealthCheck", healthCheck.HttpAnalysis);
    }
}