using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task ExampleAnalyseThreatIntel() {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.VerifyThreatIntel("example.com");
        Helpers.ShowPropertiesTable("Threat intel for example.com", healthCheck.ThreatIntelAnalysis);
    }
}
