using System.Threading.Tasks;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task ExampleAnalyseBIMI() {
        var healthCheck = new DomainHealthCheck();
        await healthCheck.Verify("github.com", [HealthCheckType.BIMI]);
        var narrative = BimiNarrative.Build(healthCheck.BimiAnalysis);
        Helpers.ShowPropertiesTable("BIMI narrative for github.com", narrative);
    }
}
