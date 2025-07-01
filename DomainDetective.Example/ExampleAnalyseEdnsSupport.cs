using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task ExampleAnalyseEdnsSupport() {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.VerifyEdnsSupport("example.com");
        Helpers.ShowPropertiesTable("EDNS support", healthCheck.EdnsSupportAnalysis.ServerSupport);
    }
}
