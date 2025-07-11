using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task ExampleAnalyseRpki() {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.VerifyRPKI("example.com");
        Helpers.ShowPropertiesTable("RPKI for example.com", healthCheck.RpkiAnalysis.Results);
    }
}
