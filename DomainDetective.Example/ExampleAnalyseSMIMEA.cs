using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task ExampleAnalyseSMIMEA() {
        var healthCheck = new DomainHealthCheck();
        await healthCheck.VerifySMIMEA("user@example.com");
        Helpers.ShowPropertiesTable("SMIMEA for user@example.com", healthCheck.SmimeaAnalysis);
        Helpers.ShowPropertiesTable("SMIMEA recommendations", healthCheck.SmimeaAnalysis.Recommendations);
    }
}

