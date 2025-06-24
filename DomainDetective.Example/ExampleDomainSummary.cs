using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task ExampleDomainSummary() {
        var healthCheck = new DomainHealthCheck();
        await healthCheck.Verify("github.com");
        var summary = healthCheck.BuildSummary();
        Helpers.ShowPropertiesTable("Summary for github.com", summary);
    }
}
