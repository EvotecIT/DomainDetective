using System.Threading.Tasks;

namespace DomainDetective.Example;

/// <summary>
/// Demonstrates building a summary of domain health information.
/// </summary>
public static partial class Program {
    /// <summary>Runs the summary example.</summary>
    public static async Task ExampleDomainSummary() {
        var healthCheck = new DomainHealthCheck();
        await healthCheck.Verify("github.com");
        var summary = healthCheck.BuildSummary();
        Helpers.ShowPropertiesTable("Summary for github.com", summary);
    }
}
