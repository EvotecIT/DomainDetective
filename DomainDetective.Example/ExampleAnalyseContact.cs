using System.Threading.Tasks;

namespace DomainDetective.Example;

/// <summary>
/// Demonstrates analysis of contact TXT records.
/// </summary>
public static partial class Program {
    /// <summary>Runs the contact TXT analysis example.</summary>
    public static async Task ExampleAnalyseContact() {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.CheckContactInfo("email=admin@example.com; phone=12345");
        Helpers.ShowPropertiesTable(analysisOf: "Contact record", objs: healthCheck.ContactInfoAnalysis);

        await healthCheck.VerifyContactInfo("example.com");
        Helpers.ShowPropertiesTable(analysisOf: "Contact TXT for example.com", objs: healthCheck.ContactInfoAnalysis);
    }
}
