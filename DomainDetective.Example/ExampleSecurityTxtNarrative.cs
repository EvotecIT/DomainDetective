using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program {
    /// <summary>
    /// Demonstrates building a security.txt narrative for a domain.
    /// </summary>
    public static async Task ExampleSecurityTxtNarrative() {
        var healthCheck = new DomainHealthCheck();
        await healthCheck.Verify("securitytxt.org", new[] { HealthCheckType.SECURITYTXT });
        var narrative = SecurityTxtNarrative.Build(healthCheck.SecurityTXTAnalysis);
        Helpers.ShowPropertiesTable("security.txt Narrative", narrative);
    }
}

