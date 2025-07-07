using System.Threading.Tasks;

namespace DomainDetective.Example;

/// <summary>
/// Demonstrates analysis of SECURITYTXT files.
/// </summary>
public static partial class Program {
    /// <summary>Runs the SECURITYTXT example.</summary>
    public static async Task ExampleAnalyseSecurityTXT() {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.Verify("google.com", new[] { HealthCheckType.SECURITYTXT });
        Helpers.ShowPropertiesTable(analysisOf: "SECURITYTXT for google.com", objs: healthCheck.SecurityTXTAnalysis);

        await healthCheck.Verify("www.gemini.com", new[] { HealthCheckType.SECURITYTXT });
        Helpers.ShowPropertiesTable(analysisOf: "SECURITYTXT for gemini.com", objs: healthCheck.SecurityTXTAnalysis);

        await healthCheck.Verify("www.facebook.com", new[] { HealthCheckType.SECURITYTXT });
        Helpers.ShowPropertiesTable(analysisOf: "SECURITYTXT for www.facebook.com", objs: healthCheck.SecurityTXTAnalysis);

        await healthCheck.Verify("evotec.xyz", new[] { HealthCheckType.SECURITYTXT });
        Helpers.ShowPropertiesTable(analysisOf: "SECURITYTXT for evotec.xyz", objs: healthCheck.SecurityTXTAnalysis);

        await healthCheck.Verify("gov.uk", new[] { HealthCheckType.SECURITYTXT });
        Helpers.ShowPropertiesTable(analysisOf: "SECURITYTXT for gov.uk", objs: healthCheck.SecurityTXTAnalysis);

        await healthCheck.Verify("securitytxt.org", new[] { HealthCheckType.SECURITYTXT });
        Helpers.ShowPropertiesTable(analysisOf: "SECURITYTXT for securitytxt.org", objs: healthCheck.SecurityTXTAnalysis);
    }
}