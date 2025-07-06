using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task ExampleFlattenSpfIps() {
        var healthCheck = new DomainHealthCheck();
        await healthCheck.Verify("github.com", [HealthCheckType.SPF]);
        var ips = await healthCheck.SpfAnalysis.GetFlattenedIpAddresses("github.com");
        Helpers.ShowPropertiesTable("Flattened SPF IPs for github.com", ips);
    }
}
