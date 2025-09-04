using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example
{
    public static partial class Program
    {
        /// <summary>
        /// Demonstrates building an IP neighbor narrative from live data.
        /// </summary>
        public static async Task ExampleIpNeighborNarrative()
        {
            var healthCheck = new DomainHealthCheck();
            await healthCheck.Verify("evotec.pl", new[] { HealthCheckType.IPNEIGHBOR });
            var narrative = IpNeighborNarrative.Build(healthCheck.IPNeighborAnalysis);
            Helpers.ShowPropertiesTable("IP Neighbor Narrative", narrative);
        }
    }
}

