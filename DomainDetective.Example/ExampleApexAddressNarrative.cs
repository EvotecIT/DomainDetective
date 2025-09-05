using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example
{
    public static partial class Program
    {
        /// <summary>
        /// Demonstrates building a narrative from apex address analysis.
        /// </summary>
        public static async Task ExampleApexAddressNarrative()
        {
            var health = new DomainHealthCheck();
            await health.Verify("gmail.com", new[] { HealthCheckType.APEXADDRESS });
            var sections = ApexAddressNarrative.Build(health.ApexAddressAnalysis);
            Helpers.ShowPropertiesTable("Apex Address Narrative", sections);
        }
    }
}
