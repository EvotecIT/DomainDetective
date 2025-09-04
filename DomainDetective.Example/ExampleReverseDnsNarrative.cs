using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example
{
    public static partial class Program
    {
        /// <summary>
        /// Demonstrates building a narrative from reverse DNS analysis.
        /// </summary>
        public static async Task ExampleReverseDnsNarrative()
        {
            var health = new DomainHealthCheck();
            await health.Verify("gmail.com", new[] { HealthCheckType.REVERSEDNS });
            var sections = ReverseDnsNarrative.Build(health.ReverseDnsAnalysis);
            Helpers.ShowPropertiesTable("Reverse DNS Narrative", sections);
        }
    }
}
