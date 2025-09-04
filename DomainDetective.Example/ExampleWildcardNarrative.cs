using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example
{
    public static partial class Program
    {
        /// <summary>
        /// Demonstrates building a narrative from wildcard DNS analysis.
        /// </summary>
        public static async Task ExampleWildcardNarrative()
        {
            var health = new DomainHealthCheck();
            await health.VerifyWildcardDns("example.com");
            var sections = WildcardNarrative.Build(health.WildcardDnsAnalysis);
            Helpers.ShowPropertiesTable("Wildcard DNS Narrative", sections);
        }
    }
}
