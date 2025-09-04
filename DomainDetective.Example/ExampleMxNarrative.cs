using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example
{
    public static partial class Program
    {
        /// <summary>
        /// Demonstrates building a narrative from MX analysis.
        /// </summary>
        public static async Task ExampleMxNarrative()
        {
            var health = new DomainHealthCheck();
            await health.VerifyMX("gmail.com");
            var sections = MxNarrative.Build(health.MXAnalysis);
            Helpers.ShowPropertiesTable("MX Narrative", sections);
        }
    }
}
