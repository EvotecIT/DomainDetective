using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example {
    public static partial class Program {
        /// <summary>
        /// Demonstrates building a narrative from threat intelligence analysis.
        /// </summary>
        public static async Task ExampleThreatIntelNarrative() {
            var analysis = new ThreatIntelAnalysis { EnableUrlHaus = false };
            await analysis.Analyze("example.com", null, null, null, new InternalLogger());
            var sections = ThreatIntelNarrative.Build(analysis);
            Helpers.ShowPropertiesTable("Threat Intel Narrative", sections);
        }
    }
}
