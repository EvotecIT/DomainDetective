using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program {
    /// <summary>
    /// Demonstrates building a narrative for flattened SPF results.
    /// </summary>
    public static async Task ExampleSpfFlattenedNarrative() {
        var hc = new DomainHealthCheck();
        await hc.Verify("github.com", [HealthCheckType.SPF]);
        var narrative = SpfFlattenedNarrative.Build(hc.SpfAnalysis, hc.SpfAnalysis.Assessments);
        Helpers.ShowPropertiesTable("SPF Flattened Narrative", narrative);
    }
}
