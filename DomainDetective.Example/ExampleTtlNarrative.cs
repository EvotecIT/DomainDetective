using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Demonstrates building a DNS TTL narrative.
    /// </summary>
    public static async Task ExampleTtlNarrative()
    {
        var hc = new DomainHealthCheck { Verbose = false };
        await hc.Verify("evotec.pl", new[] { HealthCheckType.TTL });
        var narrative = TtlNarrative.Build(hc.DnsTtlAnalysis, hc.DnsTtlAnalysis.Assessments);
        Helpers.ShowPropertiesTable("TTL Narrative", narrative);
    }
}
