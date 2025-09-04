using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Demonstrates building a Zone Transfer narrative and listing positives.
    /// </summary>
    public static Task ExampleZoneTransferNarrative()
    {
        var analysis = new ZoneTransferAnalysis();
        analysis.ServerResults["ns1.example.com"] = false;
        analysis.Assessments.Add(new Assessment
        {
            Code = "AXFR.Restricted",
            Severity = AssessmentSeverity.Info,
            Message = "AXFR refused on ns1.example.com",
            Category = "AXFR",
            Target = "ns1.example.com"
        });
        var narrative = ZoneTransferNarrative.Build(analysis);
        Helpers.ShowPropertiesTable("Zone Transfer Narrative", narrative);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        Helpers.ShowPropertiesTable("Zone Transfer Positives", positives);
        return Task.CompletedTask;
    }
}
