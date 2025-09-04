using System.Threading.Tasks;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program
{
    public static async Task ExampleRpkiNarrative()
    {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.VerifyRPKI("example.com");
        var narrative = RpkiNarrative.Build(healthCheck.RpkiAnalysis, healthCheck.RpkiAnalysis.Assessments);
        Helpers.ShowPropertiesTable("RPKI Narrative", narrative);
    }
}

