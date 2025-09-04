using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Demonstrates building an Open Relay narrative from analysis results.
    /// </summary>
    public static Task ExampleOpenRelayNarrative()
    {
        var analysis = new OpenRelayAnalysis();
        analysis.ServerResults["smtp.example.com:25"] = new OpenRelayAnalysis.OpenRelayResult
        {
            Status = OpenRelayStatus.Denied
        };
        var narrative = OpenRelayNarrative.Build(analysis);
        Helpers.ShowPropertiesTable("Open Relay Narrative", narrative);
        return Task.CompletedTask;
    }
}
