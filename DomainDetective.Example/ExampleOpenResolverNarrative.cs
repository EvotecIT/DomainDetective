using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Demonstrates building an Open Resolver narrative from analysis results.
    /// </summary>
    public static async Task ExampleOpenResolverNarrative()
    {
        var analysis = new OpenResolverAnalysis
        {
            RecursionTestOverride = (_, _) => Task.FromResult(false)
        };
        var logger = new InternalLogger();
        await analysis.AnalyzeServer("resolver.example.com", 53, logger);
        var narrative = OpenResolverNarrative.Build(analysis, analysis.Assessments);
        Helpers.ShowPropertiesTable("Open Resolver Narrative", narrative);
    }
}

