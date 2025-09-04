using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Demonstrates building an Open Resolver narrative from synthetic analysis data.
    /// </summary>
    public static void ExampleOpenResolverNarrative()
    {
        var analysis = new OpenResolverAnalysis
        {
            Subject = "resolver.example.com"
        };

        analysis.ServerDetails["resolver.example.com:53"] = new OpenResolverResult
        {
            Host = "resolver.example.com",
            Port = 53,
            IsOpenResolver = false,
            ResponseBytes = 60
        };

        var narrative = OpenResolverNarrative.Build(analysis);
        Helpers.ShowPropertiesTable("Open Resolver Narrative", narrative);
    }
}

