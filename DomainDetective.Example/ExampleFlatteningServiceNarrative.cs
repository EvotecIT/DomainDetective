using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Demonstrates building a flattening service narrative.
    /// </summary>
    public static async Task ExampleFlatteningServiceNarrative()
    {
        var analysis = new FlatteningServiceAnalysis();
        await analysis.Analyze("example.com", new InternalLogger());
        var narrative = FlatteningServiceNarrative.Build(analysis, analysis.Assessments);
        Helpers.ShowPropertiesTable("Flattening Service Narrative", narrative);
    }
}

