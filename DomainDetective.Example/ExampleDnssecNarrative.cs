using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Demonstrates building a DNSSEC narrative.
    /// </summary>
    public static async Task ExampleDnssecNarrative()
    {
        var analysis = new DnsSecAnalysis();
        await analysis.Analyze("example.com", new InternalLogger());
        var narrative = DnssecNarrative.Build(analysis);
        Helpers.ShowPropertiesTable("DNSSEC Narrative", narrative);
    }
}
