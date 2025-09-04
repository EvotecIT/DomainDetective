using System.Threading.Tasks;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Demonstrates building a WHOIS narrative for a domain.
    /// </summary>
    public static async Task ExampleWhoisNarrative()
    {
        var healthCheck = new DomainHealthCheck();
        await healthCheck.CheckWHOIS("example.com");
        var narrative = WhoisNarrative.Build(healthCheck.WhoisAnalysis);
        Helpers.ShowPropertiesTable("WHOIS Narrative", narrative);
    }
}
