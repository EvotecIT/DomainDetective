using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Demonstrates building an RDAP narrative for a domain.
    /// </summary>
    public static async Task ExampleRdapNarrative()
    {
        var healthCheck = new DomainHealthCheck();
        await healthCheck.QueryRDAP("example.com");
        var narrative = RdapNarrative.Build(healthCheck.RdapAnalysis);
        Helpers.ShowPropertiesTable("RDAP Narrative", narrative);
    }
}
