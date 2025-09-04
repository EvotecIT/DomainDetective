using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Demonstrates building a DNS tunneling narrative.
    /// </summary>
    public static async Task ExampleDnsTunnelingNarrative()
    {
        var hc = new DomainHealthCheck { Verbose = false };
        hc.DnsTunnelingLogs = new[] { "2024-01-01T00:00:00Z verylonglabelthatexceedslimit.example.com" };
        await hc.CheckDnsTunnelingAsync("example.com");
        var narrative = DnsTunnelingNarrative.Build(hc.DnsTunnelingAnalysis, hc.DnsTunnelingAnalysis.Assessments);
        Helpers.ShowPropertiesTable("DNS Tunneling Narrative", narrative);
    }
}
