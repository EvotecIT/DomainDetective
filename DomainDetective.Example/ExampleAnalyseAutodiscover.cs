using System;
using System.Linq;
using System.Threading.Tasks;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

/// <summary>
/// Demonstrates Autodiscover analysis.
/// </summary>
public static partial class Program {
    /// <summary>Runs the Autodiscover example.</summary>
    public static async Task ExampleAnalyseAutodiscover() {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        await healthCheck.VerifyAutodiscover("example.com");
        Helpers.ShowPropertiesTable("Autodiscover DNS", healthCheck.AutodiscoverAnalysis);
        Helpers.ShowPropertiesTable("Autodiscover Endpoints", healthCheck.AutodiscoverHttpAnalysis.Endpoints);
        var narrative = AutodiscoverNarrative.Build(
            healthCheck.AutodiscoverAnalysis,
            healthCheck.AutodiscoverAnalysis.Assessments
                .Concat(healthCheck.AutodiscoverHttpAnalysis.Assessments));
        Console.WriteLine(narrative.Title);
        foreach (var h in narrative.Highlights) Console.WriteLine(" - " + h);
    }
}
