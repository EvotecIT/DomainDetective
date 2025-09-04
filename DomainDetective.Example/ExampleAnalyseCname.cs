using System;
using System.Threading.Tasks;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

/// <summary>
/// Demonstrates CNAME analysis.
/// </summary>
public static partial class Program {
    /// <summary>Runs the CNAME example.</summary>
    public static async Task ExampleAnalyseCname() {
        var analysis = new CnameAnalysis { DnsConfiguration = new DnsConfiguration() };
        await analysis.Analyze("www.example.com", new InternalLogger());
        Helpers.ShowPropertiesTable("CNAME for www.example.com", analysis);
        var narrative = CnameNarrative.Build(analysis, analysis.Assessments);
        Console.WriteLine(narrative.Title);
        foreach (var h in narrative.Highlights) Console.WriteLine(" - " + h);
    }
}
