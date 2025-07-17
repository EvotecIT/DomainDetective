using System;
using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Demonstrates checking an SNMP endpoint.
    /// </summary>
    public static async Task ExampleAnalyseSNMP()
    {
        var analysis = new SnmpAnalysis();
        await analysis.AnalyzeServer("demo.snmplabs.com", 161, new InternalLogger());
        foreach (var kvp in analysis.ServerResults)
        {
            Console.WriteLine($"{kvp.Key} responded: {kvp.Value}");
        }
    }
}
