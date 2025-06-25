using System;
using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task ExampleDetectUnsafeCsp() {
        var analysis = await HttpAnalysis.CheckUrl("https://www.google.com", collectHeaders: true);
        Console.WriteLine($"Unsafe directives detected: {analysis.CspUnsafeDirectives}");
    }
}
