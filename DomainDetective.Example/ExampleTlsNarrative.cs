using System;
using System.Threading.Tasks;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static class ExampleTlsNarrative
{
    public static async Task Run()
    {
        using var analysis = new TlsAnalysis { Subject = "example.com" };
        var logger = new InternalLogger();
        await analysis.AnalyzeServer("example.com", 443, logger);
        var sections = TlsNarrative.Build(analysis);
        Console.WriteLine(sections.Title);
    }
}

