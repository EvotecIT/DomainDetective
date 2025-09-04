using System;
using System.Threading.Tasks;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static class ExampleHttpNarrative
{
    public static async Task Run()
    {
        var analysis = new HttpAnalysis { Subject = "example.com" };
        var logger = new InternalLogger();
        await analysis.AnalyzeUrl("https://example.com", checkHsts: true, logger, collectHeaders: true);
        var sections = HttpNarrative.Build(analysis);
        Console.WriteLine(sections.Title);
    }
}
