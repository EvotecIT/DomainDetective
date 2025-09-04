using System;
using System.Threading.Tasks;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static class ExamplePortScanNarrative
{
    public static async Task Run()
    {
        var analysis = new PortScanAnalysis { Timeout = TimeSpan.FromSeconds(1) };
        var logger = new InternalLogger();
        await analysis.Scan("scanme.nmap.org", new[] { 22, 80 }, logger);
        var sections = PortScanNarrative.Build(analysis);
        Console.WriteLine(sections.Title);
    }
}
