using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static class ExamplePortAvailabilityNarrative
{
    public static async Task Run(string host, IEnumerable<int> ports)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            throw new ArgumentException("Host is required.", nameof(host));
        }

        if (ports == null)
        {
            throw new ArgumentNullException(nameof(ports));
        }

        var valid = ports.Where(p => p > 0 && p <= 65535).Distinct().ToArray();
        if (valid.Length == 0)
        {
            throw new ArgumentException("No valid ports specified.", nameof(ports));
        }

        var analysis = new PortAvailabilityAnalysis();
        var logger = new InternalLogger();
        await analysis.AnalyzeServers(new[] { host }, valid, logger);
        var sections = PortAvailabilityNarrative.Build(analysis);
        Console.WriteLine(sections.Title);
    }
}
