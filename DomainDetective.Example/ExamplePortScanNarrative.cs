using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static class ExamplePortScanNarrative
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

        var validPorts = ports.Where(p => p > 0 && p <= 65535).Distinct().ToArray();
        if (validPorts.Length == 0)
        {
            throw new ArgumentException("No valid ports specified.", nameof(ports));
        }

        var analysis = new PortScanAnalysis { Timeout = TimeSpan.FromSeconds(1) };
        var logger = new InternalLogger();
        await analysis.Scan(host, validPorts, logger);
        var sections = PortScanNarrative.Build(analysis);
        Console.WriteLine(sections.Title);
    }
}
