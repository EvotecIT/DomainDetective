using System;
using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Demonstrates checking connectivity to common service ports.
    /// </summary>
    public static async Task ExamplePortAvailability()
    {
        var analysis = new PortAvailabilityAnalysis { Timeout = TimeSpan.FromSeconds(1) };
        var logger = new InternalLogger();
        await analysis.AnalyzeServers(new[] { "example.com" }, new[] { 80, 443 }, logger);
        Helpers.ShowPropertiesTable("Port Availability", analysis.ServerResults);
    }
}
