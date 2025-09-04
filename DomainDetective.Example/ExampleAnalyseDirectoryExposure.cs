using System;
using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>Demonstrates directory exposure analysis.</summary>
    public static async Task ExampleAnalyseDirectoryExposure()
    {
        var healthCheck = new DomainHealthCheck { Verbose = false };
        await healthCheck.Verify("example.com", new[] { HealthCheckType.DIRECTORYEXPOSURE });
        Helpers.ShowPropertiesTable("Directory exposure for example.com", healthCheck.DirectoryExposureAnalysis);
        if (healthCheck.DirectoryExposureAnalysis.ExposedPaths.Count > 0)
        {
            Console.WriteLine("Exposed paths:");
            foreach (var path in healthCheck.DirectoryExposureAnalysis.ExposedPaths)
            {
                Console.WriteLine(path);
            }
        }
    }
}
