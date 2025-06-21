using DomainDetective;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective.CLI {
    public class Program {
        public static Task<int> Main(string[] args) => Run(args);

        public static async Task<int> Run(string[] args) {
            if (args.Length != 2 || args[0].ToLowerInvariant() != "ns") {
                Console.WriteLine("Usage: DomainDetective.CLI ns <domain>");
                return 1;
            }

            var domain = args[1];
            var healthCheck = new DomainHealthCheck();
            await healthCheck.Verify(domain, new[] { HealthCheckType.NS });

            foreach (var record in healthCheck.NSAnalysis.NsRecords) {
                Console.WriteLine(record);
            }

            Console.WriteLine($"AtLeastTwoRecords: {healthCheck.NSAnalysis.AtLeastTwoRecords}");
            Console.WriteLine($"HasDuplicates: {healthCheck.NSAnalysis.HasDuplicates}");
            Console.WriteLine($"AllHaveAOrAaaa: {healthCheck.NSAnalysis.AllHaveAOrAaaa}");
            Console.WriteLine($"PointsToCname: {healthCheck.NSAnalysis.PointsToCname}");
            return 0;
        }
    }
}
