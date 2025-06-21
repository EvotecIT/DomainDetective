using DomainDetective;
using System;
using System.Threading.Tasks;

namespace DomainDetective.CLI {
    public static class Program {
        public static async Task<int> Main(string[] args) {
            if (args.Length < 2) {
                ShowUsage();
                return 1;
            }

            var command = args[0].ToLowerInvariant();
            var target = args[1];

            switch (command) {
                case "ns":
                    var checker = new DomainHealthCheck();
                    await checker.Verify(target, new[] { HealthCheckType.NS });

                    Console.WriteLine($"Results for {target}:");
                    Console.WriteLine($"Records: {string.Join(", ", checker.NSAnalysis.NsRecords)}");
                    Console.WriteLine($"HasDuplicates: {checker.NSAnalysis.HasDuplicates}");
                    Console.WriteLine($"AtLeastTwoRecords: {checker.NSAnalysis.AtLeastTwoRecords}");
                    Console.WriteLine($"AllHaveAOrAaaa: {checker.NSAnalysis.AllHaveAOrAaaa}");
                    Console.WriteLine($"PointsToCname: {checker.NSAnalysis.PointsToCname}");
                    return 0;
                default:
                    Console.WriteLine($"Unknown command: {command}");
                    ShowUsage();
                    return 1;
            }
        }

        private static void ShowUsage() {
            Console.WriteLine("DomainDetective CLI");
            Console.WriteLine("Usage:");
            Console.WriteLine("  ns <domain>     - analyze NS records");
        }
    }
}

