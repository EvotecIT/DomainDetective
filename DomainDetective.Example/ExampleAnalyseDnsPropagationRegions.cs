using DnsClientX;
using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace DomainDetective.Example {
    internal class ExampleAnalyseDnsPropagationRegionsClass {
        public static async Task Run() {
            var analysis = new DnsPropagationAnalysis();
            var baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? string.Empty;
            var file = Path.Combine(baseDir, "Data", "DNS", "PublicDNS.json");
            analysis.LoadServers(file);

            var servers = analysis.FilterServers(take: 8);
            var results = await analysis.QueryAsync("example.com", DnsRecordType.A, servers);

            var grouped = results.GroupBy(r => r.Server.Country);
            foreach (var group in grouped) {
                Console.WriteLine($"--- {group.Key} ---");
                foreach (var result in group) {
                    var records = string.Join(',', result.Records);
                    Console.WriteLine($"{result.Server.IPAddress} - Success:{result.Success} Records:{records} Time:{result.Duration.TotalMilliseconds}ms");
                }
            }

            var comparison = DnsPropagationAnalysis.CompareResults(results);
            Console.WriteLine("\nSummary by record set:");
            foreach (var kvp in comparison) {
                var countries = string.Join(',', kvp.Value.Select(s => s.Country));
                Console.WriteLine($"Record set: {kvp.Key} seen by {kvp.Value.Count} servers ({countries})");
            }
        }
    }
}