using DnsClientX;
using System;
using System.Linq;

using System.Threading.Tasks;

namespace DomainDetective.Example {
    internal class ExampleAnalyseDnsPropagationRegionsClass {
        public static async Task Run() {
            var analysis = new DnsPropagationAnalysis();
            analysis.LoadBuiltinServers();

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

            var details = DnsPropagationAnalysis.GetComparisonDetails(results);
            Console.WriteLine("\nSummary by record set:");
            foreach (var d in details) {
                Console.WriteLine($"{d.Records}: {d.IPAddress} ({d.Country}/{d.Location})");
            }
        }
    }
}