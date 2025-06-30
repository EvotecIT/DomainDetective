using DnsClientX;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective.Example {
    internal class ExampleAnalyseDnsPropagationClass {
        public static async Task Run() {
            var analysis = new DnsPropagationAnalysis();
            analysis.LoadServers(Path.Combine("Data", "DNS", "PublicDNS.json"));
            var servers = analysis.FilterServers(country: "United States", take: 3);
            var results = await analysis.QueryAsync("example.com", DnsRecordType.A, servers);
            foreach (var result in results) {
                Console.WriteLine($"{result.Server.IPAddress} - Success:{result.Success} Records:{string.Join(',', result.Records)} Time:{result.Duration.TotalMilliseconds}ms");
            }

            var comparison = DnsPropagationAnalysis.CompareResults(results);
            foreach (var kvp in comparison) {
                Console.WriteLine($"Record set: {kvp.Key} seen by {kvp.Value.Count} servers");
            }
        }
    }
}