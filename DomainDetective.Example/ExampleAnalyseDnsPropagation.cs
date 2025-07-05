using DnsClientX;
using System;
using DomainDetective;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective.Example {
    internal class ExampleAnalyseDnsPropagationClass {
        public static async Task Run() {
            var analysis = new DnsPropagationAnalysis();
            analysis.LoadBuiltinServers();
            var servers = analysis.FilterServers(country: CountryId.UnitedStates, take: 3);
            var progress = new Progress<double>(p => Console.WriteLine($"Progress: {p:F0}%"));
            var results = await analysis.QueryAsync(
                "example.com",
                DnsRecordType.A,
                servers,
                cancellationToken: default,
                progress: progress);
            foreach (var result in results) {
                Console.WriteLine($"{result.Server.IPAddress} - Success:{result.Success} Records:{string.Join(',', result.Records)} Time:{result.Duration.TotalMilliseconds}ms");
            }

            var details = DnsPropagationAnalysis.GetComparisonDetails(results);
            foreach (var d in details) {
                Console.WriteLine($"{d.Records}: {d.IPAddress} ({d.Country}/{d.Location})");
            }
        }
    }
}