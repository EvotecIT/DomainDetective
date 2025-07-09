using DnsClientX;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective.Example {
    internal class ExampleAnalyseDnsPropagationGeoClass {
        public static async Task Run() {
            var analysis = new DnsPropagationAnalysis();
            analysis.LoadBuiltinServers();
            var servers = analysis.FilterServers(take: 3);
            var results = await analysis.QueryAsync("example.com", DnsRecordType.A, servers, includeGeo: true);
            foreach (var result in results) {
                var records = result.Records.Select(r => result.Geo != null && result.Geo.TryGetValue(r, out var info)
                    ? $"{r} ({info.Country}/{info.City})" : r);
                Console.WriteLine($"{result.Server.IPAddress} - {string.Join(',', records)}");
            }
        }
    }
}
