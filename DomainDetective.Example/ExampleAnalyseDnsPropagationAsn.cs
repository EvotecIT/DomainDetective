using DnsClientX;
using System;
using DomainDetective;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective.Example {
    internal class ExampleAnalyseDnsPropagationAsnClass {
        public static async Task Run() {
            var analysis = new DnsPropagationAnalysis();
            analysis.LoadBuiltinServers();
            var asn = analysis.GetAsns().First().Asn;
            var servers = analysis.FilterServers(asn: asn, take: 2);
            var results = await analysis.QueryAsync("example.com", DnsRecordType.A, servers);
            foreach (var r in results) {
                Console.WriteLine($"{r.Server.IPAddress} {r.Success}");
            }
        }
    }
}
