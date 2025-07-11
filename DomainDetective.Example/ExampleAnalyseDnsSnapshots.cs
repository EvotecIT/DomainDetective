using System;
using System.IO;
using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task ExampleAnalyseDnsSnapshots() {
        var analysis = new DnsPropagationAnalysis { SnapshotDirectory = "snapshots" };
        analysis.LoadBuiltinServers();
        var servers = analysis.FilterServers(take: 2);
        var results = await analysis.QueryAsync("example.com", DnsClientX.DnsRecordType.A, servers, maxParallelism: 2);
        var diff = analysis.GetSnapshotChanges("example.com", DnsClientX.DnsRecordType.A, results);
        analysis.SaveSnapshot("example.com", DnsClientX.DnsRecordType.A, results);
        foreach (var line in diff) {
            Console.WriteLine(line);
        }
    }
}
