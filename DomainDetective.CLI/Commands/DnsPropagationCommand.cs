using DnsClientX;
using Spectre.Console.Cli;
using System.Text.Json;
using System.Threading;

namespace DomainDetective.CLI;

internal sealed class DnsPropagationSettings : CommandSettings {
    [CommandOption("--domain")]
    public string Domain { get; set; } = string.Empty;

    [CommandOption("--record-type")]
    public DnsRecordType RecordType { get; set; }

    [CommandOption("--servers-file")]
    public FileInfo ServersFile { get; set; } = new FileInfo("Data/DNS/PublicDNS.json");

    [CommandOption("--json")]
    public bool Json { get; set; }

    [CommandOption("--compare-results")]
    public bool Compare { get; set; }
}

internal sealed class DnsPropagationCommand : AsyncCommand<DnsPropagationSettings> {
    public override async Task<int> ExecuteAsync(CommandContext context, DnsPropagationSettings settings) {
        var analysis = new DnsPropagationAnalysis();
        analysis.LoadServers(settings.ServersFile.FullName, clearExisting: true);
        var servers = analysis.Servers;
        var domain = CliHelpers.ToAscii(settings.Domain);
        var results = await analysis.QueryAsync(domain, settings.RecordType, servers, Program.CancellationToken);
        if (settings.Compare) {
            var groups = DnsPropagationAnalysis.CompareResults(results);
            if (settings.Json) {
                Console.WriteLine(JsonSerializer.Serialize(groups, DomainHealthCheck.JsonOptions));
            } else {
                foreach (var kvp in groups) {
                    Console.WriteLine($"{kvp.Key}: {string.Join(',', kvp.Value.Select(s => s.IPAddress.ToString()))}");
                }
            }
        } else {
            if (settings.Json) {
                Console.WriteLine(JsonSerializer.Serialize(results, DomainHealthCheck.JsonOptions));
            } else {
                foreach (var r in results) {
                    Console.WriteLine($"{r.Server.IPAddress} {r.Success} {string.Join(',', r.Records)}");
                }
            }
        }
        return 0;
    }
}
