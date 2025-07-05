using DnsClientX;
using Spectre.Console.Cli;
using System.Reflection;
using System.Text.Json;
using System.Threading;
using System.IO;

namespace DomainDetective.CLI;

internal sealed class DnsPropagationSettings : CommandSettings {
    [CommandOption("--domain")]
    public string Domain { get; set; } = string.Empty;

    [CommandOption("--record-type")]
    public DnsRecordType RecordType { get; set; }

    [CommandOption("--servers-file")]
    public FileInfo? ServersFile { get; set; }

    [CommandOption("--json")]
    public bool Json { get; set; }

    [CommandOption("--compare-results")]
    public bool Compare { get; set; }
}

internal sealed class DnsPropagationCommand : AsyncCommand<DnsPropagationSettings> {
    public override async Task<int> ExecuteAsync(CommandContext context, DnsPropagationSettings settings) {
        var analysis = new DnsPropagationAnalysis();
        if (settings.ServersFile != null) {
            var inputPath = settings.ServersFile.ToString();
            var filePath = Path.IsPathRooted(inputPath)
                ? settings.ServersFile.FullName
                : Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? string.Empty, inputPath);
            analysis.LoadServers(filePath, clearExisting: true);
        } else {
            analysis.LoadBuiltinServers();
        }
        var servers = analysis.Servers;
        var domain = CliHelpers.ToAscii(settings.Domain);
        var results = await analysis.QueryAsync(domain, settings.RecordType, servers, Program.CancellationToken);
        if (settings.Compare) {
            var details = DnsPropagationAnalysis.GetComparisonDetails(results);
            if (settings.Json) {
                Console.WriteLine(JsonSerializer.Serialize(details, DomainHealthCheck.JsonOptions));
            } else {
                foreach (var d in details) {
                    Console.WriteLine($"{d.Records}: {d.IPAddress} ({d.Country}/{d.Location})");
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
