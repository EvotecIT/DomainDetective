using DnsClientX;
using DomainDetective;
using Spectre.Console;
using Spectre.Console.Cli;
using System.Reflection;
using System.Text.Json;
using System.Threading;
using System.IO;

namespace DomainDetective.CLI;

/// <summary>
/// Settings for <see cref="DnsPropagationCommand"/>.
/// </summary>
internal sealed class DnsPropagationSettings : CommandSettings {
    /// <summary>Domain to query.</summary>
    [CommandOption("--domain")]
    public string Domain { get; set; } = string.Empty;

    /// <summary>Record type to check.</summary>
    [CommandOption("--record-type")]
    public DnsRecordType RecordType { get; set; }

    /// <summary>Optional file containing DNS server definitions.</summary>
    [CommandOption("--servers-file")]
    public FileInfo? ServersFile { get; set; }

    /// <summary>Output JSON results.</summary>
    [CommandOption("--json")]
    public bool Json { get; set; }

    /// <summary>Compare results across servers.</summary>
    [CommandOption("--compare-results")]
    public bool Compare { get; set; }

    /// <summary>Maximum number of concurrent queries.</summary>
    [CommandOption("--max-parallelism")]
    public int MaxParallelism { get; set; }

    /// <summary>Disable progress display.</summary>
    [CommandOption("--no-progress")]
    public bool NoProgress { get; set; }

    /// <summary>Include geolocation information.</summary>
    [CommandOption("--geo")]
    public bool Geo { get; set; }
}

/// <summary>
/// Checks DNS propagation across multiple public servers.
/// </summary>
internal sealed class DnsPropagationCommand : AsyncCommand<DnsPropagationSettings> {
    /// <inheritdoc/>
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

        List<DnsPropagationResult> results = new();
        if (settings.NoProgress) {
            results = await analysis.QueryAsync(domain, settings.RecordType, servers, Program.CancellationToken, null, settings.MaxParallelism, settings.Geo);
        } else {
            await AnsiConsole.Progress().StartAsync(async ctx => {
                var task = ctx.AddTask($"Query {domain}", maxValue: 100);
                var progress = new Progress<double>(p => task.Value = p);
                results = await analysis.QueryAsync(domain, settings.RecordType, servers, Program.CancellationToken, progress, settings.MaxParallelism, settings.Geo);
            });
        }
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
                    var records = r.Records.Select(rec => {
                        if (settings.Geo && r.Geo != null && r.Geo.TryGetValue(rec, out var info)) {
                            return $"{rec} ({info.Country}/{info.City})";
                        }
                        return rec;
                    });
                    Console.WriteLine($"{r.Server.IPAddress} {r.Success} {string.Join(',', records)}");
                }
            }
        }
        return 0;
    }
}
