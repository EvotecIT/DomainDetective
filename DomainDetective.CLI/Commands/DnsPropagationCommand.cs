using DnsClientX;
using DomainDetective;
using Spectre.Console;
using Spectre.Console.Cli;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Threading;
using DomainDetective.Helpers;

namespace DomainDetective.CLI;

/// <summary>
/// Settings for <see cref="DnsPropagationCommand"/>.
/// </summary>
internal sealed class DnsPropagationSettings : CommandSettings {
    /// <summary>Domain to query.</summary>
    [CommandOption("--domain <DOMAIN>")]
    public string Domain { get; set; } = string.Empty;

    /// <summary>Record type to check.</summary>
    [CommandOption("--record-type <TYPE>")]
    public DnsRecordType RecordType { get; set; }

    /// <summary>Optional file containing DNS server definitions.</summary>
    [CommandOption("--servers-file <PATH>")]
    public FileInfo? ServersFile { get; set; }

    /// <summary>Output JSON results.</summary>
    [CommandOption("--json")]
    public bool Json { get; set; }

    /// <summary>Compare results across servers.</summary>
    [CommandOption("--compare-results")]
    public bool Compare { get; set; }

    /// <summary>Directory for storing snapshots.</summary>
    [CommandOption("--snapshot-path <PATH>")]
    public DirectoryInfo? SnapshotPath { get; set; }

    /// <summary>Show differences to previous snapshot.</summary>
    [CommandOption("--diff")]
    public bool Diff { get; set; }

    /// <summary>Maximum number of concurrent queries.</summary>
    [CommandOption("--max-parallelism <N>")]
    public int MaxParallelism { get; set; }

    /// <summary>Disable progress display.</summary>
    [CommandOption("--no-progress")]
    public bool NoProgress { get; set; }

    /// <summary>Include geolocation information.</summary>
    [CommandOption("--geo")]
    public bool Geo { get; set; }

    /// <summary>Verify that server IPs are announced by expected ASNs.</summary>
    [CommandOption("--validate-asn")]
    public bool ValidateAsn { get; set; }
}

/// <summary>
/// Checks DNS propagation across multiple public servers.
/// </summary>
internal sealed class DnsPropagationCommand : AsyncCommand<DnsPropagationSettings> {
    /// <inheritdoc/>
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresAssemblyFiles("Calls System.Reflection.Assembly.Location")]
    protected override async Task<int> ExecuteAsync(CommandContext context, DnsPropagationSettings settings, CancellationToken cancellationToken) {
        var analysis = new DnsPropagationAnalysis { SnapshotDirectory = settings.SnapshotPath?.FullName };
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
        if (settings.ValidateAsn) {
            await analysis.ValidateServerAsnsAsync(new InternalLogger());
        }

        var domain = CliHelpers.ToAscii(settings.Domain);

        List<DnsPropagationResult> results = new();
        if (settings.NoProgress) {
            results = await analysis.QueryAsync(domain, settings.RecordType, servers, cancellationToken, null, settings.MaxParallelism, settings.Geo);
        } else {
            await AnsiConsole.Progress().StartAsync(async ctx => {
                var task = ctx.AddTask($"Query {domain}", maxValue: 100);
                var progress = new Progress<double>(p => task.Value = p);
                results = await analysis.QueryAsync(domain, settings.RecordType, servers, cancellationToken, progress, settings.MaxParallelism, settings.Geo);
            });
        }
        IEnumerable<string>? changes = null;
        if (settings.Diff && settings.SnapshotPath != null) {
            changes = analysis.GetSnapshotChanges(domain, settings.RecordType, results);
        }

        if (settings.SnapshotPath != null) {
            analysis.SaveSnapshot(domain, settings.RecordType, results);
        }

        if (settings.Compare) {
            var details = DnsPropagationAnalysis.GetComparisonDetails(results);
            if (settings.Json) {
                Console.WriteLine(JsonSerializer.Serialize(details, JsonOptions.Default));
            } else {
                foreach (var d in details) {
                    var country = d.Country?.ToName() ?? string.Empty;
                    var location = d.Location?.ToName() ?? string.Empty;
                    Console.WriteLine($"{d.Records}: {d.IPAddress} ({country}/{location})");
                }
            }
        } else {
            if (settings.Json) {
                Console.WriteLine(JsonSerializer.Serialize(results, JsonOptions.Default));
            } else {
                foreach (var r in results) {
                    var records = r.Records.Select(rec => {
                        if (settings.Geo && r.Geo != null && r.Geo.TryGetValue(rec, out var info)) {
                            return $"{rec} ({info.Country}/{info.Region})";
                        }
                        return rec;
                    });
                    Console.WriteLine($"{r.Server.IPAddress} {r.Success} {string.Join(',', records)}");
                }
            }
        }
        if (changes != null && changes.Any()) {
            AnsiConsole.MarkupLine("[yellow]Changes since last snapshot:[/]");
            foreach (var line in changes) {
                Console.WriteLine(line);
            }
        }
        return 0;
    }
}
