using Spectre.Console;
using Spectre.Console.Cli;
using System.Text.Json;
using System.Threading;

namespace DomainDetective.CLI;

/// <summary>
/// Settings used by <see cref="WhoisCommand"/>.
/// </summary>
internal sealed class WhoisSettings : CommandSettings {
    /// <summary>Domain name to query.</summary>
    [CommandArgument(0, "<domain>")]
    public string Domain { get; set; } = string.Empty;

    /// <summary>Optional directory for snapshot storage.</summary>
    [CommandOption("--snapshot-path")]
    public DirectoryInfo? SnapshotPath { get; set; }

    /// <summary>Show differences to previous snapshot.</summary>
    [CommandOption("--diff")]
    public bool Diff { get; set; }
}

/// <summary>
/// Retrieves WHOIS information for a domain.
/// </summary>
internal sealed class WhoisCommand : AsyncCommand<WhoisSettings> {
    /// <inheritdoc/>
    public override async Task<int> ExecuteAsync(CommandContext context, WhoisSettings settings) {
        var analysis = new WhoisAnalysis { SnapshotDirectory = settings.SnapshotPath?.FullName };
        var domain = CliHelpers.ToAscii(settings.Domain);
        await analysis.QueryWhoisServer(domain, Program.CancellationToken);
        IEnumerable<string>? changes = null;
        if (settings.Diff && settings.SnapshotPath != null) {
            changes = analysis.GetWhoisChanges();
        }
        if (settings.SnapshotPath != null) {
            analysis.SaveSnapshot();
        }
        CliHelpers.ShowPropertiesTable($"WHOIS for {domain}", analysis, false);
        if (changes != null && changes.Any()) {
            AnsiConsole.MarkupLine("[yellow]Changes since last snapshot:[/]");
            foreach (var line in changes) {
                Console.WriteLine(line);
            }
        }
        return 0;
    }
}
