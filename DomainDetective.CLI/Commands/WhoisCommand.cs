using Spectre.Console;
using Spectre.Console.Cli;
using System.Text.Json;
using System.Threading;

namespace DomainDetective.CLI;

internal sealed class WhoisSettings : CommandSettings {
    [CommandArgument(0, "<domain>")]
    public string Domain { get; set; } = string.Empty;

    [CommandOption("--snapshot-path")]
    public DirectoryInfo? SnapshotPath { get; set; }

    [CommandOption("--diff")]
    public bool Diff { get; set; }
}

internal sealed class WhoisCommand : AsyncCommand<WhoisSettings> {
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
