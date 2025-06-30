using Spectre.Console.Cli;
using System.Diagnostics.CodeAnalysis;

namespace DomainDetective.CLI;

internal sealed class AnalyzeArcSettings : CommandSettings {
    [CommandOption("--file")]
    public FileInfo? File { get; set; }

    [CommandOption("--header")]
    public string? Header { get; set; }

    [CommandOption("--json")]
    public bool Json { get; set; }
}

internal sealed class AnalyzeArcCommand : Command<AnalyzeArcSettings> {
    [RequiresDynamicCode("Calls DomainDetective.CLI.CommandUtilities.AnalyzeARC(FileInfo, String, Boolean)")]
    [RequiresUnreferencedCode("Calls DomainDetective.CLI.CommandUtilities.AnalyzeARC(FileInfo, String, Boolean)")]
    public override int Execute(CommandContext context, AnalyzeArcSettings settings) {
        CommandUtilities.AnalyzeARC(settings.File, settings.Header, settings.Json);
        return 0;
    }
}
