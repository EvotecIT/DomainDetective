using Spectre.Console.Cli;
using System.Diagnostics.CodeAnalysis;

namespace DomainDetective.CLI;

internal sealed class AnalyzeMessageHeaderSettings : CommandSettings {
    [CommandOption("--file")]
    public FileInfo? File { get; set; }

    [CommandOption("--header")]
    public string? Header { get; set; }

    [CommandOption("--json")]
    public bool Json { get; set; }
}

internal sealed class AnalyzeMessageHeaderCommand : Command<AnalyzeMessageHeaderSettings> {
    [RequiresDynamicCode("Calls DomainDetective.CLI.CommandUtilities.AnalyzeMessageHeader(FileInfo, String, Boolean)")]
    [RequiresUnreferencedCode("Calls DomainDetective.CLI.CommandUtilities.AnalyzeMessageHeader(FileInfo, String, Boolean)")]
    public override int Execute(CommandContext context, AnalyzeMessageHeaderSettings settings) {
        CommandUtilities.AnalyzeMessageHeader(settings.File, settings.Header, settings.Json);
        return 0;
    }
}
