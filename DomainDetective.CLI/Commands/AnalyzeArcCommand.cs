using Spectre.Console.Cli;
using System.Diagnostics.CodeAnalysis;

namespace DomainDetective.CLI;

/// <summary>
/// Settings for <see cref="AnalyzeArcCommand"/>.
/// </summary>
internal sealed class AnalyzeArcSettings : CommandSettings {
    /// <summary>Optional file containing the message header.</summary>
    [CommandOption("--file")]
    public FileInfo? File { get; set; }

    /// <summary>Message header text.</summary>
    [CommandOption("--header")]
    public string? Header { get; set; }

    /// <summary>Output JSON results.</summary>
    [CommandOption("--json")]
    public bool Json { get; set; }
}

/// <summary>
/// Analyzes ARC headers within an email message.
/// </summary>
internal sealed class AnalyzeArcCommand : Command<AnalyzeArcSettings> {
    [RequiresDynamicCode("Calls DomainDetective.CLI.CommandUtilities.AnalyzeARC(FileInfo, String, Boolean)")]
    [RequiresUnreferencedCode("Calls DomainDetective.CLI.CommandUtilities.AnalyzeARC(FileInfo, String, Boolean)")]
    /// <inheritdoc/>
    public override int Execute(CommandContext context, AnalyzeArcSettings settings) {
        CommandUtilities.AnalyzeARC(settings.File, settings.Header, settings.Json);
        return 0;
    }
}
