using Spectre.Console.Cli;
using System.Diagnostics.CodeAnalysis;

namespace DomainDetective.CLI;

/// <summary>
/// Settings for <see cref="AnalyzeMessageHeaderCommand"/>.
/// </summary>
internal sealed class AnalyzeMessageHeaderSettings : CommandSettings {
    /// <summary>File containing the message header.</summary>
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
/// Analyzes standard message headers for DMARC and authentication issues.
/// </summary>
internal sealed class AnalyzeMessageHeaderCommand : Command<AnalyzeMessageHeaderSettings> {
    [RequiresDynamicCode("Calls DomainDetective.CLI.CommandUtilities.AnalyzeMessageHeader(FileInfo, String, Boolean)")]
    [RequiresUnreferencedCode("Calls DomainDetective.CLI.CommandUtilities.AnalyzeMessageHeader(FileInfo, String, Boolean)")]
    /// <inheritdoc/>
    public override int Execute(CommandContext context, AnalyzeMessageHeaderSettings settings) {
        CommandUtilities.AnalyzeMessageHeader(settings.File, settings.Header, settings.Json);
        return 0;
    }
}
