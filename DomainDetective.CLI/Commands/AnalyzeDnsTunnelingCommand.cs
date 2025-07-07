using Spectre.Console.Cli;
using System.Diagnostics.CodeAnalysis;

namespace DomainDetective.CLI;

/// <summary>
/// Settings for <see cref="AnalyzeDnsTunnelingCommand"/>.
/// </summary>
internal sealed class AnalyzeDnsTunnelingSettings : CommandSettings {
    /// <summary>Domain to analyze.</summary>
    [CommandOption("--domain")]
    public string Domain { get; set; } = string.Empty;

    /// <summary>Log file containing DNS traffic.</summary>
    [CommandOption("--file")]
    public FileInfo File { get; set; } = null!;

    /// <summary>Output JSON results.</summary>
    [CommandOption("--json")]
    public bool Json { get; set; }
}

/// <summary>
/// Evaluates DNS tunneling logs for suspicious activity.
/// </summary>
internal sealed class AnalyzeDnsTunnelingCommand : Command<AnalyzeDnsTunnelingSettings> {
    [RequiresUnreferencedCode("Calls DomainDetective.CLI.CommandUtilities.AnalyzeDnsTunneling(String, String, Boolean)")]
    /// <inheritdoc/>
    public override int Execute(CommandContext context, AnalyzeDnsTunnelingSettings settings) {
        var domain = CliHelpers.ToAscii(settings.Domain);
        CommandUtilities.AnalyzeDnsTunneling(domain, settings.File.FullName, settings.Json);
        return 0;
    }
}
