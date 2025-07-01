using Spectre.Console.Cli;
using System.Diagnostics.CodeAnalysis;

namespace DomainDetective.CLI;

internal sealed class AnalyzeDnsTunnelingSettings : CommandSettings {
    [CommandOption("--domain")]
    public string Domain { get; set; } = string.Empty;

    [CommandOption("--file")]
    public FileInfo File { get; set; } = null!;

    [CommandOption("--json")]
    public bool Json { get; set; }
}

internal sealed class AnalyzeDnsTunnelingCommand : Command<AnalyzeDnsTunnelingSettings> {
    [RequiresUnreferencedCode("Calls DomainDetective.CLI.CommandUtilities.AnalyzeDnsTunneling(String, String, Boolean)")]
    public override int Execute(CommandContext context, AnalyzeDnsTunnelingSettings settings) {
        var domain = CliHelpers.ToAscii(settings.Domain);
        CommandUtilities.AnalyzeDnsTunneling(domain, settings.File.FullName, settings.Json);
        return 0;
    }
}
