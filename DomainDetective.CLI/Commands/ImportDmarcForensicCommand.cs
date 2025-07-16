using Spectre.Console.Cli;
using System.Diagnostics.CodeAnalysis;

namespace DomainDetective.CLI;

/// <summary>Settings for <see cref="ImportDmarcForensicCommand"/>.</summary>
internal sealed class ImportDmarcForensicSettings : CommandSettings {
    /// <summary>Path to zipped forensic report.</summary>
    [CommandArgument(0, "<file>")]
    public string File { get; set; } = string.Empty;

    /// <summary>Output JSON results.</summary>
    [CommandOption("--json")]
    public bool Json { get; set; }
}

/// <summary>Imports DMARC forensic reports from a zip archive.</summary>
internal sealed class ImportDmarcForensicCommand : Command<ImportDmarcForensicSettings> {
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<T>(T, JsonSerializerOptions)")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<T>(T, JsonSerializerOptions)")]
    /// <inheritdoc/>
    public override int Execute(CommandContext context, ImportDmarcForensicSettings settings) {
        CommandUtilities.ImportDmarcForensic(settings.File, settings.Json);
        return 0;
    }
}
