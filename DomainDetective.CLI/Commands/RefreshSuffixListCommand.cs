using Spectre.Console.Cli;
using System.IO;
using System.Threading.Tasks;

namespace DomainDetective.CLI;

/// <summary>
/// Settings for <see cref="RefreshSuffixListCommand"/>.
/// </summary>
internal sealed class RefreshSuffixListSettings : CommandSettings {
    /// <summary>Force refresh even if cache is valid.</summary>
    [CommandOption("--force")]
    public bool Force { get; set; }

    /// <summary>Optional cache directory.</summary>
    [CommandOption("--cache-dir")]
    public DirectoryInfo? CacheDirectory { get; set; }
}

/// <summary>
/// Downloads the latest public suffix list.
/// </summary>
internal sealed class RefreshSuffixListCommand : AsyncCommand<RefreshSuffixListSettings> {
    /// <inheritdoc/>
    public override async Task<int> ExecuteAsync(CommandContext context, RefreshSuffixListSettings settings) {
        var hc = new DomainHealthCheck();
        if (settings.CacheDirectory != null) {
            hc.CacheDirectory = settings.CacheDirectory.FullName;
        }
        await hc.RefreshPublicSuffixListAsync(force: settings.Force);
        return 0;
    }
}
