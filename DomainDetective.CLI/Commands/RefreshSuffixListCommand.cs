using Spectre.Console.Cli;
using System.IO;
using System.Threading.Tasks;

namespace DomainDetective.CLI;

internal sealed class RefreshSuffixListSettings : CommandSettings {
    [CommandOption("--force")]
    public bool Force { get; set; }

    [CommandOption("--cache-dir")]
    public DirectoryInfo? CacheDirectory { get; set; }
}

internal sealed class RefreshSuffixListCommand : AsyncCommand<RefreshSuffixListSettings> {
    public override async Task<int> ExecuteAsync(CommandContext context, RefreshSuffixListSettings settings) {
        var hc = new DomainHealthCheck();
        if (settings.CacheDirectory != null) {
            hc.CacheDirectory = settings.CacheDirectory.FullName;
        }
        await hc.RefreshPublicSuffixListAsync(force: settings.Force);
        return 0;
    }
}
