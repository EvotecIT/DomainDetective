using Spectre.Console.Cli;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.CLI;

/// <summary>
/// Settings for <see cref="TestRpkiCommand"/>.
/// </summary>
internal sealed class TestRpkiSettings : CommandSettings {
    /// <summary>Domain to query.</summary>
    [CommandArgument(0, "<domain>")]
    public string Domain { get; set; } = string.Empty;
}

/// <summary>
/// Validates RPKI origins for domain IPs.
/// </summary>
internal sealed class TestRpkiCommand : AsyncCommand<TestRpkiSettings> {
    /// <inheritdoc/>
    public override async Task<int> ExecuteAsync(CommandContext context, TestRpkiSettings settings) {
        var hc = new DomainHealthCheck();
        await hc.VerifyRPKI(settings.Domain, Program.CancellationToken);
        CliHelpers.ShowPropertiesTable($"RPKI for {settings.Domain}", hc.RpkiAnalysis.Results, false);
        return 0;
    }
}
