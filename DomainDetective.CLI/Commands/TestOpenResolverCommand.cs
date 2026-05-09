using Spectre.Console.Cli;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.CLI;

/// <summary>
/// Settings for <see cref="TestOpenResolverCommand"/>.
/// </summary>
internal sealed class TestOpenResolverSettings : CommandSettings {
    /// <summary>DNS server to test.</summary>
    [CommandArgument(0, "<server>")]
    public string Server { get; set; } = string.Empty;

    /// <summary>DNS port number.</summary>
    [CommandOption("--port <PORT>")]
    public int Port { get; set; } = 53;
}

/// <summary>
/// Tests if a DNS server allows recursive queries.
/// </summary>
internal sealed class TestOpenResolverCommand : AsyncCommand<TestOpenResolverSettings> {
    /// <inheritdoc/>
    protected override async Task<int> ExecuteAsync(CommandContext context, TestOpenResolverSettings settings, CancellationToken cancellationToken) {
        var hc = new DomainHealthCheck();
        await hc.CheckOpenResolverHost(settings.Server, settings.Port, Program.CancellationToken);
        CliHelpers.ShowPropertiesTable($"OPENRESOLVER for {settings.Server}", hc.OpenResolverAnalysis.ServerResults, false);
        return 0;
    }
}
