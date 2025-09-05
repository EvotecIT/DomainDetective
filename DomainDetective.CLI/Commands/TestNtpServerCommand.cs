using Spectre.Console.Cli;
using DomainDetective;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.CLI;

/// <summary>
/// Settings for <see cref="TestNtpServerCommand"/>.
/// </summary>
internal sealed class TestNtpServerSettings : CommandSettings {
    /// <summary>Custom NTP server to query.</summary>
    [CommandArgument(0, "server")]
    public string? Server { get; set; }

    /// <summary>Built-in server selection.</summary>
    [CommandOption("--builtin")]
    public NtpServer? Builtin { get; set; }

    /// <summary>NTP port number.</summary>
    [CommandOption("--port")]
    public int Port { get; set; } = 123;
}

/// <summary>
/// Queries an NTP server for clock offset.
/// </summary>
internal sealed class TestNtpServerCommand : AsyncCommand<TestNtpServerSettings> {
    /// <inheritdoc/>
    public override async Task<int> ExecuteAsync(CommandContext context, TestNtpServerSettings settings) {
        var hc = new DomainHealthCheck();
        string host = !string.IsNullOrWhiteSpace(settings.Server)
            ? settings.Server!
            : (settings.Builtin ?? NtpServer.Pool).ToHost();
        await hc.TestNtpServer(host, settings.Port, Program.CancellationToken);
        CliHelpers.ShowPropertiesTable($"NTP {host}", hc.NtpAnalysis.ServerResults, false);
        return 0;
    }
}
