namespace DomainDetective.CLI;

using DomainDetective;
using Spectre.Console.Cli;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Settings for <see cref="TestRdapNameserverCommand"/>.
/// </summary>
internal sealed class TestRdapNameserverSettings : CommandSettings {
    /// <summary>Nameserver host name.</summary>
    [CommandArgument(0, "<host>")]
    public string Host { get; set; } = string.Empty;
}

/// <summary>
/// Queries RDAP information for a nameserver.
/// </summary>
internal sealed class TestRdapNameserverCommand : AsyncCommand<TestRdapNameserverSettings> {
    /// <inheritdoc/>
    protected override async Task<int> ExecuteAsync(CommandContext context, TestRdapNameserverSettings settings, CancellationToken cancellationToken) {
        var client = new RdapClient();
        var result = await client.QueryNameserverAsync(settings.Host, cancellationToken);
        if (result != null) {
            CliHelpers.ShowPropertiesTable($"RDAP nameserver {settings.Host}", result, false);
        }
        return 0;
    }
}
