using Spectre.Console.Cli;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.CLI;

/// <summary>
/// Settings for <see cref="TestRdapCommand"/>.
/// </summary>
internal sealed class TestRdapSettings : CommandSettings {
    /// <summary>Domain to query.</summary>
    [CommandArgument(0, "<domain>")]
    public string Domain { get; set; } = string.Empty;
}

/// <summary>
/// Queries RDAP registration information.
/// </summary>
internal sealed class TestRdapCommand : AsyncCommand<TestRdapSettings> {
    /// <inheritdoc/>
    protected override async Task<int> ExecuteAsync(CommandContext context, TestRdapSettings settings, CancellationToken cancellationToken) {
        var client = new RdapClient();
        var result = await client.QueryDomainAsync(settings.Domain, cancellationToken);
        if (result != null) {
            CliHelpers.ShowPropertiesTable($"RDAP for {settings.Domain}", result, false);
        }
        return 0;
    }
}
