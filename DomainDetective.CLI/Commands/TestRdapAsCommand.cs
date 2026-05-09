namespace DomainDetective.CLI;

using DomainDetective;
using Spectre.Console.Cli;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Settings for <see cref="TestRdapAsCommand"/>.
/// </summary>
internal sealed class TestRdapAsSettings : CommandSettings {
    /// <summary>Autonomous system number.</summary>
    [CommandArgument(0, "<asn>")]
    public string Asn { get; set; } = string.Empty;
}

/// <summary>
/// Queries RDAP information for an autonomous system.
/// </summary>
internal sealed class TestRdapAsCommand : AsyncCommand<TestRdapAsSettings> {
    /// <inheritdoc/>
    protected override async Task<int> ExecuteAsync(CommandContext context, TestRdapAsSettings settings, CancellationToken cancellationToken) {
        var client = new RdapClient();
        var result = await client.QueryAutnumAsync(settings.Asn, Program.CancellationToken);
        if (result != null) {
            CliHelpers.ShowPropertiesTable($"RDAP AS {settings.Asn}", result, false);
        }
        return 0;
    }
}
