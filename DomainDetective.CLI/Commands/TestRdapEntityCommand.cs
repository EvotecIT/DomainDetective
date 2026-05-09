namespace DomainDetective.CLI;

using DomainDetective;
using Spectre.Console.Cli;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Settings for <see cref="TestRdapEntityCommand"/>.
/// </summary>
internal sealed class TestRdapEntitySettings : CommandSettings {
    /// <summary>Entity handle.</summary>
    [CommandArgument(0, "<handle>")]
    public string Handle { get; set; } = string.Empty;
}

/// <summary>
/// Queries RDAP information for an entity.
/// </summary>
internal sealed class TestRdapEntityCommand : AsyncCommand<TestRdapEntitySettings> {
    /// <inheritdoc/>
    protected override async Task<int> ExecuteAsync(CommandContext context, TestRdapEntitySettings settings, CancellationToken cancellationToken) {
        var client = new RdapClient();
        var result = await client.QueryEntityAsync(settings.Handle, Program.CancellationToken);
        if (result != null) {
            CliHelpers.ShowPropertiesTable($"RDAP entity {settings.Handle}", result, false);
        }
        return 0;
    }
}
