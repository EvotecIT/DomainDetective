using DomainDetective.CLI;
using DomainDetective.Helpers;
using DomainDetective.TimeSeries.Registration;
using Spectre.Console;
using Spectre.Console.Cli;
using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Threading.Tasks;

namespace DomainDetective.CLI.Commands;

/// <summary>
/// Settings for <see cref="ImportRegistrationSnapshotCommand"/>.
/// </summary>
internal sealed class ImportRegistrationSnapshotSettings : CommandSettings {
    /// <summary>Domain to query.</summary>
    [Description("Domain to query.")]
    [CommandArgument(0, "<domain>")]
    public string Domain { get; set; } = string.Empty;

    /// <summary>Root directory for snapshot storage.</summary>
    [Description("Root directory for snapshot storage.")]
    [CommandOption("--store|--store-path <PATH>")]
    public string StorePath { get; set; } = string.Empty;

    /// <summary>Skip RDAP query (use WHOIS only).</summary>
    [Description("Skip RDAP query (use WHOIS only).")]
    [CommandOption("--skip-rdap")]
    public bool SkipRdap { get; set; }

    /// <summary>Skip WHOIS query (use RDAP only).</summary>
    [Description("Skip WHOIS query (use RDAP only).")]
    [CommandOption("--skip-whois")]
    public bool SkipWhois { get; set; }

    /// <summary>WHOIS timeout in seconds (default 30).</summary>
    [Description("WHOIS timeout in seconds (default 30).")]
    [CommandOption("--whois-timeout-seconds <SECONDS>")]
    [DefaultValue(30)]
    public int WhoisTimeoutSeconds { get; set; } = 30;

    /// <summary>Output JSON instead of a console summary.</summary>
    [Description("Output JSON instead of a console summary.")]
    [CommandOption("--json")]
    public bool Json { get; set; }
}

/// <summary>
/// Captures a unified WHOIS/RDAP registration snapshot and stores it in a time-series store.
/// </summary>
internal sealed class ImportRegistrationSnapshotCommand : AsyncCommand<ImportRegistrationSnapshotSettings> {
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    protected override async Task<int> ExecuteAsync(CommandContext context, ImportRegistrationSnapshotSettings settings, CancellationToken cancellationToken) {
        if (settings == null) {
            throw new ArgumentNullException(nameof(settings));
        }

        var domain = CliHelpers.ToAscii(settings.Domain);
        if (string.IsNullOrWhiteSpace(domain)) {
            AnsiConsole.MarkupLine("[red]<domain> is required.[/]");
            return 1;
        }
        if (string.IsNullOrWhiteSpace(settings.StorePath)) {
            AnsiConsole.MarkupLine("[red]--store-path is required.[/]");
            return 1;
        }
        if (settings.WhoisTimeoutSeconds < 1 || settings.WhoisTimeoutSeconds > 600) {
            AnsiConsole.MarkupLine("[red]--whois-timeout-seconds must be between 1 and 600.[/]");
            return 1;
        }

        var logger = new InternalLogger(false);
        var healthCheck = new DomainHealthCheck(internalLogger: logger);
        healthCheck.WhoisAnalysis.Timeout = TimeSpan.FromSeconds(settings.WhoisTimeoutSeconds);

        RdapAnalysis? rdap = null;
        WhoisAnalysis? whois = null;

        if (!settings.SkipRdap) {
            try {
                await healthCheck.QueryRDAP(domain, Program.CancellationToken);
                rdap = healthCheck.RdapAnalysis;
            }
            catch (Exception ex) {
                AnsiConsole.MarkupLine($"[yellow]RDAP query failed:[/] {Markup.Escape(ex.Message)}");
            }
        }

        if (!settings.SkipWhois) {
            try {
                await healthCheck.CheckWHOIS(domain, Program.CancellationToken);
                whois = healthCheck.WhoisAnalysis;
            }
            catch (Exception ex) {
                AnsiConsole.MarkupLine($"[yellow]WHOIS query failed:[/] {Markup.Escape(ex.Message)}");
            }
        }

        var snapshot = RegistrationSnapshotBuilder.Build(domain, rdap, whois);
        var store = new RegistrationTimeSeriesStore(settings.StorePath);
        var path = store.SaveSnapshot(snapshot);

        if (settings.Json) {
            var json = JsonSerializer.Serialize(snapshot, JsonOptions.Default);
            Console.WriteLine(json);
            return 0;
        }

        AnsiConsole.MarkupLine($"[green]Saved[/] registration snapshot for [blue]{Markup.Escape(domain)}[/] to:");
        AnsiConsole.MarkupLine($"[blue]{Markup.Escape(path)}[/]");
        return 0;
    }
}
