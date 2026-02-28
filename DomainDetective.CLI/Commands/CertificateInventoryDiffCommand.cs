using DomainDetective.Helpers;
using Spectre.Console;
using Spectre.Console.Cli;
using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace DomainDetective.CLI.Commands;

/// <summary>
/// Settings for <see cref="CertificateInventoryDiffCommand"/>.
/// </summary>
internal sealed class CertificateInventoryDiffSettings : CommandSettings {
    /// <summary>Certificate monitor cache directory (defaults to system temp path).</summary>
    [Description("Certificate monitor cache directory (defaults to system temp path).")]
    [CommandOption("--cache-dir <PATH>")]
    public string? CacheDirectory { get; set; }

    /// <summary>Only include snapshots captured since this UTC timestamp.</summary>
    [Description("Only include snapshots captured since this UTC timestamp.")]
    [CommandOption("--since-utc <UTC>")]
    public DateTime? SinceUtc { get; set; }

    /// <summary>Timestamp selector for the previous snapshot.</summary>
    [Description("Timestamp selector for the previous snapshot.")]
    [CommandOption("--previous-utc <UTC>")]
    public DateTime? PreviousUtc { get; set; }

    /// <summary>Timestamp selector for the current snapshot.</summary>
    [Description("Timestamp selector for the current snapshot.")]
    [CommandOption("--current-utc <UTC>")]
    public DateTime? CurrentUtc { get; set; }

    /// <summary>Include unchanged endpoints in output.</summary>
    [Description("Include unchanged endpoints in output.")]
    [CommandOption("--include-unchanged")]
    public bool IncludeUnchanged { get; set; }

    /// <summary>Maximum endpoint rows returned.</summary>
    [Description("Maximum endpoint rows returned.")]
    [CommandOption("--max-endpoints <N>")]
    [DefaultValue(500)]
    public int MaxEndpoints { get; set; } = 500;

    /// <summary>Output JSON instead of tables.</summary>
    [Description("Output JSON instead of tables.")]
    [CommandOption("--json")]
    public bool Json { get; set; }
}

/// <summary>
/// Compares two persisted certificate inventory snapshots and shows endpoint deltas.
/// </summary>
internal sealed class CertificateInventoryDiffCommand : AsyncCommand<CertificateInventoryDiffSettings> {
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    public override Task<int> ExecuteAsync(CommandContext context, CertificateInventoryDiffSettings settings) {
        if (settings == null) {
            throw new ArgumentNullException(nameof(settings));
        }

        if (settings.MaxEndpoints < 0) {
            AnsiConsole.MarkupLine("[red]--max-endpoints must be 0 or greater.[/]");
            return Task.FromResult(1);
        }

        var cacheDirectory = CertificateInventoryCommandHelpers.ResolveCacheDirectory(settings.CacheDirectory);
        var monitor = new CertificateMonitor {
            CacheDirectory = cacheDirectory,
            PersistInventorySnapshots = false
        };

        var diff = monitor.BuildInventoryDiff(
            sinceUtc: CertificateInventoryCommandHelpers.ToUtc(settings.SinceUtc),
            previousCapturedAtUtc: CertificateInventoryCommandHelpers.ToUtc(settings.PreviousUtc),
            currentCapturedAtUtc: CertificateInventoryCommandHelpers.ToUtc(settings.CurrentUtc),
            includeUnchanged: settings.IncludeUnchanged,
            maxEndpoints: settings.MaxEndpoints);

        if (settings.Json) {
            Console.WriteLine(JsonSerializer.Serialize(diff, JsonOptions.Default));
            return Task.FromResult(0);
        }

        if (!diff.CurrentCapturedAtUtc.HasValue && !diff.PreviousCapturedAtUtc.HasValue) {
            AnsiConsole.MarkupLine($"[yellow]No inventory snapshots found in:[/] {cacheDirectory}");
            return Task.FromResult(0);
        }

        var summary = new Table().Border(TableBorder.Rounded);
        summary.AddColumn("Metric");
        summary.AddColumn("Value");
        summary.AddRow("Previous Snapshot", diff.PreviousCapturedAtUtc?.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss") ?? "-");
        summary.AddRow("Current Snapshot", diff.CurrentCapturedAtUtc?.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss") ?? "-");
        summary.AddRow("Previous Endpoints", diff.PreviousEndpointCount.ToString());
        summary.AddRow("Current Endpoints", diff.CurrentEndpointCount.ToString());
        summary.AddRow("Added", diff.AddedCount.ToString());
        summary.AddRow("Removed", diff.RemovedCount.ToString());
        summary.AddRow("Changed", diff.ChangedCount.ToString());
        summary.AddRow("Unchanged", diff.UnchangedCount.ToString());
        summary.AddRow("Returned Rows", diff.Endpoints.Count.ToString());
        AnsiConsole.Write(summary);

        if (diff.Endpoints.Count == 0) {
            AnsiConsole.MarkupLine("[yellow]No endpoint deltas to display.[/]");
            return Task.FromResult(0);
        }

        var rows = new Table().Border(TableBorder.Rounded);
        rows.Title = new TableTitle("Certificate Snapshot Diff");
        rows.AddColumn("Host");
        rows.AddColumn("Port");
        rows.AddColumn("Status");
        rows.AddColumn("Reasons");
        rows.AddColumn("Issuer");
        rows.AddColumn("Root");
        rows.AddColumn("Expiry");
        foreach (var endpoint in diff.Endpoints.OrderBy(x => x.Host, StringComparer.OrdinalIgnoreCase).ThenBy(x => x.Port)) {
            var reasons = endpoint.ChangeReasons.Count > 0 ? string.Join(",", endpoint.ChangeReasons) : "-";
            var issuer = endpoint.CurrentIssuer ?? endpoint.PreviousIssuer ?? "-";
            var root = endpoint.CurrentRoot ?? endpoint.PreviousRoot ?? "-";
            var expiry = endpoint.CurrentNotAfterUtc?.UtcDateTime.ToString("yyyy-MM-dd") ??
                         endpoint.PreviousNotAfterUtc?.UtcDateTime.ToString("yyyy-MM-dd") ??
                         "-";
            rows.AddRow(
                endpoint.Host,
                endpoint.Port.ToString(),
                endpoint.Status,
                reasons,
                issuer,
                root,
                expiry);
        }
        AnsiConsole.Write(rows);

        return Task.FromResult(0);
    }

}
