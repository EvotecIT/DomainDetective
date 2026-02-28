using DomainDetective.Helpers;
using Spectre.Console;
using Spectre.Console.Cli;
using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Text;
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

    /// <summary>Optional CSV output path for endpoint diff rows.</summary>
    [Description("Optional CSV output path for endpoint diff rows.")]
    [CommandOption("--csv-path <PATH>")]
    public string? CsvPath { get; set; }

    /// <summary>Optional NDJSON output path for endpoint diff rows (one JSON object per line).</summary>
    [Description("Optional NDJSON output path for endpoint diff rows (one JSON object per line).")]
    [CommandOption("--ndjson-path <PATH>")]
    public string? NdjsonPath { get; set; }
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

        if (!string.IsNullOrWhiteSpace(settings.CsvPath)) {
            try {
                WriteCsv(diff, settings.CsvPath!);
                AnsiConsole.MarkupLine($"[grey]CSV written:[/] {settings.CsvPath}");
            } catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]Failed to write CSV:[/] {ex.Message}");
                return Task.FromResult(1);
            }
        }

        if (!string.IsNullOrWhiteSpace(settings.NdjsonPath)) {
            try {
                WriteNdjson(diff, settings.NdjsonPath!);
                AnsiConsole.MarkupLine($"[grey]NDJSON written:[/] {settings.NdjsonPath}");
            } catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]Failed to write NDJSON:[/] {ex.Message}");
                return Task.FromResult(1);
            }
        }

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
        summary.AddRow("Requested Previous Snapshot", diff.RequestedPreviousCapturedAtUtc?.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss") ?? "-");
        summary.AddRow("Requested Current Snapshot", diff.RequestedCurrentCapturedAtUtc?.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss") ?? "-");
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

        if (diff.Warnings.Count > 0) {
            foreach (var warning in diff.Warnings) {
                if (string.IsNullOrWhiteSpace(warning)) {
                    continue;
                }

                AnsiConsole.MarkupLine($"[yellow]Warning:[/] {Markup.Escape(warning)}");
            }
        }

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

    private static void WriteCsv(CertificateInventoryDiffSummary diff, string path) {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory)) {
            Directory.CreateDirectory(directory);
        }

        var warnings = string.Join("|", diff.Warnings.Where(warning => !string.IsNullOrWhiteSpace(warning)));
        var requestedPrevious = diff.RequestedPreviousCapturedAtUtc?.UtcDateTime.ToString("O") ?? string.Empty;
        var requestedCurrent = diff.RequestedCurrentCapturedAtUtc?.UtcDateTime.ToString("O") ?? string.Empty;
        var previousSnapshot = diff.PreviousCapturedAtUtc?.UtcDateTime.ToString("O") ?? string.Empty;
        var currentSnapshot = diff.CurrentCapturedAtUtc?.UtcDateTime.ToString("O") ?? string.Empty;

        var sb = new StringBuilder();
        sb.AppendLine("Host,Port,Status,ChangeReasons,PreviousService,CurrentService,PreviousIssuer,CurrentIssuer,PreviousRoot,CurrentRoot,PreviousThumbprint,CurrentThumbprint,PreviousNotAfterUtc,CurrentNotAfterUtc,PreviousValid,CurrentValid,PreviousChainComplete,CurrentChainComplete,PreviousHostnameMatch,CurrentHostnameMatch,RequestedPreviousSnapshotUtc,RequestedCurrentSnapshotUtc,PreviousSnapshotUtc,CurrentSnapshotUtc,Warnings");
        foreach (var endpoint in diff.Endpoints) {
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.Host));
            sb.Append(',');
            sb.Append(endpoint.Port);
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.Status));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(string.Join("|", endpoint.ChangeReasons)));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.PreviousService));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.CurrentService));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.PreviousIssuer));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.CurrentIssuer));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.PreviousRoot));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.CurrentRoot));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.PreviousThumbprint));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.CurrentThumbprint));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.PreviousNotAfterUtc?.UtcDateTime.ToString("O") ?? string.Empty));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.CurrentNotAfterUtc?.UtcDateTime.ToString("O") ?? string.Empty));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.PreviousValid?.ToString().ToLowerInvariant() ?? string.Empty));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.CurrentValid?.ToString().ToLowerInvariant() ?? string.Empty));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.PreviousChainComplete?.ToString().ToLowerInvariant() ?? string.Empty));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.CurrentChainComplete?.ToString().ToLowerInvariant() ?? string.Empty));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.PreviousHostnameMatch?.ToString().ToLowerInvariant() ?? string.Empty));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.CurrentHostnameMatch?.ToString().ToLowerInvariant() ?? string.Empty));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(requestedPrevious));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(requestedCurrent));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(previousSnapshot));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(currentSnapshot));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(warnings));
            sb.AppendLine();
        }

        CertificateInventoryCommandHelpers.WriteUtf8Text(fullPath, sb.ToString());
    }

    private static void WriteNdjson(CertificateInventoryDiffSummary diff, string path) {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory)) {
            Directory.CreateDirectory(directory);
        }

        var sb = new StringBuilder();
        foreach (var endpoint in diff.Endpoints) {
            sb.AppendLine(CertificateInventoryCommandHelpers.SerializeJsonLine(endpoint));
        }

        CertificateInventoryCommandHelpers.WriteUtf8Text(fullPath, sb.ToString());
    }
}

