using DomainDetective.Helpers;
using Spectre.Console;
using Spectre.Console.Cli;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace DomainDetective.CLI.Commands;

/// <summary>
/// Settings for <see cref="CertificateInventoryCtDiagnosticsCommand"/>.
/// </summary>
internal sealed class CertificateInventoryCtDiagnosticsSettings : CommandSettings {
    [Description("Certificate monitor cache directory (defaults to system temp path).")]
    [CommandOption("--cache-dir <PATH>")]
    public string? CacheDirectory { get; set; }

    [Description("Only include snapshots captured since this UTC timestamp.")]
    [CommandOption("--since-utc <UTC>")]
    public DateTime? SinceUtc { get; set; }

    [Description("Only include snapshots captured up to this UTC timestamp.")]
    [CommandOption("--until-utc <UTC>")]
    public DateTime? UntilUtc { get; set; }

    [Description("Only evaluate the latest snapshot after date filtering.")]
    [CommandOption("--latest-only")]
    public bool LatestOnly { get; set; }

    [Description("State filter(s): Succeeded, Failed, CircuitOpen, Unknown. Repeat for multiple values.")]
    [CommandOption("--state <STATE>")]
    public string[] States { get; set; } = Array.Empty<string>();

    [Description("Optional contains filter applied to diagnostic log URL.")]
    [CommandOption("--log-url-contains <TEXT>")]
    public string? LogUrlContains { get; set; }

    [Description("Optional contains filter applied to diagnostic scope.")]
    [CommandOption("--scope-contains <TEXT>")]
    public string? ScopeContains { get; set; }

    [Description("Only return diagnostics currently marked as circuit open.")]
    [CommandOption("--circuit-open-only")]
    public bool CircuitOpenOnly { get; set; }

    [Description("Only return diagnostics that include failure messages.")]
    [CommandOption("--failure-only")]
    public bool FailureOnly { get; set; }

    [Description("Optional minimum LagBefore value.")]
    [CommandOption("--lag-before-min <N>")]
    public long? LagBeforeMin { get; set; }

    [Description("Optional maximum LagBefore value.")]
    [CommandOption("--lag-before-max <N>")]
    public long? LagBeforeMax { get; set; }

    [Description("Optional minimum LagAfter value.")]
    [CommandOption("--lag-after-min <N>")]
    public long? LagAfterMin { get; set; }

    [Description("Optional maximum LagAfter value.")]
    [CommandOption("--lag-after-max <N>")]
    public long? LagAfterMax { get; set; }

    [Description("Maximum number of rows returned.")]
    [CommandOption("--max-results <N>")]
    [DefaultValue(2000)]
    public int MaxResults { get; set; } = 2000;

    [Description("Output JSON instead of tables.")]
    [CommandOption("--json")]
    public bool Json { get; set; }

    [Description("Optional CSV output path.")]
    [CommandOption("--csv-path <PATH>")]
    public string? CsvPath { get; set; }

    [Description("Optional NDJSON output path.")]
    [CommandOption("--ndjson-path <PATH>")]
    public string? NdjsonPath { get; set; }
}

/// <summary>
/// Queries persisted native CT ingestion diagnostics.
/// </summary>
internal sealed class CertificateInventoryCtDiagnosticsCommand : AsyncCommand<CertificateInventoryCtDiagnosticsSettings> {
    private static readonly HashSet<string> AllowedStates = new(StringComparer.OrdinalIgnoreCase) {
        "Succeeded",
        "Failed",
        "CircuitOpen",
        "Unknown"
    };

    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    public override Task<int> ExecuteAsync(CommandContext context, CertificateInventoryCtDiagnosticsSettings settings) {
        if (settings == null) {
            throw new ArgumentNullException(nameof(settings));
        }

        if (settings.MaxResults < 0) {
            AnsiConsole.MarkupLine("[red]--max-results must be 0 or greater.[/]");
            return Task.FromResult(1);
        }

        var sinceUtc = CertificateInventoryCommandHelpers.ToUtc(settings.SinceUtc);
        var untilUtc = CertificateInventoryCommandHelpers.ToUtc(settings.UntilUtc);
        if (sinceUtc.HasValue && untilUtc.HasValue && sinceUtc.Value > untilUtc.Value) {
            AnsiConsole.MarkupLine("[red]--since-utc must be less than or equal to --until-utc.[/]");
            return Task.FromResult(1);
        }
        if (settings.LagBeforeMin.HasValue && settings.LagBeforeMax.HasValue && settings.LagBeforeMin.Value > settings.LagBeforeMax.Value) {
            AnsiConsole.MarkupLine("[red]--lag-before-min must be less than or equal to --lag-before-max.[/]");
            return Task.FromResult(1);
        }
        if (settings.LagAfterMin.HasValue && settings.LagAfterMax.HasValue && settings.LagAfterMin.Value > settings.LagAfterMax.Value) {
            AnsiConsole.MarkupLine("[red]--lag-after-min must be less than or equal to --lag-after-max.[/]");
            return Task.FromResult(1);
        }

        var query = new CertificateInventoryNativeCtDiagnosticsQuery {
            SinceUtc = sinceUtc,
            UntilUtc = untilUtc,
            LatestSnapshotOnly = settings.LatestOnly,
            LogUrlContains = settings.LogUrlContains,
            ScopeContains = settings.ScopeContains,
            CircuitOpenOnly = settings.CircuitOpenOnly,
            FailureOnly = settings.FailureOnly,
            LagBeforeMin = settings.LagBeforeMin,
            LagBeforeMax = settings.LagBeforeMax,
            LagAfterMin = settings.LagAfterMin,
            LagAfterMax = settings.LagAfterMax,
            MaxResults = settings.MaxResults
        };

        if (settings.States != null && settings.States.Length > 0) {
            foreach (var state in settings.States) {
                if (string.IsNullOrWhiteSpace(state)) {
                    continue;
                }

                var normalized = state.Trim();
                if (!AllowedStates.Contains(normalized)) {
                    AnsiConsole.MarkupLine($"[red]Unsupported state:[/] {normalized}. Allowed: Succeeded, Failed, CircuitOpen, Unknown.");
                    return Task.FromResult(1);
                }

                query.States.Add(normalized);
            }
        }

        var monitor = new CertificateMonitor {
            CacheDirectory = CertificateInventoryCommandHelpers.ResolveCacheDirectory(settings.CacheDirectory),
            PersistInventorySnapshots = false
        };
        var result = monitor.QueryInventoryNativeCtDiagnostics(query);

        if (!string.IsNullOrWhiteSpace(settings.CsvPath)) {
            try {
                WriteCsv(result, settings.CsvPath!);
                AnsiConsole.MarkupLine($"[grey]CSV written:[/] {settings.CsvPath}");
            } catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]Failed to write CSV:[/] {ex.Message}");
                return Task.FromResult(1);
            }
        }

        if (!string.IsNullOrWhiteSpace(settings.NdjsonPath)) {
            try {
                WriteNdjson(result, settings.NdjsonPath!);
                AnsiConsole.MarkupLine($"[grey]NDJSON written:[/] {settings.NdjsonPath}");
            } catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]Failed to write NDJSON:[/] {ex.Message}");
                return Task.FromResult(1);
            }
        }

        if (settings.Json) {
            Console.WriteLine(JsonSerializer.Serialize(result, JsonOptions.Default));
            return Task.FromResult(0);
        }

        var summary = new Table().Border(TableBorder.Rounded).Title("Native CT Diagnostics");
        summary.AddColumn("Metric");
        summary.AddColumn("Value");
        summary.AddRow("Loaded Snapshots", result.LoadedSnapshotCount.ToString());
        summary.AddRow("Scanned Snapshots", result.ScannedSnapshotCount.ToString());
        summary.AddRow("Scanned Diagnostics", result.ScannedDiagnosticCount.ToString());
        summary.AddRow("Matched Diagnostics", result.MatchedDiagnosticCount.ToString());
        summary.AddRow("Returned Rows", result.Entries.Count.ToString());
        summary.AddRow("Truncated", result.Truncated ? "Yes" : "No");
        AnsiConsole.Write(summary);

        if (result.Entries.Count == 0) {
            AnsiConsole.MarkupLine("[yellow]No native CT diagnostics matched filters.[/]");
            return Task.FromResult(0);
        }

        var rows = new Table().Border(TableBorder.Rounded);
        rows.Title = new TableTitle("Native CT Diagnostic Rows");
        rows.AddColumn("Captured (UTC)");
        rows.AddColumn("State");
        rows.AddColumn("Scope");
        rows.AddColumn("Log");
        rows.AddColumn("Lag Before");
        rows.AddColumn("Lag After");
        rows.AddColumn("Circuit Until (UTC)");
        rows.AddColumn("Failure");

        foreach (var observed in result.Entries) {
            var entry = observed.Entry ?? new NativeCtLogDiagnosticEntry();
            rows.AddRow(
                observed.CapturedAtUtc.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss"),
                string.IsNullOrWhiteSpace(entry.State) ? "-" : entry.State,
                string.IsNullOrWhiteSpace(entry.Scope) ? "-" : entry.Scope,
                string.IsNullOrWhiteSpace(entry.LogUrl) ? "-" : entry.LogUrl,
                entry.LagBefore.HasValue ? entry.LagBefore.Value.ToString() : "-",
                entry.LagAfter.HasValue ? entry.LagAfter.Value.ToString() : "-",
                entry.CircuitOpenUntilUtc.HasValue ? entry.CircuitOpenUntilUtc.Value.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss") : "-",
                string.IsNullOrWhiteSpace(entry.Failure) ? "-" : entry.Failure);
        }
        AnsiConsole.Write(rows);

        return Task.FromResult(0);
    }

    private static void WriteCsv(CertificateInventoryNativeCtDiagnosticsResult result, string path) {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory)) {
            Directory.CreateDirectory(directory);
        }

        var sb = new StringBuilder();
        sb.AppendLine("CapturedAtUtc,State,Scope,LogUrl,SharedIngestion,TreeSize,LastProcessedIndex,LagBefore,LagAfter,CircuitOpenUntilUtc,Failure");
        foreach (var observed in result.Entries) {
            var entry = observed.Entry ?? new NativeCtLogDiagnosticEntry();
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(observed.CapturedAtUtc.UtcDateTime.ToString("O")));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(entry.State));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(entry.Scope));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(entry.LogUrl));
            sb.Append(',');
            sb.Append(entry.SharedIngestion);
            sb.Append(',');
            sb.Append(entry.TreeSize.HasValue ? entry.TreeSize.Value.ToString() : string.Empty);
            sb.Append(',');
            sb.Append(entry.LastProcessedIndex.HasValue ? entry.LastProcessedIndex.Value.ToString() : string.Empty);
            sb.Append(',');
            sb.Append(entry.LagBefore.HasValue ? entry.LagBefore.Value.ToString() : string.Empty);
            sb.Append(',');
            sb.Append(entry.LagAfter.HasValue ? entry.LagAfter.Value.ToString() : string.Empty);
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(entry.CircuitOpenUntilUtc?.UtcDateTime.ToString("O") ?? string.Empty));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(entry.Failure));
            sb.AppendLine();
        }

        File.WriteAllText(fullPath, sb.ToString(), Encoding.UTF8);
    }

    private static void WriteNdjson(CertificateInventoryNativeCtDiagnosticsResult result, string path) {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory)) {
            Directory.CreateDirectory(directory);
        }

        using var stream = new StreamWriter(fullPath, false, new UTF8Encoding(false));
        foreach (var observed in result.Entries) {
            stream.WriteLine(JsonSerializer.Serialize(observed, JsonOptions.Default));
        }
    }
}
