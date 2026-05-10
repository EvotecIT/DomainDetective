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
/// Settings for <see cref="CertificateInventoryCtHealthCommand"/>.
/// </summary>
internal sealed class CertificateInventoryCtHealthSettings : CommandSettings {
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

    [Description("Maximum snapshot rows returned.")]
    [CommandOption("--max-snapshots <N>")]
    [DefaultValue(60)]
    public int MaxSnapshots { get; set; } = 60;

    [Description("Alert threshold: maximum allowed diagnostics in Failed state.")]
    [CommandOption("--max-failed <N>")]
    public int? MaxFailed { get; set; }

    [Description("Alert threshold: maximum allowed diagnostics in CircuitOpen state.")]
    [CommandOption("--max-circuit-open <N>")]
    public int? MaxCircuitOpen { get; set; }

    [Description("Alert threshold: maximum allowed LagAfter value across diagnostics.")]
    [CommandOption("--max-lag-after <N>")]
    public long? MaxLagAfter { get; set; }

    [Description("Evaluate all returned snapshots for exit code. By default only the latest row gates exit code.")]
    [CommandOption("--fail-on-any-breach")]
    public bool FailOnAnyBreach { get; set; }

    [Description("Do not return non-zero exit code when thresholds are breached.")]
    [CommandOption("--no-fail-on-threshold-breach")]
    public bool NoFailOnThresholdBreach { get; set; }

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
/// Shows CT ingestion health timeline and latest breach status from persisted inventory snapshots.
/// </summary>
internal sealed class CertificateInventoryCtHealthCommand : AsyncCommand<CertificateInventoryCtHealthSettings> {
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    protected override Task<int> ExecuteAsync(CommandContext context, CertificateInventoryCtHealthSettings settings, CancellationToken cancellationToken) {
        if (settings == null) {
            throw new ArgumentNullException(nameof(settings));
        }

        if (settings.MaxSnapshots < 0) {
            AnsiConsole.MarkupLine("[red]--max-snapshots must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.MaxFailed.HasValue && settings.MaxFailed.Value < 0) {
            AnsiConsole.MarkupLine("[red]--max-failed must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.MaxCircuitOpen.HasValue && settings.MaxCircuitOpen.Value < 0) {
            AnsiConsole.MarkupLine("[red]--max-circuit-open must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.MaxLagAfter.HasValue && settings.MaxLagAfter.Value < 0) {
            AnsiConsole.MarkupLine("[red]--max-lag-after must be 0 or greater.[/]");
            return Task.FromResult(1);
        }

        var sinceUtc = CertificateInventoryCommandHelpers.ToUtc(settings.SinceUtc);
        var untilUtc = CertificateInventoryCommandHelpers.ToUtc(settings.UntilUtc);
        if (sinceUtc.HasValue && untilUtc.HasValue && sinceUtc.Value > untilUtc.Value) {
            AnsiConsole.MarkupLine("[red]--since-utc must be less than or equal to --until-utc.[/]");
            return Task.FromResult(1);
        }

        var monitor = new CertificateMonitor {
            CacheDirectory = CertificateInventoryCommandHelpers.ResolveCacheDirectory(settings.CacheDirectory),
            PersistInventorySnapshots = false
        };
        var query = new CertificateInventoryNativeCtDiagnosticsHealthQuery {
            SinceUtc = sinceUtc,
            UntilUtc = untilUtc,
            LatestSnapshotOnly = settings.LatestOnly,
            MaxSnapshots = settings.MaxSnapshots,
            AlertThresholds = new CertificateInventoryNativeCtDiagnosticsAlertThresholds {
                MaxFailedDiagnostics = settings.MaxFailed,
                MaxCircuitOpenDiagnostics = settings.MaxCircuitOpen,
                MaxLagAfter = settings.MaxLagAfter
            }
        };
        var health = monitor.BuildInventoryNativeCtDiagnosticsHealth(query);

        if (!string.IsNullOrWhiteSpace(settings.CsvPath)) {
            try {
                WriteCsv(health, settings.CsvPath!);
                AnsiConsole.MarkupLine($"[grey]CSV written:[/] {settings.CsvPath}");
            } catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]Failed to write CSV:[/] {ex.Message}");
                return Task.FromResult(1);
            }
        }

        if (!string.IsNullOrWhiteSpace(settings.NdjsonPath)) {
            try {
                WriteNdjson(health, settings.NdjsonPath!);
                AnsiConsole.MarkupLine($"[grey]NDJSON written:[/] {settings.NdjsonPath}");
            } catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]Failed to write NDJSON:[/] {ex.Message}");
                return Task.FromResult(1);
            }
        }

        if (settings.Json) {
            Console.WriteLine(JsonSerializer.Serialize(health, JsonOptions.Default));
            return Task.FromResult(ResolveExitCode(health, settings, false));
        }

        var summary = new Table().Border(TableBorder.Rounded).Title("Native CT Health");
        summary.AddColumn("Metric");
        summary.AddColumn("Value");
        summary.AddRow("Loaded Snapshots", health.LoadedSnapshotCount.ToString());
        summary.AddRow("Returned Snapshots", health.ReturnedSnapshotCount.ToString());
        summary.AddRow("Breached Snapshots", health.BreachedSnapshotCount.ToString());
        summary.AddRow("Latest Snapshot", health.LatestSnapshotCapturedAtUtc?.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss") ?? "-");
        summary.AddRow("Latest Status", health.LatestStatus);
        summary.AddRow("Last Breach", health.LastBreachCapturedAtUtc?.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss") ?? "-");
        summary.AddRow("Threshold MaxFailed", health.AlertThresholds.MaxFailedDiagnostics?.ToString() ?? "-");
        summary.AddRow("Threshold MaxCircuitOpen", health.AlertThresholds.MaxCircuitOpenDiagnostics?.ToString() ?? "-");
        summary.AddRow("Threshold MaxLagAfter", health.AlertThresholds.MaxLagAfter?.ToString() ?? "-");
        AnsiConsole.Write(summary);

        if (health.Snapshots.Count > 0) {
            var rows = new Table().Border(TableBorder.Rounded).Title("Native CT Health Timeline");
            rows.AddColumn("Captured (UTC)");
            rows.AddColumn("Status");
            rows.AddColumn("Diagnostics");
            rows.AddColumn("Failed");
            rows.AddColumn("CircuitOpen");
            rows.AddColumn("Max LagAfter");
            rows.AddColumn("Breaches");

            foreach (var row in health.Snapshots) {
                var breachSummary = row.Breaches.Count == 0 ? "-" : string.Join(" | ", row.Breaches);
                rows.AddRow(
                    row.CapturedAtUtc.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss"),
                    row.Status,
                    row.DiagnosticCount.ToString(),
                    row.FailedCount.ToString(),
                    row.CircuitOpenCount.ToString(),
                    row.HighestLagAfter?.ToString() ?? "-",
                    breachSummary);
            }

            AnsiConsole.Write(rows);
        } else {
            AnsiConsole.MarkupLine("[yellow]No snapshots matched the requested CT health window.[/]");
        }

        return Task.FromResult(ResolveExitCode(health, settings, true));
    }

    private static int ResolveExitCode(
        CertificateInventoryNativeCtDiagnosticsHealthSummary health,
        CertificateInventoryCtHealthSettings settings,
        bool renderMessages) {
        if (settings.NoFailOnThresholdBreach) {
            return 0;
        }

        var breached = settings.FailOnAnyBreach
            ? health.BreachedSnapshotCount > 0
            : health.Snapshots.Count > 0 && health.Snapshots[0].ThresholdBreached;
        if (!breached) {
            return 0;
        }

        if (renderMessages) {
            if (settings.FailOnAnyBreach) {
                AnsiConsole.MarkupLine("[red]Threshold breached in one or more returned snapshots.[/]");
            } else {
                AnsiConsole.MarkupLine("[red]Threshold breached in latest returned snapshot.[/]");
            }

            foreach (var message in health.LatestBreachMessages) {
                AnsiConsole.MarkupLine($"[red]Breach detail:[/] {Markup.Escape(message)}");
            }
        }

        return 2;
    }

    private static void WriteCsv(CertificateInventoryNativeCtDiagnosticsHealthSummary health, string path) {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory)) {
            Directory.CreateDirectory(directory);
        }

        var sb = new StringBuilder();
        sb.AppendLine("CapturedAtUtc,Status,ThresholdBreached,DiagnosticCount,FailedCount,CircuitOpenCount,HighestLagAfter,Breaches,LoadedSnapshotCount,ReturnedSnapshotCount,BreachedSnapshotCount,LatestStatus,LastBreachCapturedAtUtc,ThresholdMaxFailed,ThresholdMaxCircuitOpen,ThresholdMaxLagAfter");
        foreach (var row in health.Snapshots) {
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(row.CapturedAtUtc.UtcDateTime.ToString("O")));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(row.Status));
            sb.Append(',');
            sb.Append(row.ThresholdBreached);
            sb.Append(',');
            sb.Append(row.DiagnosticCount);
            sb.Append(',');
            sb.Append(row.FailedCount);
            sb.Append(',');
            sb.Append(row.CircuitOpenCount);
            sb.Append(',');
            sb.Append(row.HighestLagAfter.HasValue ? row.HighestLagAfter.Value.ToString() : string.Empty);
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(string.Join(" | ", row.Breaches)));
            sb.Append(',');
            sb.Append(health.LoadedSnapshotCount);
            sb.Append(',');
            sb.Append(health.ReturnedSnapshotCount);
            sb.Append(',');
            sb.Append(health.BreachedSnapshotCount);
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(health.LatestStatus));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(health.LastBreachCapturedAtUtc?.UtcDateTime.ToString("O") ?? string.Empty));
            sb.Append(',');
            sb.Append(health.AlertThresholds.MaxFailedDiagnostics.HasValue ? health.AlertThresholds.MaxFailedDiagnostics.Value.ToString() : string.Empty);
            sb.Append(',');
            sb.Append(health.AlertThresholds.MaxCircuitOpenDiagnostics.HasValue ? health.AlertThresholds.MaxCircuitOpenDiagnostics.Value.ToString() : string.Empty);
            sb.Append(',');
            sb.Append(health.AlertThresholds.MaxLagAfter.HasValue ? health.AlertThresholds.MaxLagAfter.Value.ToString() : string.Empty);
            sb.AppendLine();
        }

        CertificateInventoryCommandHelpers.WriteUtf8Text(fullPath, sb.ToString());
    }

    private static void WriteNdjson(CertificateInventoryNativeCtDiagnosticsHealthSummary health, string path) {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory)) {
            Directory.CreateDirectory(directory);
        }

        var sb = new StringBuilder();
        foreach (var row in health.Snapshots) {
            sb.AppendLine(CertificateInventoryCommandHelpers.SerializeJsonLine(new {
                RowType = "Snapshot",
                row.CapturedAtUtc,
                row.Status,
                row.ThresholdBreached,
                row.DiagnosticCount,
                row.FailedCount,
                row.CircuitOpenCount,
                row.HighestLagAfter,
                row.Breaches,
                health.LoadedSnapshotCount,
                health.ReturnedSnapshotCount,
                health.BreachedSnapshotCount,
                health.LatestStatus,
                health.LastBreachCapturedAtUtc,
                health.AlertThresholds.MaxFailedDiagnostics,
                health.AlertThresholds.MaxCircuitOpenDiagnostics,
                health.AlertThresholds.MaxLagAfter
            }));
        }

        CertificateInventoryCommandHelpers.WriteUtf8Text(fullPath, sb.ToString());
    }
}
