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
/// Settings for <see cref="CertificateInventoryPolicyDriftCommand"/>.
/// </summary>
internal sealed class CertificateInventoryPolicyDriftSettings : CommandSettings {
    /// <summary>Certificate monitor cache directory (defaults to system temp path).</summary>
    [Description("Certificate monitor cache directory (defaults to system temp path).")]
    [CommandOption("--cache-dir <PATH>")]
    public string? CacheDirectory { get; set; }

    /// <summary>Only include snapshots captured since this UTC timestamp.</summary>
    [Description("Only include snapshots captured since this UTC timestamp.")]
    [CommandOption("--since-utc <UTC>")]
    public DateTime? SinceUtc { get; set; }

    /// <summary>Optional previous snapshot UTC selector (latest snapshot at or before timestamp).</summary>
    [Description("Optional previous snapshot UTC selector (latest snapshot at or before timestamp).")]
    [CommandOption("--previous-utc <UTC>")]
    public DateTime? PreviousUtc { get; set; }

    /// <summary>Optional zero-based selector for previous snapshot from latest to oldest (0 = latest).</summary>
    [Description("Optional zero-based selector for previous snapshot from latest to oldest (0 = latest).")]
    [CommandOption("--previous-index <N>")]
    public int? PreviousIndex { get; set; }

    /// <summary>Optional current snapshot UTC selector (latest snapshot at or before timestamp).</summary>
    [Description("Optional current snapshot UTC selector (latest snapshot at or before timestamp).")]
    [CommandOption("--current-utc <UTC>")]
    public DateTime? CurrentUtc { get; set; }

    /// <summary>Optional zero-based selector for current snapshot from latest to oldest (0 = latest).</summary>
    [Description("Optional zero-based selector for current snapshot from latest to oldest (0 = latest).")]
    [CommandOption("--current-index <N>")]
    public int? CurrentIndex { get; set; }

    /// <summary>Baseline policy profile (Strict, Balanced, Legacy).</summary>
    [Description("Baseline policy profile (Strict, Balanced, Legacy).")]
    [CommandOption("--baseline-profile <NAME>")]
    [DefaultValue("Balanced")]
    public string BaselineProfile { get; set; } = "Balanced";

    /// <summary>Only return endpoint rows with detected policy drift.</summary>
    [Description("Only return endpoint rows with detected policy drift.")]
    [CommandOption("--changed-only")]
    public bool ChangedOnly { get; set; }

    /// <summary>Maximum endpoint rows returned.</summary>
    [Description("Maximum endpoint rows returned.")]
    [CommandOption("--max-endpoints <N>")]
    [DefaultValue(300)]
    public int MaxEndpoints { get; set; } = 300;

    /// <summary>Output JSON instead of tables.</summary>
    [Description("Output JSON instead of tables.")]
    [CommandOption("--json")]
    public bool Json { get; set; }

    /// <summary>Optional CSV output path for endpoint policy drift rows.</summary>
    [Description("Optional CSV output path for endpoint policy drift rows.")]
    [CommandOption("--csv-path <PATH>")]
    public string? CsvPath { get; set; }

    /// <summary>Optional NDJSON output path for endpoint policy drift rows (one JSON object per line).</summary>
    [Description("Optional NDJSON output path for endpoint policy drift rows (one JSON object per line).")]
    [CommandOption("--ndjson-path <PATH>")]
    public string? NdjsonPath { get; set; }

    /// <summary>Optional JSON file path with policy override rules.</summary>
    [Description("Optional JSON file path with policy override rules.")]
    [CommandOption("--policy-overrides-path <PATH>")]
    public string? PolicyOverridesPath { get; set; }
}

/// <summary>
/// Displays endpoint-level policy drift between two persisted inventory snapshots.
/// </summary>
internal sealed class CertificateInventoryPolicyDriftCommand : AsyncCommand<CertificateInventoryPolicyDriftSettings> {
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    protected override Task<int> ExecuteAsync(CommandContext context, CertificateInventoryPolicyDriftSettings settings, CancellationToken cancellationToken) {
        if (settings == null) {
            throw new ArgumentNullException(nameof(settings));
        }

        if (settings.MaxEndpoints < 0) {
            AnsiConsole.MarkupLine("[red]--max-endpoints must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.PreviousIndex.HasValue && settings.PreviousIndex.Value < 0) {
            AnsiConsole.MarkupLine("[red]--previous-index must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.CurrentIndex.HasValue && settings.CurrentIndex.Value < 0) {
            AnsiConsole.MarkupLine("[red]--current-index must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.PreviousUtc.HasValue && settings.PreviousIndex.HasValue) {
            AnsiConsole.MarkupLine("[red]Use either --previous-utc or --previous-index, not both.[/]");
            return Task.FromResult(1);
        }
        if (settings.CurrentUtc.HasValue && settings.CurrentIndex.HasValue) {
            AnsiConsole.MarkupLine("[red]Use either --current-utc or --current-index, not both.[/]");
            return Task.FromResult(1);
        }

        if (!CertificateInventoryPolicyAnalyzer.TryResolveBaselineProfile(settings.BaselineProfile, out var normalizedProfile)) {
            AnsiConsole.MarkupLine($"[red]--baseline-profile must be one of: {CertificateInventoryPolicyAnalyzer.BaselineProfileAcceptedValues}.[/]");
            return Task.FromResult(1);
        }

        var cacheDirectory = CertificateInventoryCommandHelpers.ResolveCacheDirectory(settings.CacheDirectory);
        CertificateInventoryPolicyOverrides? policyOverrides = null;
        if (!string.IsNullOrWhiteSpace(settings.PolicyOverridesPath)) {
            try {
                policyOverrides = CertificateInventoryPolicyOverrides.Load(settings.PolicyOverridesPath!);
            } catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]Failed to load policy overrides:[/] {ex.Message}");
                return Task.FromResult(1);
            }
        }

        var monitor = new CertificateMonitor {
            CacheDirectory = cacheDirectory,
            PersistInventorySnapshots = false
        };
        var sinceUtc = CertificateInventoryCommandHelpers.ToUtc(settings.SinceUtc);
        var previousCapturedAtUtc = CertificateInventoryCommandHelpers.ToUtc(settings.PreviousUtc);
        var currentCapturedAtUtc = CertificateInventoryCommandHelpers.ToUtc(settings.CurrentUtc);
        if (settings.PreviousIndex.HasValue || settings.CurrentIndex.HasValue) {
            var snapshotIndex = monitor
                .LoadInventorySnapshots(sinceUtc)
                .OrderByDescending(snapshot => snapshot.CapturedAtUtc)
                .ToList();

            if (settings.PreviousIndex.HasValue) {
                if (!TryResolveSnapshotByIndex(snapshotIndex, settings.PreviousIndex.Value, out var selectedSnapshot)) {
                    AnsiConsole.MarkupLine($"[red]--previous-index {settings.PreviousIndex.Value} is out of range.[/] Available snapshots: {snapshotIndex.Count}");
                    return Task.FromResult(1);
                }
                previousCapturedAtUtc = selectedSnapshot.CapturedAtUtc;
            }

            if (settings.CurrentIndex.HasValue) {
                if (!TryResolveSnapshotByIndex(snapshotIndex, settings.CurrentIndex.Value, out var selectedSnapshot)) {
                    AnsiConsole.MarkupLine($"[red]--current-index {settings.CurrentIndex.Value} is out of range.[/] Available snapshots: {snapshotIndex.Count}");
                    return Task.FromResult(1);
                }
                currentCapturedAtUtc = selectedSnapshot.CapturedAtUtc;
            }
        }

        var drift = monitor.BuildInventoryPolicyDrift(
            sinceUtc: sinceUtc,
            baselineProfile: normalizedProfile,
            previousCapturedAtUtc: previousCapturedAtUtc,
            currentCapturedAtUtc: currentCapturedAtUtc,
            changedOnly: settings.ChangedOnly,
            maxEndpoints: settings.MaxEndpoints,
            policyOverrides: policyOverrides);

        if (!string.IsNullOrWhiteSpace(settings.CsvPath)) {
            try {
                WriteCsv(drift, settings.CsvPath!);
                AnsiConsole.MarkupLine($"[grey]CSV written:[/] {settings.CsvPath}");
            } catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]Failed to write CSV:[/] {ex.Message}");
                return Task.FromResult(1);
            }
        }

        if (!string.IsNullOrWhiteSpace(settings.NdjsonPath)) {
            try {
                WriteNdjson(drift, settings.NdjsonPath!);
                AnsiConsole.MarkupLine($"[grey]NDJSON written:[/] {settings.NdjsonPath}");
            } catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]Failed to write NDJSON:[/] {ex.Message}");
                return Task.FromResult(1);
            }
        }

        if (settings.Json) {
            Console.WriteLine(JsonSerializer.Serialize(drift, JsonOptions.Default));
            return Task.FromResult(0);
        }

        if (drift.SnapshotCount == 0) {
            AnsiConsole.MarkupLine($"[yellow]No inventory snapshots found in:[/] {cacheDirectory}");
            return Task.FromResult(0);
        }

        var summary = new Table().Border(TableBorder.Rounded);
        summary.AddColumn("Metric");
        summary.AddColumn("Value");
        summary.AddRow("Baseline Profile", drift.BaselineProfile);
        summary.AddRow("Snapshots", drift.SnapshotCount.ToString());
        summary.AddRow("Requested Previous Snapshot", drift.RequestedPreviousCapturedAtUtc?.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss") ?? "-");
        summary.AddRow("Requested Current Snapshot", drift.RequestedCurrentCapturedAtUtc?.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss") ?? "-");
        summary.AddRow("Previous Snapshot", drift.PreviousCapturedAtUtc?.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss") ?? "-");
        summary.AddRow("Current Snapshot", drift.CurrentCapturedAtUtc?.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss") ?? "-");
        summary.AddRow("Previous Endpoints", drift.PreviousEndpointCount.ToString());
        summary.AddRow("Current Endpoints", drift.CurrentEndpointCount.ToString());
        summary.AddRow("Union Endpoints", drift.EndpointCount.ToString());
        summary.AddRow("Previous Violation Endpoints", drift.PreviousViolationEndpointCount.ToString());
        summary.AddRow("Current Violation Endpoints", drift.CurrentViolationEndpointCount.ToString());
        summary.AddRow("Added Violation Endpoints", drift.AddedViolationEndpointCount.ToString());
        summary.AddRow("Resolved Violation Endpoints", drift.ResolvedViolationEndpointCount.ToString());
        summary.AddRow("Increased Violation Endpoints", drift.IncreasedViolationEndpointCount.ToString());
        summary.AddRow("Decreased Violation Endpoints", drift.DecreasedViolationEndpointCount.ToString());
        summary.AddRow("Unchanged Violation Endpoints", drift.UnchangedViolationEndpointCount.ToString());
        summary.AddRow("Endpoints with Any Policy Change", drift.EndpointsWithAnyPolicyChange.ToString());
        summary.AddRow("Endpoints Matching Filters", drift.EndpointsMatchingFilters.ToString());
        summary.AddRow("Excluded by ChangedOnly", drift.EndpointsExcludedByChangedOnly.ToString());
        summary.AddRow("Returned Endpoints", drift.Endpoints.Count.ToString());
        summary.AddRow("Truncated Endpoints", drift.EndpointsTruncatedByMaxEndpoints.ToString());
        AnsiConsole.Write(summary);

        if (drift.Warnings.Count > 0) {
            foreach (var warning in drift.Warnings) {
                if (string.IsNullOrWhiteSpace(warning)) {
                    continue;
                }

                AnsiConsole.MarkupLine($"[yellow]Warning:[/] {Markup.Escape(warning)}");
            }
        }

        if (drift.NewViolationCodeCounts.Count > 0) {
            var addedCodes = new Table().Border(TableBorder.Rounded);
            addedCodes.Title = new TableTitle("New Violation Codes");
            addedCodes.AddColumn("Code");
            addedCodes.AddColumn("Count");
            foreach (var code in drift.NewViolationCodeCounts
                         .OrderByDescending(x => x.Value)
                         .ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
                         .Take(20)) {
                addedCodes.AddRow(code.Key, code.Value.ToString());
            }
            AnsiConsole.Write(addedCodes);
        }

        if (drift.ResolvedViolationCodeCounts.Count > 0) {
            var resolvedCodes = new Table().Border(TableBorder.Rounded);
            resolvedCodes.Title = new TableTitle("Resolved Violation Codes");
            resolvedCodes.AddColumn("Code");
            resolvedCodes.AddColumn("Count");
            foreach (var code in drift.ResolvedViolationCodeCounts
                         .OrderByDescending(x => x.Value)
                         .ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
                         .Take(20)) {
                resolvedCodes.AddRow(code.Key, code.Value.ToString());
            }
            AnsiConsole.Write(resolvedCodes);
        }

        if (drift.Endpoints.Count == 0) {
            AnsiConsole.MarkupLine("[yellow]No endpoint policy drift rows to display.[/]");
            return Task.FromResult(0);
        }

        if (drift.Truncated) {
            AnsiConsole.MarkupLine($"[yellow]Endpoint rows truncated by --max-endpoints:[/] {drift.EndpointsTruncatedByMaxEndpoints}");
        }

        var rows = new Table().Border(TableBorder.Rounded);
        rows.Title = new TableTitle("Certificate Policy Drift");
        rows.AddColumn("Host");
        rows.AddColumn("Port");
        rows.AddColumn("Status");
        rows.AddColumn("Prev Viol");
        rows.AddColumn("Cur Viol");
        rows.AddColumn("Prev Sev");
        rows.AddColumn("Cur Sev");
        rows.AddColumn("New Codes");
        rows.AddColumn("Resolved Codes");
        rows.AddColumn("Changes");
        foreach (var endpoint in drift.Endpoints) {
            rows.AddRow(
                Markup.Escape(endpoint.Host),
                endpoint.Port.ToString(),
                Markup.Escape(endpoint.Status),
                endpoint.PreviousViolationCount.ToString(),
                endpoint.CurrentViolationCount.ToString(),
                Markup.Escape(endpoint.PreviousMaxViolationSeverity),
                Markup.Escape(endpoint.CurrentMaxViolationSeverity),
                Markup.Escape(endpoint.NewViolationCodes.Count == 0 ? "-" : string.Join(",", endpoint.NewViolationCodes)),
                Markup.Escape(endpoint.ResolvedViolationCodes.Count == 0 ? "-" : string.Join(",", endpoint.ResolvedViolationCodes)),
                Markup.Escape(endpoint.ChangeKinds.Count == 0 ? "-" : string.Join(",", endpoint.ChangeKinds)));
        }
        AnsiConsole.Write(rows);

        return Task.FromResult(0);
    }

    private static void WriteCsv(CertificateInventoryPolicyDriftSummary drift, string path) {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory)) {
            Directory.CreateDirectory(directory);
        }

        var sb = new StringBuilder();
        sb.AppendLine("Host,Port,Status,PreviousCompliant,CurrentCompliant,PreviousViolationCount,CurrentViolationCount,PreviousMaxViolationSeverity,CurrentMaxViolationSeverity,PreviousRiskScore,CurrentRiskScore,PreviousRiskSeverity,CurrentRiskSeverity,PreviousIssuer,CurrentIssuer,PreviousNotAfterUtc,CurrentNotAfterUtc,PreviousViolationCodes,CurrentViolationCodes,NewViolationCodes,ResolvedViolationCodes,ChangeKinds");

        foreach (var endpoint in drift.Endpoints) {
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.Host));
            sb.Append(',');
            sb.Append(endpoint.Port);
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.Status));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.PreviousCompliant?.ToString().ToLowerInvariant() ?? string.Empty));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.CurrentCompliant?.ToString().ToLowerInvariant() ?? string.Empty));
            sb.Append(',');
            sb.Append(endpoint.PreviousViolationCount);
            sb.Append(',');
            sb.Append(endpoint.CurrentViolationCount);
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.PreviousMaxViolationSeverity));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.CurrentMaxViolationSeverity));
            sb.Append(',');
            sb.Append(endpoint.PreviousRiskScore);
            sb.Append(',');
            sb.Append(endpoint.CurrentRiskScore);
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.PreviousRiskSeverity));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.CurrentRiskSeverity));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.PreviousIssuer));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.CurrentIssuer));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.PreviousNotAfterUtc?.UtcDateTime.ToString("O") ?? string.Empty));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.CurrentNotAfterUtc?.UtcDateTime.ToString("O") ?? string.Empty));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(string.Join("|", endpoint.PreviousViolationCodes)));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(string.Join("|", endpoint.CurrentViolationCodes)));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(string.Join("|", endpoint.NewViolationCodes)));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(string.Join("|", endpoint.ResolvedViolationCodes)));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(string.Join("|", endpoint.ChangeKinds)));
            sb.AppendLine();
        }

        CertificateInventoryCommandHelpers.WriteUtf8Text(fullPath, sb.ToString());
    }

    private static void WriteNdjson(CertificateInventoryPolicyDriftSummary drift, string path) {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory)) {
            Directory.CreateDirectory(directory);
        }

        var sb = new StringBuilder();
        foreach (var endpoint in drift.Endpoints) {
            sb.AppendLine(CertificateInventoryCommandHelpers.SerializeJsonLine(endpoint));
        }

        CertificateInventoryCommandHelpers.WriteUtf8Text(fullPath, sb.ToString());
    }

    private static bool TryResolveSnapshotByIndex(
        IReadOnlyList<CertificateInventorySnapshot> snapshots,
        int index,
        out CertificateInventorySnapshot selectedSnapshot) {
        selectedSnapshot = null!;
        if (index < 0 || index >= snapshots.Count) {
            return false;
        }

        selectedSnapshot = snapshots[index];
        return true;
    }
}

