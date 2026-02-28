using DomainDetective.Helpers;
using Spectre.Console;
using Spectre.Console.Cli;
using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
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

    /// <summary>Optional current snapshot UTC selector (latest snapshot at or before timestamp).</summary>
    [Description("Optional current snapshot UTC selector (latest snapshot at or before timestamp).")]
    [CommandOption("--current-utc <UTC>")]
    public DateTime? CurrentUtc { get; set; }

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
}

/// <summary>
/// Displays endpoint-level policy drift between two persisted inventory snapshots.
/// </summary>
internal sealed class CertificateInventoryPolicyDriftCommand : AsyncCommand<CertificateInventoryPolicyDriftSettings> {
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    public override Task<int> ExecuteAsync(CommandContext context, CertificateInventoryPolicyDriftSettings settings) {
        if (settings == null) {
            throw new ArgumentNullException(nameof(settings));
        }

        if (settings.MaxEndpoints < 0) {
            AnsiConsole.MarkupLine("[red]--max-endpoints must be 0 or greater.[/]");
            return Task.FromResult(1);
        }

        if (!CertificateInventoryPolicyAnalyzer.TryResolveBaselineProfile(settings.BaselineProfile, out var normalizedProfile)) {
            AnsiConsole.MarkupLine($"[red]--baseline-profile must be one of: {CertificateInventoryPolicyAnalyzer.BaselineProfileAcceptedValues}.[/]");
            return Task.FromResult(1);
        }

        var cacheDirectory = ResolveCacheDirectory(settings.CacheDirectory);
        var monitor = new CertificateMonitor {
            CacheDirectory = cacheDirectory,
            PersistInventorySnapshots = false
        };

        var drift = monitor.BuildInventoryPolicyDrift(
            sinceUtc: ToUtc(settings.SinceUtc),
            baselineProfile: normalizedProfile,
            previousCapturedAtUtc: ToUtc(settings.PreviousUtc),
            currentCapturedAtUtc: ToUtc(settings.CurrentUtc),
            changedOnly: settings.ChangedOnly,
            maxEndpoints: settings.MaxEndpoints);

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
                endpoint.Host,
                endpoint.Port.ToString(),
                endpoint.Status,
                endpoint.PreviousViolationCount.ToString(),
                endpoint.CurrentViolationCount.ToString(),
                endpoint.PreviousMaxViolationSeverity,
                endpoint.CurrentMaxViolationSeverity,
                endpoint.NewViolationCodes.Count == 0 ? "-" : string.Join(",", endpoint.NewViolationCodes),
                endpoint.ResolvedViolationCodes.Count == 0 ? "-" : string.Join(",", endpoint.ResolvedViolationCodes),
                endpoint.ChangeKinds.Count == 0 ? "-" : string.Join(",", endpoint.ChangeKinds));
        }
        AnsiConsole.Write(rows);

        return Task.FromResult(0);
    }

    private static string ResolveCacheDirectory(string? configured) {
        if (!string.IsNullOrWhiteSpace(configured)) {
            return configured;
        }

        return Path.Combine(Path.GetTempPath(), "DomainDetective", "cert-monitor");
    }

    private static DateTimeOffset? ToUtc(DateTime? value) {
        if (!value.HasValue) {
            return null;
        }

        var dt = value.Value;
        if (dt.Kind == DateTimeKind.Unspecified) {
            dt = DateTime.SpecifyKind(dt, DateTimeKind.Utc);
        }

        return dt.ToUniversalTime();
    }
}
