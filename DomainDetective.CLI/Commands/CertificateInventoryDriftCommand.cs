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
/// Settings for <see cref="CertificateInventoryDriftCommand"/>.
/// </summary>
internal sealed class CertificateInventoryDriftSettings : CommandSettings {
    /// <summary>Certificate monitor cache directory (defaults to system temp path).</summary>
    [Description("Certificate monitor cache directory (defaults to system temp path).")]
    [CommandOption("--cache-dir <PATH>")]
    public string? CacheDirectory { get; set; }

    /// <summary>Only include snapshots captured since this UTC timestamp.</summary>
    [Description("Only include snapshots captured since this UTC timestamp.")]
    [CommandOption("--since-utc <UTC>")]
    public DateTime? SinceUtc { get; set; }

    /// <summary>Only return endpoints where drift was observed.</summary>
    [Description("Only return endpoints where drift was observed.")]
    [CommandOption("--changed-only")]
    public bool ChangedOnly { get; set; }

    /// <summary>Maximum endpoint rows returned.</summary>
    [Description("Maximum endpoint rows returned.")]
    [CommandOption("--max-endpoints <N>")]
    [DefaultValue(200)]
    public int MaxEndpoints { get; set; } = 200;

    /// <summary>Optional minimum drift severity filter (none, low, medium, high).</summary>
    [Description("Optional minimum drift severity filter (none, low, medium, high).")]
    [CommandOption("--minimum-severity <SEVERITY>")]
    public string? MinimumSeverity { get; set; }

    /// <summary>Output JSON instead of tables.</summary>
    [Description("Output JSON instead of tables.")]
    [CommandOption("--json")]
    public bool Json { get; set; }
}

/// <summary>
/// Displays endpoint-level certificate drift from persisted inventory snapshots.
/// </summary>
internal sealed class CertificateInventoryDriftCommand : AsyncCommand<CertificateInventoryDriftSettings> {
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    public override Task<int> ExecuteAsync(CommandContext context, CertificateInventoryDriftSettings settings) {
        if (settings == null) {
            throw new ArgumentNullException(nameof(settings));
        }

        if (settings.MaxEndpoints < 0) {
            AnsiConsole.MarkupLine("[red]--max-endpoints must be 0 or greater.[/]");
            return Task.FromResult(1);
        }

        if (!CertificateInventoryDriftAnalyzer.TryNormalizeSeverity(settings.MinimumSeverity, out var minimumSeverity)) {
            AnsiConsole.MarkupLine("[red]--minimum-severity must be one of: none, low, medium, high.[/]");
            return Task.FromResult(1);
        }

        var cacheDirectory = ResolveCacheDirectory(settings.CacheDirectory);
        var monitor = new CertificateMonitor {
            CacheDirectory = cacheDirectory,
            PersistInventorySnapshots = false
        };

        var sinceUtc = ToUtc(settings.SinceUtc);
        var drift = monitor.BuildInventoryDrift(
            sinceUtc: sinceUtc,
            changedOnly: settings.ChangedOnly,
            maxEndpoints: settings.MaxEndpoints,
            minimumSeverity: minimumSeverity);

        if (settings.Json) {
            var json = JsonSerializer.Serialize(drift, JsonOptions.Default);
            Console.WriteLine(json);
            return Task.FromResult(0);
        }

        if (drift.SnapshotCount == 0) {
            AnsiConsole.MarkupLine($"[yellow]No inventory snapshots found in:[/] {cacheDirectory}");
            return Task.FromResult(0);
        }

        var summary = new Table().Border(TableBorder.Rounded);
        summary.AddColumn("Metric");
        summary.AddColumn("Value");
        summary.AddRow("Snapshots", drift.SnapshotCount.ToString());
        summary.AddRow("Endpoints (Total)", drift.EndpointCount.ToString());
        summary.AddRow("Endpoints Matching Filters", drift.FilteredEndpointCount.ToString());
        summary.AddRow("Returned Endpoints", drift.Endpoints.Count.ToString());
        summary.AddRow("Minimum Severity", minimumSeverity ?? "None");
        summary.AddRow("Any Change", drift.EndpointsWithAnyChange.ToString());
        summary.AddRow("High Severity", drift.EndpointsWithHighSeverityDrift.ToString());
        summary.AddRow("Medium Severity", drift.EndpointsWithMediumSeverityDrift.ToString());
        summary.AddRow("Low Severity", drift.EndpointsWithLowSeverityDrift.ToString());
        summary.AddRow("Certificate Change", drift.EndpointsWithCertificateChange.ToString());
        summary.AddRow("Issuer Change", drift.EndpointsWithIssuerChange.ToString());
        summary.AddRow("Expiry Change", drift.EndpointsWithExpiryChange.ToString());
        summary.AddRow("Service Change", drift.EndpointsWithServiceChange.ToString());
        summary.AddRow("Auth Profile Change", drift.EndpointsWithAuthenticationProfileChange.ToString());
        summary.AddRow("Chain Source Change", drift.EndpointsWithChainSourceChange.ToString());
        AnsiConsole.Write(summary);

        if (drift.Endpoints.Count == 0) {
            AnsiConsole.MarkupLine("[yellow]No endpoint drift rows to display.[/]");
            return Task.FromResult(0);
        }

        var rows = new Table().Border(TableBorder.Rounded);
        rows.Title = new TableTitle("Certificate Drift");
        rows.AddColumn("Host");
        rows.AddColumn("Port");
        rows.AddColumn("Obs");
        rows.AddColumn("Distinct Certs");
        rows.AddColumn("Severity");
        rows.AddColumn("Changes");
        rows.AddColumn("Changed");
        rows.AddColumn("Last Change");
        rows.AddColumn("Current Issuer");
        rows.AddColumn("Current Expiry");
        rows.AddColumn("Auth Profile");
        rows.AddColumn("Chain Source");
        foreach (var endpoint in drift.Endpoints
                     .OrderByDescending(x => x.LastChangedAtUtc ?? DateTimeOffset.MinValue)
                     .ThenBy(x => x.Host, StringComparer.OrdinalIgnoreCase)) {
            var changed = BuildChangedFlags(endpoint);
            var lastChange = endpoint.LastChangedAtUtc?.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss") ?? "-";
            var expiry = endpoint.CurrentNotAfterUtc?.UtcDateTime.ToString("yyyy-MM-dd") ?? "-";
            rows.AddRow(
                endpoint.Host,
                endpoint.Port.ToString(),
                endpoint.ObservationCount.ToString(),
                endpoint.DistinctCertificateCount.ToString(),
                endpoint.DriftSeverity,
                BuildChangeKinds(endpoint),
                changed,
                lastChange,
                string.IsNullOrWhiteSpace(endpoint.CurrentIssuer) ? "-" : endpoint.CurrentIssuer!,
                expiry,
                string.IsNullOrWhiteSpace(endpoint.CurrentAuthenticationProfile) ? "-" : endpoint.CurrentAuthenticationProfile!,
                NormalizeChainSource(endpoint.CurrentChainSource));
        }
        AnsiConsole.Write(rows);
        AnsiConsole.MarkupLine("[grey]Flags: C=Certificate, I=Issuer, E=Expiry, S=Service, A=AuthProfile, H=ChainSource[/]");

        return Task.FromResult(0);
    }

    private static string BuildChangedFlags(CertificateInventoryEndpointDrift endpoint) {
        var flags = string.Empty;
        if (endpoint.CertificateChanged) {
            flags += "C";
        }
        if (endpoint.IssuerChanged) {
            flags += "I";
        }
        if (endpoint.ExpiryChanged) {
            flags += "E";
        }
        if (endpoint.ServiceChanged) {
            flags += "S";
        }
        if (endpoint.AuthenticationProfileChanged) {
            flags += "A";
        }
        if (endpoint.ChainSourceChanged) {
            flags += "H";
        }

        return flags.Length == 0 ? "-" : flags;
    }

    private static string BuildChangeKinds(CertificateInventoryEndpointDrift endpoint) {
        if (endpoint.ChangeKinds == null || endpoint.ChangeKinds.Count == 0) {
            return "-";
        }

        return string.Join(", ", endpoint.ChangeKinds);
    }

    private static string NormalizeChainSource(string? source) {
        if (string.IsNullOrWhiteSpace(source)) {
            return "-";
        }

        if (source.Equals("unknown", StringComparison.OrdinalIgnoreCase)) {
            return "-";
        }

        return source;
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
