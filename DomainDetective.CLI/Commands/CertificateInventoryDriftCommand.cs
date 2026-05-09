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

    /// <summary>Optional drift change-kind filter (repeat option to include multiple kinds).</summary>
    [Description("Optional drift change-kind filter (certificate, issuer, expiry, service, auth-profile, chain-source). Repeat option to include multiple kinds.")]
    [CommandOption("--change-kind <KIND>")]
    public string[]? ChangeKinds { get; set; }

    /// <summary>Optional change-kind matching mode (any or all).</summary>
    [Description("Optional change-kind matching mode (any or all).")]
    [CommandOption("--change-kind-match <MODE>")]
    public string? ChangeKindMatchMode { get; set; }

    /// <summary>Output JSON instead of tables.</summary>
    [Description("Output JSON instead of tables.")]
    [CommandOption("--json")]
    public bool Json { get; set; }

    /// <summary>Optional CSV output path for endpoint drift rows.</summary>
    [Description("Optional CSV output path for endpoint drift rows.")]
    [CommandOption("--csv-path <PATH>")]
    public string? CsvPath { get; set; }

    /// <summary>Optional NDJSON output path for endpoint drift rows (one JSON object per line).</summary>
    [Description("Optional NDJSON output path for endpoint drift rows (one JSON object per line).")]
    [CommandOption("--ndjson-path <PATH>")]
    public string? NdjsonPath { get; set; }
}

/// <summary>
/// Displays endpoint-level certificate drift from persisted inventory snapshots.
/// </summary>
internal sealed class CertificateInventoryDriftCommand : AsyncCommand<CertificateInventoryDriftSettings> {
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    protected override Task<int> ExecuteAsync(CommandContext context, CertificateInventoryDriftSettings settings, CancellationToken cancellationToken) {
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

        if (!CertificateInventoryDriftAnalyzer.TryNormalizeChangeKindMatchMode(settings.ChangeKindMatchMode, out var changeKindMatchMode)) {
            AnsiConsole.MarkupLine("[red]--change-kind-match must be one of: any, all.[/]");
            return Task.FromResult(1);
        }

        var normalizedChangeKinds = new List<string>();
        var dedupeChangeKinds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rawChangeKind in settings.ChangeKinds ?? Array.Empty<string>()) {
            if (!CertificateInventoryDriftAnalyzer.TryNormalizeChangeKind(rawChangeKind, out var normalizedChangeKind) || string.IsNullOrWhiteSpace(normalizedChangeKind)) {
                AnsiConsole.MarkupLine("[red]--change-kind must be one of: certificate, issuer, expiry, service, auth-profile, chain-source.[/]");
                return Task.FromResult(1);
            }

            if (dedupeChangeKinds.Add(normalizedChangeKind)) {
                normalizedChangeKinds.Add(normalizedChangeKind);
            }
        }
        if (normalizedChangeKinds.Count == 0 && changeKindMatchMode.Equals("All", StringComparison.OrdinalIgnoreCase)) {
            AnsiConsole.MarkupLine("[yellow]--change-kind-match all has no effect without --change-kind.[/]");
        }

        var cacheDirectory = CertificateInventoryCommandHelpers.ResolveCacheDirectory(settings.CacheDirectory);
        var monitor = new CertificateMonitor {
            CacheDirectory = cacheDirectory,
            PersistInventorySnapshots = false
        };

        var sinceUtc = CertificateInventoryCommandHelpers.ToUtc(settings.SinceUtc);
        var drift = monitor.BuildInventoryDrift(
            sinceUtc: sinceUtc,
            changedOnly: settings.ChangedOnly,
            maxEndpoints: settings.MaxEndpoints,
            minimumSeverity: minimumSeverity,
            requiredChangeKinds: normalizedChangeKinds,
            changeKindMatchMode: changeKindMatchMode);

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
        summary.AddRow("Endpoints Matching Filters", drift.EndpointsMatchingFilters.ToString());
        if (drift.EndpointsExcludedByFilters > 0) {
            summary.AddRow("Excluded by Filters", drift.EndpointsExcludedByFilters.ToString());
            summary.AddRow("Excluded by ChangedOnly", drift.EndpointsExcludedByChangedOnly.ToString());
            summary.AddRow("Excluded by Severity", drift.EndpointsExcludedByMinimumSeverity.ToString());
            summary.AddRow("Excluded by Change Kind", drift.EndpointsExcludedByChangeKindFilter.ToString());
        }
        summary.AddRow("Returned Endpoints", drift.Endpoints.Count.ToString());
        if (drift.EndpointsTruncatedByMaxEndpoints > 0) {
            summary.AddRow("Truncated by Max Endpoints", drift.EndpointsTruncatedByMaxEndpoints.ToString());
        }
        summary.AddRow("Minimum Severity", minimumSeverity ?? "None");
        summary.AddRow("Change Kind Filter", drift.AppliedChangeKinds.Count == 0 ? "Any" : string.Join(", ", drift.AppliedChangeKinds));
        if (drift.AppliedChangeKinds.Count > 0) {
            summary.AddRow("Change Kind Match", drift.AppliedChangeKindMatchMode);
        }
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
        foreach (var endpoint in drift.Endpoints) {
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

    private static void WriteCsv(CertificateInventoryDriftSummary drift, string path) {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory)) {
            Directory.CreateDirectory(directory);
        }

        var sb = new StringBuilder();
        sb.AppendLine("Host,Port,Service,ObservationCount,DistinctCertificateCount,DriftSeverity,FirstSeenUtc,LastSeenUtc,LastChangedAtUtc,PreviousCertificateId,CurrentCertificateId,PreviousIssuer,CurrentIssuer,PreviousNotAfterUtc,CurrentNotAfterUtc,PreviousAuthenticationProfile,CurrentAuthenticationProfile,PreviousChainSource,CurrentChainSource,CertificateChanged,IssuerChanged,ExpiryChanged,ServiceChanged,AuthenticationProfileChanged,ChainSourceChanged,ChangeKinds");
        foreach (var endpoint in drift.Endpoints) {
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.Host));
            sb.Append(',');
            sb.Append(endpoint.Port);
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.Service));
            sb.Append(',');
            sb.Append(endpoint.ObservationCount);
            sb.Append(',');
            sb.Append(endpoint.DistinctCertificateCount);
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.DriftSeverity));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.FirstSeenUtc?.UtcDateTime.ToString("O") ?? string.Empty));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.LastSeenUtc?.UtcDateTime.ToString("O") ?? string.Empty));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.LastChangedAtUtc?.UtcDateTime.ToString("O") ?? string.Empty));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.PreviousCertificateId));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.CurrentCertificateId));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.PreviousIssuer));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.CurrentIssuer));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.PreviousNotAfterUtc?.UtcDateTime.ToString("O") ?? string.Empty));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.CurrentNotAfterUtc?.UtcDateTime.ToString("O") ?? string.Empty));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.PreviousAuthenticationProfile));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.CurrentAuthenticationProfile));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.PreviousChainSource));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(endpoint.CurrentChainSource));
            sb.Append(',');
            sb.Append(endpoint.CertificateChanged ? "true" : "false");
            sb.Append(',');
            sb.Append(endpoint.IssuerChanged ? "true" : "false");
            sb.Append(',');
            sb.Append(endpoint.ExpiryChanged ? "true" : "false");
            sb.Append(',');
            sb.Append(endpoint.ServiceChanged ? "true" : "false");
            sb.Append(',');
            sb.Append(endpoint.AuthenticationProfileChanged ? "true" : "false");
            sb.Append(',');
            sb.Append(endpoint.ChainSourceChanged ? "true" : "false");
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(string.Join("|", endpoint.ChangeKinds)));
            sb.AppendLine();
        }

        CertificateInventoryCommandHelpers.WriteUtf8Text(fullPath, sb.ToString());
    }

    private static void WriteNdjson(CertificateInventoryDriftSummary drift, string path) {
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

}

