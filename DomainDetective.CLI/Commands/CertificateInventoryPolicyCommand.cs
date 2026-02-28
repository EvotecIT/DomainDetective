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
/// Settings for <see cref="CertificateInventoryPolicyCommand"/>.
/// </summary>
internal sealed class CertificateInventoryPolicySettings : CommandSettings {
    /// <summary>Certificate monitor cache directory (defaults to system temp path).</summary>
    [Description("Certificate monitor cache directory (defaults to system temp path).")]
    [CommandOption("--cache-dir <PATH>")]
    public string? CacheDirectory { get; set; }

    /// <summary>Only include snapshots captured since this UTC timestamp.</summary>
    [Description("Only include snapshots captured since this UTC timestamp.")]
    [CommandOption("--since-utc <UTC>")]
    public DateTime? SinceUtc { get; set; }

    /// <summary>Baseline policy profile (Strict, Balanced, Legacy).</summary>
    [Description("Baseline policy profile (Strict, Balanced, Legacy).")]
    [CommandOption("--baseline-profile <NAME>")]
    [DefaultValue("Balanced")]
    public string BaselineProfile { get; set; } = "Balanced";

    /// <summary>Include endpoints with no policy violations.</summary>
    [Description("Include endpoints with no policy violations.")]
    [CommandOption("--include-compliant")]
    public bool IncludeCompliant { get; set; }

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
/// Evaluates persisted certificate inventory snapshots against a baseline policy profile.
/// </summary>
internal sealed class CertificateInventoryPolicyCommand : AsyncCommand<CertificateInventoryPolicySettings> {
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    public override Task<int> ExecuteAsync(CommandContext context, CertificateInventoryPolicySettings settings) {
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

        var policy = monitor.BuildInventoryPolicy(
            sinceUtc: ToUtc(settings.SinceUtc),
            baselineProfile: normalizedProfile,
            includeCompliant: settings.IncludeCompliant,
            maxEndpoints: settings.MaxEndpoints);

        if (settings.Json) {
            Console.WriteLine(JsonSerializer.Serialize(policy, JsonOptions.Default));
            return Task.FromResult(0);
        }

        if (policy.SnapshotCount == 0) {
            AnsiConsole.MarkupLine($"[yellow]No inventory snapshots found in:[/] {cacheDirectory}");
            return Task.FromResult(0);
        }

        var summary = new Table().Border(TableBorder.Rounded);
        summary.AddColumn("Metric");
        summary.AddColumn("Value");
        summary.AddRow("Baseline Profile", policy.BaselineProfile);
        summary.AddRow("Snapshots", policy.SnapshotCount.ToString());
        summary.AddRow("Endpoints (Total)", policy.EndpointCount.ToString());
        summary.AddRow("Violation Endpoints", policy.ViolationEndpointCount.ToString());
        summary.AddRow("Compliant Endpoints", policy.CompliantEndpointCount.ToString());
        summary.AddRow("Matched Endpoints", policy.MatchedEndpointCount.ToString());
        summary.AddRow("Returned Endpoints", policy.Endpoints.Count.ToString());
        summary.AddRow("Truncated Endpoints", policy.EndpointsTruncatedByMaxEndpoints.ToString());
        summary.AddRow("Total Violations", policy.TotalViolationCount.ToString());
        summary.AddRow("Critical Violations", policy.CriticalViolationCount.ToString());
        summary.AddRow("High Violations", policy.HighViolationCount.ToString());
        summary.AddRow("Medium Violations", policy.MediumViolationCount.ToString());
        summary.AddRow("Low Violations", policy.LowViolationCount.ToString());
        AnsiConsole.Write(summary);

        if (policy.ViolationCodeCounts.Count > 0) {
            var codes = new Table().Border(TableBorder.Rounded);
            codes.Title = new TableTitle("Top Violation Codes");
            codes.AddColumn("Code");
            codes.AddColumn("Count");
            foreach (var code in policy.ViolationCodeCounts
                         .OrderByDescending(x => x.Value)
                         .ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
                         .Take(20)) {
                codes.AddRow(code.Key, code.Value.ToString());
            }
            AnsiConsole.Write(codes);
        }

        if (policy.Endpoints.Count == 0) {
            AnsiConsole.MarkupLine("[yellow]No endpoint policy rows to display.[/]");
            return Task.FromResult(0);
        }

        if (policy.Truncated) {
            AnsiConsole.MarkupLine($"[yellow]Endpoint rows truncated by --max-endpoints:[/] {policy.EndpointsTruncatedByMaxEndpoints}");
        }

        var rows = new Table().Border(TableBorder.Rounded);
        rows.Title = new TableTitle("Certificate Policy Posture");
        rows.AddColumn("Host");
        rows.AddColumn("Port");
        rows.AddColumn("Service");
        rows.AddColumn("Status");
        rows.AddColumn("Policy Severity");
        rows.AddColumn("Violations");
        rows.AddColumn("Risk");
        rows.AddColumn("Issuer");
        rows.AddColumn("Codes");

        foreach (var endpoint in policy.Endpoints) {
            var status = endpoint.Compliant ? "Compliant" : "NonCompliant";
            var severity = endpoint.MaxViolationSeverity;
            var codes = endpoint.Violations.Count == 0
                ? "-"
                : string.Join(",", endpoint.Violations.Select(violation => violation.Code));
            var risk = $"{endpoint.RiskSeverity}/{endpoint.RiskScore}";

            rows.AddRow(
                endpoint.Host,
                endpoint.Port.ToString(),
                endpoint.Service,
                status,
                severity,
                endpoint.ViolationCount.ToString(),
                risk,
                endpoint.Issuer,
                codes);
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
