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

    /// <summary>Optional CSV output path for endpoint policy rows.</summary>
    [Description("Optional CSV output path for endpoint policy rows.")]
    [CommandOption("--csv-path <PATH>")]
    public string? CsvPath { get; set; }

    /// <summary>Optional JSON file path with policy override rules.</summary>
    [Description("Optional JSON file path with policy override rules.")]
    [CommandOption("--policy-overrides-path <PATH>")]
    public string? PolicyOverridesPath { get; set; }
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

        var policy = monitor.BuildInventoryPolicy(
            sinceUtc: ToUtc(settings.SinceUtc),
            baselineProfile: normalizedProfile,
            includeCompliant: settings.IncludeCompliant,
            maxEndpoints: settings.MaxEndpoints,
            policyOverrides: policyOverrides);

        if (!string.IsNullOrWhiteSpace(settings.CsvPath)) {
            try {
                WriteCsv(policy, settings.CsvPath!);
                AnsiConsole.MarkupLine($"[grey]CSV written:[/] {settings.CsvPath}");
            } catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]Failed to write CSV:[/] {ex.Message}");
                return Task.FromResult(1);
            }
        }

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

    private static void WriteCsv(CertificateInventoryPolicySummary policy, string path) {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory)) {
            Directory.CreateDirectory(directory);
        }

        var sb = new StringBuilder();
        sb.AppendLine("Host,Port,Service,Compliant,EffectiveBaselineProfile,ViolationCount,MaxViolationSeverity,RiskScore,RiskSeverity,Issuer,RootIssuer,NotBeforeUtc,NotAfterUtc,DaysUntilValid,DaysToExpire,AuthenticationProfile,CertificateReuseEndpointCount,CertificateReuseDistinctServiceCount,CertificateReuseDistinctPortCount,SuppressedViolationCodes,AppliedPolicyOverrideRules,ViolationCodes,ViolationSeverities,ViolationMessages,RiskReasons");

        foreach (var endpoint in policy.Endpoints) {
            var violationCodes = endpoint.Violations.Count == 0
                ? string.Empty
                : string.Join("|", endpoint.Violations.Select(violation => violation.Code));
            var violationSeverities = endpoint.Violations.Count == 0
                ? string.Empty
                : string.Join("|", endpoint.Violations.Select(violation => violation.Severity));
            var violationMessages = endpoint.Violations.Count == 0
                ? string.Empty
                : string.Join("|", endpoint.Violations.Select(violation => violation.Message));
            var riskReasons = endpoint.RiskReasons.Count == 0
                ? string.Empty
                : string.Join("|", endpoint.RiskReasons);
            var suppressedViolationCodes = endpoint.SuppressedViolationCodes.Count == 0
                ? string.Empty
                : string.Join("|", endpoint.SuppressedViolationCodes);
            var appliedOverrideRules = endpoint.AppliedPolicyOverrideRules.Count == 0
                ? string.Empty
                : string.Join("|", endpoint.AppliedPolicyOverrideRules);

            sb.Append(EscapeCsv(endpoint.Host));
            sb.Append(',');
            sb.Append(endpoint.Port);
            sb.Append(',');
            sb.Append(EscapeCsv(endpoint.Service));
            sb.Append(',');
            sb.Append(endpoint.Compliant ? "true" : "false");
            sb.Append(',');
            sb.Append(EscapeCsv(endpoint.EffectiveBaselineProfile));
            sb.Append(',');
            sb.Append(endpoint.ViolationCount);
            sb.Append(',');
            sb.Append(EscapeCsv(endpoint.MaxViolationSeverity));
            sb.Append(',');
            sb.Append(endpoint.RiskScore);
            sb.Append(',');
            sb.Append(EscapeCsv(endpoint.RiskSeverity));
            sb.Append(',');
            sb.Append(EscapeCsv(endpoint.Issuer));
            sb.Append(',');
            sb.Append(EscapeCsv(endpoint.RootIssuer));
            sb.Append(',');
            sb.Append(EscapeCsv(endpoint.NotBeforeUtc?.UtcDateTime.ToString("O") ?? string.Empty));
            sb.Append(',');
            sb.Append(EscapeCsv(endpoint.NotAfterUtc?.UtcDateTime.ToString("O") ?? string.Empty));
            sb.Append(',');
            sb.Append(EscapeCsv(endpoint.DaysUntilValid?.ToString() ?? string.Empty));
            sb.Append(',');
            sb.Append(EscapeCsv(endpoint.DaysToExpire?.ToString() ?? string.Empty));
            sb.Append(',');
            sb.Append(EscapeCsv(endpoint.AuthenticationProfile));
            sb.Append(',');
            sb.Append(endpoint.CertificateReuseEndpointCount);
            sb.Append(',');
            sb.Append(endpoint.CertificateReuseDistinctServiceCount);
            sb.Append(',');
            sb.Append(endpoint.CertificateReuseDistinctPortCount);
            sb.Append(',');
            sb.Append(EscapeCsv(suppressedViolationCodes));
            sb.Append(',');
            sb.Append(EscapeCsv(appliedOverrideRules));
            sb.Append(',');
            sb.Append(EscapeCsv(violationCodes));
            sb.Append(',');
            sb.Append(EscapeCsv(violationSeverities));
            sb.Append(',');
            sb.Append(EscapeCsv(violationMessages));
            sb.Append(',');
            sb.Append(EscapeCsv(riskReasons));
            sb.AppendLine();
        }

        File.WriteAllText(fullPath, sb.ToString(), Encoding.UTF8);
    }

    private static string EscapeCsv(string? value) {
        var text = value ?? string.Empty;
        if (text.IndexOfAny(new[] { ',', '"', '\r', '\n' }) >= 0) {
            return "\"" + text.Replace("\"", "\"\"") + "\"";
        }

        return text;
    }
}
