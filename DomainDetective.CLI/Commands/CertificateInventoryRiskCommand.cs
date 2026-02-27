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
/// Settings for <see cref="CertificateInventoryRiskCommand"/>.
/// </summary>
internal sealed class CertificateInventoryRiskSettings : CommandSettings {
    /// <summary>Certificate monitor cache directory (defaults to system temp path).</summary>
    [Description("Certificate monitor cache directory (defaults to system temp path).")]
    [CommandOption("--cache-dir <PATH>")]
    public string? CacheDirectory { get; set; }

    /// <summary>Only include snapshots captured since this UTC timestamp.</summary>
    [Description("Only include snapshots captured since this UTC timestamp.")]
    [CommandOption("--since-utc <UTC>")]
    public DateTime? SinceUtc { get; set; }

    /// <summary>Warning threshold window in days for expiring certificates.</summary>
    [Description("Warning threshold window in days for expiring certificates.")]
    [CommandOption("--expiring-within-days <DAYS>")]
    [DefaultValue(30)]
    public int ExpiringWithinDays { get; set; } = 30;

    /// <summary>Critical threshold window in days for expiring certificates.</summary>
    [Description("Critical threshold window in days for expiring certificates.")]
    [CommandOption("--critical-expiring-within-days <DAYS>")]
    [DefaultValue(7)]
    public int CriticalExpiringWithinDays { get; set; } = 7;

    /// <summary>Include endpoints with no detected risk findings.</summary>
    [Description("Include endpoints with no detected risk findings.")]
    [CommandOption("--include-healthy")]
    public bool IncludeHealthy { get; set; }

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
/// Displays endpoint-level certificate risk posture from persisted inventory snapshots.
/// </summary>
internal sealed class CertificateInventoryRiskCommand : AsyncCommand<CertificateInventoryRiskSettings> {
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    public override Task<int> ExecuteAsync(CommandContext context, CertificateInventoryRiskSettings settings) {
        if (settings == null) {
            throw new ArgumentNullException(nameof(settings));
        }

        if (settings.MaxEndpoints < 0) {
            AnsiConsole.MarkupLine("[red]--max-endpoints must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ExpiringWithinDays < 0) {
            AnsiConsole.MarkupLine("[red]--expiring-within-days must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.CriticalExpiringWithinDays < 0) {
            AnsiConsole.MarkupLine("[red]--critical-expiring-within-days must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.CriticalExpiringWithinDays > settings.ExpiringWithinDays) {
            AnsiConsole.MarkupLine("[red]--critical-expiring-within-days cannot be greater than --expiring-within-days.[/]");
            return Task.FromResult(1);
        }

        var cacheDirectory = ResolveCacheDirectory(settings.CacheDirectory);
        var monitor = new CertificateMonitor {
            CacheDirectory = cacheDirectory,
            PersistInventorySnapshots = false
        };

        var risk = monitor.BuildInventoryRisk(
            sinceUtc: ToUtc(settings.SinceUtc),
            includeNoRisk: settings.IncludeHealthy,
            expiringWithinDays: settings.ExpiringWithinDays,
            criticalExpiringWithinDays: settings.CriticalExpiringWithinDays,
            maxEndpoints: settings.MaxEndpoints);

        if (settings.Json) {
            Console.WriteLine(JsonSerializer.Serialize(risk, JsonOptions.Default));
            return Task.FromResult(0);
        }

        if (risk.SnapshotCount == 0) {
            AnsiConsole.MarkupLine($"[yellow]No inventory snapshots found in:[/] {cacheDirectory}");
            return Task.FromResult(0);
        }

        var summary = new Table().Border(TableBorder.Rounded);
        summary.AddColumn("Metric");
        summary.AddColumn("Value");
        summary.AddRow("Snapshots", risk.SnapshotCount.ToString());
        summary.AddRow("Endpoints (Total)", risk.EndpointCount.ToString());
        summary.AddRow("Returned Endpoints", risk.Endpoints.Count.ToString());
        summary.AddRow("Critical", risk.CriticalCount.ToString());
        summary.AddRow("High", risk.HighCount.ToString());
        summary.AddRow("Medium", risk.MediumCount.ToString());
        summary.AddRow("Low", risk.LowCount.ToString());
        summary.AddRow("No Risk", risk.NoRiskCount.ToString());
        summary.AddRow("Average Score", risk.AverageScore.ToString("0.00"));
        AnsiConsole.Write(summary);

        if (risk.ReasonCounts.Count > 0) {
            var reasons = new Table().Border(TableBorder.Rounded);
            reasons.Title = new TableTitle("Top Risk Reasons");
            reasons.AddColumn("Reason");
            reasons.AddColumn("Count");
            foreach (var reason in risk.ReasonCounts
                         .OrderByDescending(x => x.Value)
                         .ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
                         .Take(20)) {
                reasons.AddRow(reason.Key, reason.Value.ToString());
            }
            AnsiConsole.Write(reasons);
        }

        if (risk.Endpoints.Count == 0) {
            AnsiConsole.MarkupLine("[yellow]No endpoint risk rows to display.[/]");
            return Task.FromResult(0);
        }

        var rows = new Table().Border(TableBorder.Rounded);
        rows.Title = new TableTitle("Certificate Risk Posture");
        rows.AddColumn("Host");
        rows.AddColumn("Port");
        rows.AddColumn("Service");
        rows.AddColumn("Score");
        rows.AddColumn("Severity");
        rows.AddColumn("Valid From");
        rows.AddColumn("Expiry");
        rows.AddColumn("Auth");
        rows.AddColumn("Issuer");
        rows.AddColumn("Reasons");
        foreach (var endpoint in risk.Endpoints) {
            var validFrom = endpoint.NotBeforeUtc?.UtcDateTime.ToString("yyyy-MM-dd") ?? "-";
            if (endpoint.DaysUntilValid.HasValue && endpoint.DaysUntilValid.Value > 0) {
                validFrom = $"{validFrom} (in {endpoint.DaysUntilValid.Value}d)";
            }

            var expiry = endpoint.NotAfterUtc?.UtcDateTime.ToString("yyyy-MM-dd") ?? "-";
            if (endpoint.DaysToExpire.HasValue) {
                expiry = $"{expiry} ({endpoint.DaysToExpire.Value}d)";
            }

            var auth = BuildAuthSummary(endpoint);
            var reasons = endpoint.Reasons.Count > 0 ? string.Join(",", endpoint.Reasons) : "-";
            rows.AddRow(
                endpoint.Host,
                endpoint.Port.ToString(),
                endpoint.Service,
                endpoint.Score.ToString(),
                endpoint.Severity,
                validFrom,
                expiry,
                auth,
                endpoint.Issuer,
                reasons);
        }
        AnsiConsole.Write(rows);
        AnsiConsole.MarkupLine("[grey]Auth flags: S=ServerAuth, C=ClientAuth, E=SecureEmail.[/]");

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

    private static string BuildAuthSummary(CertificateInventoryEndpointRisk endpoint) {
        var flags = string.Empty;
        if (endpoint.AllowsServerAuthentication) {
            flags += "S";
        }
        if (endpoint.AllowsClientAuthentication) {
            flags += "C";
        }
        if (endpoint.AllowsSecureEmail) {
            flags += "E";
        }

        if (flags.Length == 0) {
            flags = "-";
        }

        if (string.IsNullOrWhiteSpace(endpoint.AuthenticationProfile)) {
            return flags;
        }

        return $"{flags} ({endpoint.AuthenticationProfile})";
    }
}
