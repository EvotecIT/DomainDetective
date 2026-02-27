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
/// Settings for <see cref="CertificateInventorySummaryCommand"/>.
/// </summary>
internal sealed class CertificateInventorySummarySettings : CommandSettings {
    /// <summary>Certificate monitor cache directory (defaults to system temp path).</summary>
    [Description("Certificate monitor cache directory (defaults to system temp path).")]
    [CommandOption("--cache-dir <PATH>")]
    public string? CacheDirectory { get; set; }

    /// <summary>Only include snapshots captured since this UTC timestamp.</summary>
    [Description("Only include snapshots captured since this UTC timestamp.")]
    [CommandOption("--since-utc <UTC>")]
    public DateTime? SinceUtc { get; set; }

    /// <summary>Window in days for \"expiring soon\" calculations.</summary>
    [Description("Window in days for \"expiring soon\" calculations.")]
    [CommandOption("--expiring-within-days <DAYS>")]
    [DefaultValue(30)]
    public int ExpiringWithinDays { get; set; } = 30;

    /// <summary>Maximum expiring endpoints to include in output.</summary>
    [Description("Maximum expiring endpoints to include in output.")]
    [CommandOption("--max-expiring <N>")]
    [DefaultValue(20)]
    public int MaxExpiring { get; set; } = 20;

    /// <summary>Output JSON instead of tables.</summary>
    [Description("Output JSON instead of tables.")]
    [CommandOption("--json")]
    public bool Json { get; set; }
}

/// <summary>
/// Displays aggregate insights from persisted certificate inventory snapshots.
/// </summary>
internal sealed class CertificateInventorySummaryCommand : AsyncCommand<CertificateInventorySummarySettings> {
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    public override Task<int> ExecuteAsync(CommandContext context, CertificateInventorySummarySettings settings) {
        if (settings == null) {
            throw new ArgumentNullException(nameof(settings));
        }

        if (settings.ExpiringWithinDays < 0) {
            AnsiConsole.MarkupLine("[red]--expiring-within-days must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.MaxExpiring < 0) {
            AnsiConsole.MarkupLine("[red]--max-expiring must be 0 or greater.[/]");
            return Task.FromResult(1);
        }

        var cacheDirectory = ResolveCacheDirectory(settings.CacheDirectory);
        var monitor = new CertificateMonitor {
            CacheDirectory = cacheDirectory,
            PersistInventorySnapshots = false
        };

        var sinceUtc = ToUtc(settings.SinceUtc);
        var summary = monitor.BuildInventorySummary(sinceUtc, settings.ExpiringWithinDays, settings.MaxExpiring);

        if (settings.Json) {
            var json = JsonSerializer.Serialize(summary, JsonOptions.Default);
            Console.WriteLine(json);
            return Task.FromResult(0);
        }

        if (summary.SnapshotCount == 0) {
            AnsiConsole.MarkupLine($"[yellow]No inventory snapshots found in:[/] {cacheDirectory}");
            return Task.FromResult(0);
        }

        var overview = new Table().Border(TableBorder.Rounded);
        overview.AddColumn("Metric");
        overview.AddColumn("Value");
        overview.AddRow("Snapshots", summary.SnapshotCount.ToString());
        overview.AddRow("Samples", summary.SampleCount.ToString());
        overview.AddRow("Unique Endpoints", summary.UniqueEndpointCount.ToString());
        overview.AddRow("Expired Endpoints", summary.ExpiredEndpointCount.ToString());
        overview.AddRow($"Expiring <= {settings.ExpiringWithinDays}d", summary.ExpiringSoonEndpointCount.ToString());
        overview.AddRow("Missing ServerAuth EKU", summary.MissingServerAuthEndpointCount.ToString());
        overview.AddRow("ClientAuth EKU", summary.ClientAuthEndpointCount.ToString());
        overview.AddRow("SecureEmail EKU", summary.SecureEmailEndpointCount.ToString());
        overview.AddRow("Self-Signed", summary.SelfSignedEndpointCount.ToString());
        overview.AddRow("Incomplete Chains", summary.IncompleteChainEndpointCount.ToString());
        overview.AddRow("CT Template Errors", summary.CtTemplateErrorEndpointCount.ToString());
        AnsiConsole.Write(overview);

        RenderCountTable("Service Distribution", summary.ServiceCounts);
        RenderCountTable("Issuer Distribution", summary.IssuerCounts);
        RenderCountTable("Root Distribution", summary.RootIssuerCounts);
        RenderCountTable("CT Template Error Categories", summary.CtTemplateErrorCounts);

        if (summary.ExpiringSoon.Count > 0) {
            var expiring = new Table().Border(TableBorder.Rounded);
            expiring.Title = new TableTitle("Expiring Endpoints");
            expiring.AddColumn("Host");
            expiring.AddColumn("Port");
            expiring.AddColumn("Service");
            expiring.AddColumn("Expires");
            expiring.AddColumn("Days");
            expiring.AddColumn("Issuer");
            foreach (var item in summary.ExpiringSoon) {
                var expires = item.NotAfterUtc?.UtcDateTime.ToString("yyyy-MM-dd") ?? "-";
                expiring.AddRow(
                    item.Host,
                    item.Port.ToString(),
                    item.Service,
                    expires,
                    item.DaysToExpire.ToString(),
                    item.Issuer);
            }
            AnsiConsole.Write(expiring);
        }

        return Task.FromResult(0);
    }

    private static void RenderCountTable(string title, System.Collections.Generic.Dictionary<string, int> counters) {
        var table = new Table().Border(TableBorder.Rounded);
        table.Title = new TableTitle(title);
        table.AddColumn("Name");
        table.AddColumn("Count");
        foreach (var kv in counters.OrderByDescending(x => x.Value).ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase).Take(20)) {
            table.AddRow(kv.Key, kv.Value.ToString());
        }
        AnsiConsole.Write(table);
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
