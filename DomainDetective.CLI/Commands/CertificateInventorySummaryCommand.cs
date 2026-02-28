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

    /// <summary>Optional CSV output path for summary metrics, distributions, and expiring endpoints.</summary>
    [Description("Optional CSV output path for summary metrics, distributions, and expiring endpoints.")]
    [CommandOption("--csv-path <PATH>")]
    public string? CsvPath { get; set; }

    /// <summary>Optional NDJSON output path for summary metrics and rows (one JSON object per line).</summary>
    [Description("Optional NDJSON output path for summary metrics and rows (one JSON object per line).")]
    [CommandOption("--ndjson-path <PATH>")]
    public string? NdjsonPath { get; set; }
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

        var cacheDirectory = CertificateInventoryCommandHelpers.ResolveCacheDirectory(settings.CacheDirectory);
        var monitor = new CertificateMonitor {
            CacheDirectory = cacheDirectory,
            PersistInventorySnapshots = false
        };

        var sinceUtc = CertificateInventoryCommandHelpers.ToUtc(settings.SinceUtc);
        var summary = monitor.BuildInventorySummary(sinceUtc, settings.ExpiringWithinDays, settings.MaxExpiring);

        if (!string.IsNullOrWhiteSpace(settings.CsvPath)) {
            try {
                WriteCsv(summary, settings.CsvPath!);
                AnsiConsole.MarkupLine($"[grey]CSV written:[/] {settings.CsvPath}");
            } catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]Failed to write CSV:[/] {ex.Message}");
                return Task.FromResult(1);
            }
        }

        if (!string.IsNullOrWhiteSpace(settings.NdjsonPath)) {
            try {
                WriteNdjson(summary, settings.NdjsonPath!);
                AnsiConsole.MarkupLine($"[grey]NDJSON written:[/] {settings.NdjsonPath}");
            } catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]Failed to write NDJSON:[/] {ex.Message}");
                return Task.FromResult(1);
            }
        }

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
        RenderCountTable("Authentication Profiles", summary.AuthenticationProfileCounts);
        RenderCountTable("Chain Sources", summary.ChainSourceCounts);
        RenderCountTable("CT Sources", summary.CtSourceCounts);
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

    private static void WriteCsv(CertificateInventorySummary summary, string path) {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory)) {
            Directory.CreateDirectory(directory);
        }

        var sb = new StringBuilder();
        sb.AppendLine("RowType,Category,Name,Count,Host,Port,Service,NotAfterUtc,DaysToExpire,Issuer,SnapshotCount,SampleCount,UniqueEndpointCount,ExpiredEndpointCount,ExpiringSoonEndpointCount,MissingServerAuthEndpointCount,ClientAuthEndpointCount,SecureEmailEndpointCount,SelfSignedEndpointCount,IncompleteChainEndpointCount,CtTemplateErrorEndpointCount");

        var summaryRow = NewCsvRow();
        summaryRow[0] = "Summary";
        summaryRow[10] = summary.SnapshotCount.ToString();
        summaryRow[11] = summary.SampleCount.ToString();
        summaryRow[12] = summary.UniqueEndpointCount.ToString();
        summaryRow[13] = summary.ExpiredEndpointCount.ToString();
        summaryRow[14] = summary.ExpiringSoonEndpointCount.ToString();
        summaryRow[15] = summary.MissingServerAuthEndpointCount.ToString();
        summaryRow[16] = summary.ClientAuthEndpointCount.ToString();
        summaryRow[17] = summary.SecureEmailEndpointCount.ToString();
        summaryRow[18] = summary.SelfSignedEndpointCount.ToString();
        summaryRow[19] = summary.IncompleteChainEndpointCount.ToString();
        summaryRow[20] = summary.CtTemplateErrorEndpointCount.ToString();
        AppendCsvRow(sb, summaryRow);

        AppendCounterRows(sb, "Service", summary.ServiceCounts);
        AppendCounterRows(sb, "Issuer", summary.IssuerCounts);
        AppendCounterRows(sb, "RootIssuer", summary.RootIssuerCounts);
        AppendCounterRows(sb, "AuthenticationProfile", summary.AuthenticationProfileCounts);
        AppendCounterRows(sb, "ChainSource", summary.ChainSourceCounts);
        AppendCounterRows(sb, "CtSource", summary.CtSourceCounts);
        AppendCounterRows(sb, "CtTemplateErrorCategory", summary.CtTemplateErrorCounts);

        foreach (var endpoint in summary.ExpiringSoon) {
            var endpointRow = NewCsvRow();
            endpointRow[0] = "ExpiringEndpoint";
            endpointRow[1] = "ExpiringSoon";
            endpointRow[4] = endpoint.Host;
            endpointRow[5] = endpoint.Port.ToString();
            endpointRow[6] = endpoint.Service;
            endpointRow[7] = endpoint.NotAfterUtc?.UtcDateTime.ToString("O") ?? string.Empty;
            endpointRow[8] = endpoint.DaysToExpire.ToString();
            endpointRow[9] = endpoint.Issuer;
            AppendCsvRow(sb, endpointRow);
        }

        CertificateInventoryCommandHelpers.WriteUtf8Text(fullPath, sb.ToString());
    }

    private static void WriteNdjson(CertificateInventorySummary summary, string path) {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory)) {
            Directory.CreateDirectory(directory);
        }

        var sb = new StringBuilder();
        sb.AppendLine(CertificateInventoryCommandHelpers.SerializeJsonLine(new {
            RowType = "Summary",
            summary.SnapshotCount,
            summary.SampleCount,
            summary.UniqueEndpointCount,
            summary.ExpiredEndpointCount,
            summary.ExpiringSoonEndpointCount,
            summary.MissingServerAuthEndpointCount,
            summary.ClientAuthEndpointCount,
            summary.SecureEmailEndpointCount,
            summary.SelfSignedEndpointCount,
            summary.IncompleteChainEndpointCount,
            summary.CtTemplateErrorEndpointCount
        }));

        AppendCounterNdjson(sb, "Service", summary.ServiceCounts);
        AppendCounterNdjson(sb, "Issuer", summary.IssuerCounts);
        AppendCounterNdjson(sb, "RootIssuer", summary.RootIssuerCounts);
        AppendCounterNdjson(sb, "AuthenticationProfile", summary.AuthenticationProfileCounts);
        AppendCounterNdjson(sb, "ChainSource", summary.ChainSourceCounts);
        AppendCounterNdjson(sb, "CtSource", summary.CtSourceCounts);
        AppendCounterNdjson(sb, "CtTemplateErrorCategory", summary.CtTemplateErrorCounts);

        foreach (var endpoint in summary.ExpiringSoon) {
            sb.AppendLine(CertificateInventoryCommandHelpers.SerializeJsonLine(new {
                RowType = "ExpiringEndpoint",
                endpoint.Host,
                endpoint.Port,
                endpoint.Service,
                endpoint.NotAfterUtc,
                endpoint.DaysToExpire,
                endpoint.Issuer
            }));
        }

        CertificateInventoryCommandHelpers.WriteUtf8Text(fullPath, sb.ToString());
    }

    private static void AppendCounterRows(StringBuilder sb, string category, System.Collections.Generic.Dictionary<string, int> counters) {
        foreach (var kv in counters.OrderByDescending(x => x.Value).ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase)) {
            var counterRow = NewCsvRow();
            counterRow[0] = "Counter";
            counterRow[1] = category;
            counterRow[2] = kv.Key;
            counterRow[3] = kv.Value.ToString();
            AppendCsvRow(sb, counterRow);
        }
    }

    private static void AppendCounterNdjson(StringBuilder sb, string category, System.Collections.Generic.Dictionary<string, int> counters) {
        foreach (var kv in counters.OrderByDescending(x => x.Value).ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase)) {
            sb.AppendLine(CertificateInventoryCommandHelpers.SerializeJsonLine(new {
                RowType = "Counter",
                Category = category,
                Name = kv.Key,
                Count = kv.Value
            }));
        }
    }

    private static string[] NewCsvRow() {
        return new string[21];
    }

    private static void AppendCsvRow(StringBuilder sb, string[] columns) {
        if (columns.Length != 21) {
            throw new ArgumentException("CSV row must have 21 columns.", nameof(columns));
        }

        for (var i = 0; i < columns.Length; i++) {
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(columns[i]));
            if (i < columns.Length - 1) {
                sb.Append(',');
            }
        }

        sb.AppendLine();
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

}

