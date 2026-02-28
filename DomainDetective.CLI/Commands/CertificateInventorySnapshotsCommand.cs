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
/// Settings for <see cref="CertificateInventorySnapshotsCommand"/>.
/// </summary>
internal sealed class CertificateInventorySnapshotsSettings : CommandSettings {
    /// <summary>Certificate monitor cache directory (defaults to system temp path).</summary>
    [Description("Certificate monitor cache directory (defaults to system temp path).")]
    [CommandOption("--cache-dir <PATH>")]
    public string? CacheDirectory { get; set; }

    /// <summary>Only include snapshots captured since this UTC timestamp.</summary>
    [Description("Only include snapshots captured since this UTC timestamp.")]
    [CommandOption("--since-utc <UTC>")]
    public DateTime? SinceUtc { get; set; }

    /// <summary>Only include snapshots captured up to this UTC timestamp.</summary>
    [Description("Only include snapshots captured up to this UTC timestamp.")]
    [CommandOption("--until-utc <UTC>")]
    public DateTime? UntilUtc { get; set; }

    /// <summary>Maximum snapshot rows returned.</summary>
    [Description("Maximum snapshot rows returned.")]
    [CommandOption("--max-snapshots <N>")]
    [DefaultValue(200)]
    public int MaxSnapshots { get; set; } = 200;

    /// <summary>Output JSON instead of tables.</summary>
    [Description("Output JSON instead of tables.")]
    [CommandOption("--json")]
    public bool Json { get; set; }

    /// <summary>Optional CSV output path for snapshot catalog rows.</summary>
    [Description("Optional CSV output path for snapshot catalog rows.")]
    [CommandOption("--csv-path <PATH>")]
    public string? CsvPath { get; set; }

    /// <summary>Optional NDJSON output path for snapshot catalog rows (one JSON object per line).</summary>
    [Description("Optional NDJSON output path for snapshot catalog rows (one JSON object per line).")]
    [CommandOption("--ndjson-path <PATH>")]
    public string? NdjsonPath { get; set; }
}

/// <summary>
/// Lists persisted certificate inventory snapshots with high-level metrics.
/// </summary>
internal sealed class CertificateInventorySnapshotsCommand : AsyncCommand<CertificateInventorySnapshotsSettings> {
    private sealed class SnapshotCatalogResult {
        public DateTimeOffset? SinceUtc { get; set; }
        public DateTimeOffset? UntilUtc { get; set; }
        public int LoadedSnapshotCount { get; set; }
        public int ReturnedSnapshotCount { get; set; }
        public int ExcludedByUntilCount { get; set; }
        public List<SnapshotCatalogRow> Snapshots { get; set; } = new();
    }

    private sealed class SnapshotCatalogRow {
        public DateTimeOffset CapturedAtUtc { get; set; }
        public int Port { get; set; }
        public int EntryCount { get; set; }
        public int UniqueEndpointCount { get; set; }
        public int ValidEntryCount { get; set; }
        public int ExpiredEntryCount { get; set; }
        public int MissingServerAuthEntryCount { get; set; }
        public int ClientAuthEntryCount { get; set; }
        public int IncompleteChainEntryCount { get; set; }
        public int CtTemplateErrorEntryCount { get; set; }
    }

    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    public override Task<int> ExecuteAsync(CommandContext context, CertificateInventorySnapshotsSettings settings) {
        if (settings == null) {
            throw new ArgumentNullException(nameof(settings));
        }

        if (settings.MaxSnapshots < 0) {
            AnsiConsole.MarkupLine("[red]--max-snapshots must be 0 or greater.[/]");
            return Task.FromResult(1);
        }

        var sinceUtc = CertificateInventoryCommandHelpers.ToUtc(settings.SinceUtc);
        var untilUtc = CertificateInventoryCommandHelpers.ToUtc(settings.UntilUtc);
        if (sinceUtc.HasValue && untilUtc.HasValue && sinceUtc.Value > untilUtc.Value) {
            AnsiConsole.MarkupLine("[red]--since-utc must be less than or equal to --until-utc.[/]");
            return Task.FromResult(1);
        }

        var cacheDirectory = CertificateInventoryCommandHelpers.ResolveCacheDirectory(settings.CacheDirectory);
        var monitor = new CertificateMonitor {
            CacheDirectory = cacheDirectory,
            PersistInventorySnapshots = false
        };

        var loadedSnapshots = monitor.LoadInventorySnapshots(sinceUtc);
        var filteredByUntil = loadedSnapshots
            .Where(snapshot => !untilUtc.HasValue || snapshot.CapturedAtUtc <= untilUtc.Value)
            .ToList();

        var rows = filteredByUntil
            .OrderByDescending(snapshot => snapshot.CapturedAtUtc)
            .Take(settings.MaxSnapshots)
            .Select(BuildRow)
            .ToList();

        var result = new SnapshotCatalogResult {
            SinceUtc = sinceUtc,
            UntilUtc = untilUtc,
            LoadedSnapshotCount = loadedSnapshots.Count,
            ReturnedSnapshotCount = rows.Count,
            ExcludedByUntilCount = loadedSnapshots.Count - filteredByUntil.Count,
            Snapshots = rows
        };

        if (!string.IsNullOrWhiteSpace(settings.CsvPath)) {
            try {
                WriteCsv(result, settings.CsvPath!);
                AnsiConsole.MarkupLine($"[grey]CSV written:[/] {settings.CsvPath}");
            } catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]Failed to write CSV:[/] {ex.Message}");
                return Task.FromResult(1);
            }
        }

        if (!string.IsNullOrWhiteSpace(settings.NdjsonPath)) {
            try {
                WriteNdjson(result, settings.NdjsonPath!);
                AnsiConsole.MarkupLine($"[grey]NDJSON written:[/] {settings.NdjsonPath}");
            } catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]Failed to write NDJSON:[/] {ex.Message}");
                return Task.FromResult(1);
            }
        }

        if (settings.Json) {
            Console.WriteLine(JsonSerializer.Serialize(result, JsonOptions.Default));
            return Task.FromResult(0);
        }

        if (rows.Count == 0) {
            AnsiConsole.MarkupLine($"[yellow]No inventory snapshots found in:[/] {cacheDirectory}");
            return Task.FromResult(0);
        }

        var summary = new Table().Border(TableBorder.Rounded);
        summary.AddColumn("Metric");
        summary.AddColumn("Value");
        summary.AddRow("Loaded Snapshots", result.LoadedSnapshotCount.ToString());
        summary.AddRow("Returned Snapshots", result.ReturnedSnapshotCount.ToString());
        if (result.ExcludedByUntilCount > 0) {
            summary.AddRow("Excluded by UntilUtc", result.ExcludedByUntilCount.ToString());
        }
        summary.AddRow("SinceUtc", sinceUtc?.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss") ?? "-");
        summary.AddRow("UntilUtc", untilUtc?.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss") ?? "-");
        AnsiConsole.Write(summary);

        var rowsTable = new Table().Border(TableBorder.Rounded);
        rowsTable.Title = new TableTitle("Certificate Inventory Snapshots");
        rowsTable.AddColumn("Captured (UTC)");
        rowsTable.AddColumn("Port");
        rowsTable.AddColumn("Entries");
        rowsTable.AddColumn("Unique Endpoints");
        rowsTable.AddColumn("Valid");
        rowsTable.AddColumn("Expired");
        rowsTable.AddColumn("No ServerAuth");
        rowsTable.AddColumn("ClientAuth");
        rowsTable.AddColumn("Incomplete Chains");
        rowsTable.AddColumn("CT Template Errors");

        foreach (var row in rows) {
            rowsTable.AddRow(
                row.CapturedAtUtc.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss"),
                row.Port.ToString(),
                row.EntryCount.ToString(),
                row.UniqueEndpointCount.ToString(),
                row.ValidEntryCount.ToString(),
                row.ExpiredEntryCount.ToString(),
                row.MissingServerAuthEntryCount.ToString(),
                row.ClientAuthEntryCount.ToString(),
                row.IncompleteChainEntryCount.ToString(),
                row.CtTemplateErrorEntryCount.ToString());
        }

        AnsiConsole.Write(rowsTable);
        return Task.FromResult(0);
    }

    private static SnapshotCatalogRow BuildRow(CertificateInventorySnapshot snapshot) {
        var entries = snapshot.Entries ?? new List<CertificateInventoryEntry>();
        var endpointSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var validCount = 0;
        var expiredCount = 0;
        var missingServerAuthCount = 0;
        var clientAuthCount = 0;
        var incompleteChainCount = 0;
        var ctTemplateErrorCount = 0;

        foreach (var entry in entries) {
            if (entry == null) {
                continue;
            }

            var host = entry.ResolvedHost ?? entry.Host;
            var port = entry.Port > 0 ? entry.Port : 443;
            endpointSet.Add($"{host}:{port}");

            if (entry.Valid) {
                validCount++;
            }
            if (entry.Expired) {
                expiredCount++;
            }
            if (!entry.AllowsServerAuthentication) {
                missingServerAuthCount++;
            }
            if (entry.AllowsClientAuthentication) {
                clientAuthCount++;
            }
            if (!entry.ChainComplete && entry.IsReachable && !entry.IsSelfSigned) {
                incompleteChainCount++;
            }

            if (entry.CtTemplateFormatErrors != null &&
                entry.CtTemplateFormatErrors.Any(error => !string.IsNullOrWhiteSpace(error))) {
                ctTemplateErrorCount++;
            }
        }

        return new SnapshotCatalogRow {
            CapturedAtUtc = snapshot.CapturedAtUtc,
            Port = snapshot.Port,
            EntryCount = entries.Count,
            UniqueEndpointCount = endpointSet.Count,
            ValidEntryCount = validCount,
            ExpiredEntryCount = expiredCount,
            MissingServerAuthEntryCount = missingServerAuthCount,
            ClientAuthEntryCount = clientAuthCount,
            IncompleteChainEntryCount = incompleteChainCount,
            CtTemplateErrorEntryCount = ctTemplateErrorCount
        };
    }

    private static void WriteCsv(SnapshotCatalogResult result, string path) {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory)) {
            Directory.CreateDirectory(directory);
        }

        var sb = new StringBuilder();
        sb.AppendLine("CapturedAtUtc,Port,EntryCount,UniqueEndpointCount,ValidEntryCount,ExpiredEntryCount,MissingServerAuthEntryCount,ClientAuthEntryCount,IncompleteChainEntryCount,CtTemplateErrorEntryCount,LoadedSnapshotCount,ReturnedSnapshotCount,ExcludedByUntilCount,SinceUtc,UntilUtc");
        var sinceUtc = result.SinceUtc?.UtcDateTime.ToString("O") ?? string.Empty;
        var untilUtc = result.UntilUtc?.UtcDateTime.ToString("O") ?? string.Empty;
        foreach (var row in result.Snapshots) {
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(row.CapturedAtUtc.UtcDateTime.ToString("O")));
            sb.Append(',');
            sb.Append(row.Port);
            sb.Append(',');
            sb.Append(row.EntryCount);
            sb.Append(',');
            sb.Append(row.UniqueEndpointCount);
            sb.Append(',');
            sb.Append(row.ValidEntryCount);
            sb.Append(',');
            sb.Append(row.ExpiredEntryCount);
            sb.Append(',');
            sb.Append(row.MissingServerAuthEntryCount);
            sb.Append(',');
            sb.Append(row.ClientAuthEntryCount);
            sb.Append(',');
            sb.Append(row.IncompleteChainEntryCount);
            sb.Append(',');
            sb.Append(row.CtTemplateErrorEntryCount);
            sb.Append(',');
            sb.Append(result.LoadedSnapshotCount);
            sb.Append(',');
            sb.Append(result.ReturnedSnapshotCount);
            sb.Append(',');
            sb.Append(result.ExcludedByUntilCount);
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(sinceUtc));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(untilUtc));
            sb.AppendLine();
        }

        CertificateInventoryCommandHelpers.WriteUtf8Text(fullPath, sb.ToString());
    }

    private static void WriteNdjson(SnapshotCatalogResult result, string path) {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory)) {
            Directory.CreateDirectory(directory);
        }

        var sb = new StringBuilder();
        foreach (var row in result.Snapshots) {
            sb.AppendLine(CertificateInventoryCommandHelpers.SerializeJsonLine(new {
                RowType = "Snapshot",
                row.CapturedAtUtc,
                row.Port,
                row.EntryCount,
                row.UniqueEndpointCount,
                row.ValidEntryCount,
                row.ExpiredEntryCount,
                row.MissingServerAuthEntryCount,
                row.ClientAuthEntryCount,
                row.IncompleteChainEntryCount,
                row.CtTemplateErrorEntryCount,
                result.LoadedSnapshotCount,
                result.ReturnedSnapshotCount,
                result.ExcludedByUntilCount,
                result.SinceUtc,
                result.UntilUtc
            }));
        }

        CertificateInventoryCommandHelpers.WriteUtf8Text(fullPath, sb.ToString());
    }
}
