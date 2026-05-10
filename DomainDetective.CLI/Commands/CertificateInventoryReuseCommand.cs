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
/// Settings for <see cref="CertificateInventoryReuseCommand"/>.
/// </summary>
internal sealed class CertificateInventoryReuseSettings : CommandSettings {
    /// <summary>Certificate monitor cache directory (defaults to system temp path).</summary>
    [Description("Certificate monitor cache directory (defaults to system temp path).")]
    [CommandOption("--cache-dir <PATH>")]
    public string? CacheDirectory { get; set; }

    /// <summary>Only include snapshots captured since this UTC timestamp.</summary>
    [Description("Only include snapshots captured since this UTC timestamp.")]
    [CommandOption("--since-utc <UTC>")]
    public DateTime? SinceUtc { get; set; }

    /// <summary>Include certificates assigned to only one endpoint.</summary>
    [Description("Include certificates assigned to only one endpoint.")]
    [CommandOption("--include-singletons")]
    public bool IncludeSingletons { get; set; }

    /// <summary>Minimum endpoint count required per certificate row.</summary>
    [Description("Minimum endpoint count required per certificate row.")]
    [CommandOption("--min-endpoints <N>")]
    [DefaultValue(2)]
    public int MinEndpoints { get; set; } = 2;

    /// <summary>Maximum certificate rows returned.</summary>
    [Description("Maximum certificate rows returned.")]
    [CommandOption("--max-certificates <N>")]
    [DefaultValue(300)]
    public int MaxCertificates { get; set; } = 300;

    /// <summary>Maximum endpoint references returned per certificate row.</summary>
    [Description("Maximum endpoint references returned per certificate row.")]
    [CommandOption("--max-endpoints-per-certificate <N>")]
    [DefaultValue(30)]
    public int MaxEndpointsPerCertificate { get; set; } = 30;

    /// <summary>Output JSON instead of tables.</summary>
    [Description("Output JSON instead of tables.")]
    [CommandOption("--json")]
    public bool Json { get; set; }

    /// <summary>Optional CSV output path for certificate reuse rows.</summary>
    [Description("Optional CSV output path for certificate reuse rows.")]
    [CommandOption("--csv-path <PATH>")]
    public string? CsvPath { get; set; }

    /// <summary>Optional NDJSON output path for certificate reuse rows (one JSON object per line).</summary>
    [Description("Optional NDJSON output path for certificate reuse rows (one JSON object per line).")]
    [CommandOption("--ndjson-path <PATH>")]
    public string? NdjsonPath { get; set; }
}

/// <summary>
/// Displays certificate-to-endpoint assignment and reuse mapping from persisted snapshots.
/// </summary>
internal sealed class CertificateInventoryReuseCommand : AsyncCommand<CertificateInventoryReuseSettings> {
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    protected override Task<int> ExecuteAsync(CommandContext context, CertificateInventoryReuseSettings settings, CancellationToken cancellationToken) {
        if (settings == null) {
            throw new ArgumentNullException(nameof(settings));
        }

        if (settings.MinEndpoints < 1) {
            AnsiConsole.MarkupLine("[red]--min-endpoints must be 1 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.MaxCertificates < 0) {
            AnsiConsole.MarkupLine("[red]--max-certificates must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.MaxEndpointsPerCertificate < 0) {
            AnsiConsole.MarkupLine("[red]--max-endpoints-per-certificate must be 0 or greater.[/]");
            return Task.FromResult(1);
        }

        var cacheDirectory = CertificateInventoryCommandHelpers.ResolveCacheDirectory(settings.CacheDirectory);
        var monitor = new CertificateMonitor {
            CacheDirectory = cacheDirectory,
            PersistInventorySnapshots = false
        };

        var reuse = monitor.BuildInventoryReuse(
            sinceUtc: CertificateInventoryCommandHelpers.ToUtc(settings.SinceUtc),
            includeSingleEndpointCertificates: settings.IncludeSingletons,
            minEndpointCount: settings.MinEndpoints,
            maxCertificates: settings.MaxCertificates,
            maxEndpointsPerCertificate: settings.MaxEndpointsPerCertificate);

        if (!string.IsNullOrWhiteSpace(settings.CsvPath)) {
            try {
                WriteCsv(reuse, settings.CsvPath!);
                AnsiConsole.MarkupLine($"[grey]CSV written:[/] {settings.CsvPath}");
            } catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]Failed to write CSV:[/] {ex.Message}");
                return Task.FromResult(1);
            }
        }

        if (!string.IsNullOrWhiteSpace(settings.NdjsonPath)) {
            try {
                WriteNdjson(reuse, settings.NdjsonPath!);
                AnsiConsole.MarkupLine($"[grey]NDJSON written:[/] {settings.NdjsonPath}");
            } catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]Failed to write NDJSON:[/] {ex.Message}");
                return Task.FromResult(1);
            }
        }

        if (settings.Json) {
            Console.WriteLine(JsonSerializer.Serialize(reuse, JsonOptions.Default));
            return Task.FromResult(0);
        }

        if (reuse.SnapshotCount == 0) {
            AnsiConsole.MarkupLine($"[yellow]No inventory snapshots found in:[/] {cacheDirectory}");
            return Task.FromResult(0);
        }

        var summary = new Table().Border(TableBorder.Rounded);
        summary.AddColumn("Metric");
        summary.AddColumn("Value");
        summary.AddRow("Snapshots", reuse.SnapshotCount.ToString());
        summary.AddRow("Endpoints (Latest)", reuse.EndpointCount.ToString());
        summary.AddRow("Certificates (Latest)", reuse.CertificateCount.ToString());
        summary.AddRow("Multi-Endpoint Certs", reuse.MultiEndpointCertificateCount.ToString());
        summary.AddRow("Cross-Service Certs", reuse.CrossServiceCertificateCount.ToString());
        summary.AddRow("Wildcard Certs", reuse.WildcardCertificateCount.ToString());
        summary.AddRow("Returned Rows", reuse.Certificates.Count.ToString());
        AnsiConsole.Write(summary);

        if (reuse.Certificates.Count == 0) {
            AnsiConsole.MarkupLine("[yellow]No certificate reuse rows to display.[/]");
            return Task.FromResult(0);
        }

        var rows = new Table().Border(TableBorder.Rounded);
        rows.Title = new TableTitle("Certificate Reuse");
        rows.AddColumn("Subject");
        rows.AddColumn("Issuer");
        rows.AddColumn("Endpoints");
        rows.AddColumn("Services");
        rows.AddColumn("Ports");
        rows.AddColumn("Expiry");
        rows.AddColumn("Flags");
        rows.AddColumn("Sample Endpoints");
        foreach (var certificate in reuse.Certificates
                     .OrderByDescending(x => x.EndpointCount)
                     .ThenBy(x => x.Subject, StringComparer.OrdinalIgnoreCase)) {
            var expiry = certificate.NotAfterUtc?.UtcDateTime.ToString("yyyy-MM-dd") ?? "-";
            var flags = BuildFlags(certificate);
            var sampleEndpoints = certificate.Endpoints.Count == 0
                ? "-"
                : string.Join(", ", certificate.Endpoints.Select(x => $"{x.Host}:{x.Port}"));
            rows.AddRow(
                string.IsNullOrWhiteSpace(certificate.Subject) ? "-" : certificate.Subject,
                certificate.Issuer,
                certificate.EndpointCount.ToString(),
                certificate.DistinctServiceCount.ToString(),
                certificate.DistinctPortCount.ToString(),
                expiry,
                flags,
                sampleEndpoints);
        }
        AnsiConsole.Write(rows);

        return Task.FromResult(0);
    }

    private static void WriteCsv(CertificateInventoryReuseSummary reuse, string path) {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory)) {
            Directory.CreateDirectory(directory);
        }

        var sb = new StringBuilder();
        sb.AppendLine("CertificateId,Thumbprint,Subject,Issuer,RootIssuer,NotAfterUtc,IsKnownCertificateAuthority,HasWildcardSan,AllowsServerAuthentication,AllowsClientAuthentication,EndpointCount,DistinctServiceCount,DistinctPortCount,Endpoints");
        foreach (var certificate in reuse.Certificates) {
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(certificate.CertificateId));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(certificate.Thumbprint));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(certificate.Subject));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(certificate.Issuer));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(certificate.RootIssuer));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(certificate.NotAfterUtc?.UtcDateTime.ToString("O") ?? string.Empty));
            sb.Append(',');
            sb.Append(certificate.IsKnownCertificateAuthority ? "true" : "false");
            sb.Append(',');
            sb.Append(certificate.HasWildcardSan ? "true" : "false");
            sb.Append(',');
            sb.Append(certificate.AllowsServerAuthentication ? "true" : "false");
            sb.Append(',');
            sb.Append(certificate.AllowsClientAuthentication ? "true" : "false");
            sb.Append(',');
            sb.Append(certificate.EndpointCount);
            sb.Append(',');
            sb.Append(certificate.DistinctServiceCount);
            sb.Append(',');
            sb.Append(certificate.DistinctPortCount);
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(string.Join("|", certificate.Endpoints.Select(endpoint =>
                $"{endpoint.Host}:{endpoint.Port}:{endpoint.Service}:{endpoint.LastObservedUtc.UtcDateTime:O}"))));
            sb.AppendLine();
        }

        CertificateInventoryCommandHelpers.WriteUtf8Text(fullPath, sb.ToString());
    }

    private static void WriteNdjson(CertificateInventoryReuseSummary reuse, string path) {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory)) {
            Directory.CreateDirectory(directory);
        }

        var sb = new StringBuilder();
        foreach (var certificate in reuse.Certificates) {
            sb.AppendLine(CertificateInventoryCommandHelpers.SerializeJsonLine(certificate));
        }

        CertificateInventoryCommandHelpers.WriteUtf8Text(fullPath, sb.ToString());
    }

    private static string BuildFlags(CertificateInventoryCertificateReuse certificate) {
        var flags = string.Empty;
        if (certificate.HasWildcardSan) {
            flags += "W";
        }
        if (certificate.IsKnownCertificateAuthority) {
            flags += "K";
        }
        if (certificate.AllowsServerAuthentication) {
            flags += "S";
        }
        if (certificate.AllowsClientAuthentication) {
            flags += "C";
        }
        return flags.Length == 0 ? "-" : flags;
    }

}

