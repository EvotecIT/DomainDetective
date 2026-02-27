using DomainDetective.Helpers;
using Spectre.Console;
using Spectre.Console.Cli;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace DomainDetective.CLI.Commands;

/// <summary>
/// Settings for <see cref="CertificateInventoryQueryCommand"/>.
/// </summary>
internal sealed class CertificateInventoryQuerySettings : CommandSettings {
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

    /// <summary>Host substring filter.</summary>
    [Description("Host substring filter.")]
    [CommandOption("--host-contains <TEXT>")]
    public string? HostContains { get; set; }

    /// <summary>Certificate subject substring filter.</summary>
    [Description("Certificate subject substring filter.")]
    [CommandOption("--subject-contains <TEXT>")]
    public string? SubjectContains { get; set; }

    /// <summary>Subject alternative name substring filter.</summary>
    [Description("Subject alternative name substring filter.")]
    [CommandOption("--san-contains <TEXT>")]
    public string? SanContains { get; set; }

    /// <summary>Service equality filter (for example HTTPS, HTTPS-Alt, Custom TLS).</summary>
    [Description("Service equality filter (for example HTTPS, HTTPS-Alt, Custom TLS).")]
    [CommandOption("--service <NAME>")]
    public string? ServiceEquals { get; set; }

    /// <summary>Issuer substring filter.</summary>
    [Description("Issuer substring filter.")]
    [CommandOption("--issuer-contains <TEXT>")]
    public string? IssuerContains { get; set; }

    /// <summary>Leaf authority family exact-match filter (for example DigiCert, LetsEncrypt).</summary>
    [Description("Leaf authority family exact-match filter (for example DigiCert, LetsEncrypt).")]
    [CommandOption("--authority-family <NAME>")]
    public string? AuthorityFamilyEquals { get; set; }

    /// <summary>Root issuer/subject substring filter.</summary>
    [Description("Root issuer/subject substring filter.")]
    [CommandOption("--root-contains <TEXT>")]
    public string? RootContains { get; set; }

    /// <summary>Root authority family exact-match filter (for example DigiCert, LetsEncrypt).</summary>
    [Description("Root authority family exact-match filter (for example DigiCert, LetsEncrypt).")]
    [CommandOption("--root-authority-family <NAME>")]
    public string? RootAuthorityFamilyEquals { get; set; }

    /// <summary>CT source substring filter (for example crt.sh, shodan, censys).</summary>
    [Description("CT source substring filter (for example crt.sh, shodan, censys).")]
    [CommandOption("--ct-source-contains <TEXT>")]
    public string? CtSourceContains { get; set; }

    /// <summary>CT template/configuration error substring filter.</summary>
    [Description("CT template/configuration error substring filter.")]
    [CommandOption("--ct-template-error-contains <TEXT>")]
    public string? CtTemplateErrorContains { get; set; }

    /// <summary>Certificate chain source substring filter (for example tls-handshake).</summary>
    [Description("Certificate chain source substring filter (for example tls-handshake).")]
    [CommandOption("--chain-source-contains <TEXT>")]
    public string? ChainSourceContains { get; set; }

    /// <summary>Leaf certificate thumbprint exact-match filter.</summary>
    [Description("Leaf certificate thumbprint exact-match filter.")]
    [CommandOption("--thumbprint <HEX>")]
    public string? ThumbprintEquals { get; set; }

    /// <summary>Only include certificates from recognized public CAs.</summary>
    [Description("Only include certificates from recognized public CAs.")]
    [CommandOption("--known-ca-only")]
    public bool KnownCaOnly { get; set; }

    /// <summary>Only include certificates chaining to recognized public root CAs.</summary>
    [Description("Only include certificates chaining to recognized public root CAs.")]
    [CommandOption("--known-root-ca-only")]
    public bool KnownRootCaOnly { get; set; }

    /// <summary>Only include entries where certificate validation succeeded.</summary>
    [Description("Only include entries where certificate validation succeeded.")]
    [CommandOption("--valid-only")]
    public bool ValidOnly { get; set; }

    /// <summary>Only include expired certificates.</summary>
    [Description("Only include expired certificates.")]
    [CommandOption("--expired-only")]
    public bool ExpiredOnly { get; set; }

    /// <summary>Only include entries with incomplete chains.</summary>
    [Description("Only include entries with incomplete chains.")]
    [CommandOption("--chain-incomplete-only")]
    public bool ChainIncompleteOnly { get; set; }

    /// <summary>Only include entries where hostname validation failed.</summary>
    [Description("Only include entries where hostname validation failed.")]
    [CommandOption("--hostname-mismatch-only")]
    public bool HostnameMismatchOnly { get; set; }

    /// <summary>Only include self-signed certificates.</summary>
    [Description("Only include self-signed certificates.")]
    [CommandOption("--self-signed-only")]
    public bool SelfSignedOnly { get; set; }

    /// <summary>Only include unreachable endpoints.</summary>
    [Description("Only include unreachable endpoints.")]
    [CommandOption("--unreachable-only")]
    public bool UnreachableOnly { get; set; }

    /// <summary>Only include certificates observed in CT logs.</summary>
    [Description("Only include certificates observed in CT logs.")]
    [CommandOption("--ct-only")]
    public bool CtOnly { get; set; }

    /// <summary>Only include certificates that allow server authentication EKU.</summary>
    [Description("Only include certificates that allow server authentication EKU.")]
    [CommandOption("--server-auth-only")]
    public bool ServerAuthOnly { get; set; }

    /// <summary>Only include certificates that allow client authentication EKU.</summary>
    [Description("Only include certificates that allow client authentication EKU.")]
    [CommandOption("--client-auth-only")]
    public bool ClientAuthOnly { get; set; }

    /// <summary>Only include certificates that allow secure email EKU.</summary>
    [Description("Only include certificates that allow secure email EKU.")]
    [CommandOption("--secure-email-only")]
    public bool SecureEmailOnly { get; set; }

    /// <summary>Only include certificates that use weak keys.</summary>
    [Description("Only include certificates that use weak keys.")]
    [CommandOption("--weak-key-only")]
    public bool WeakKeyOnly { get; set; }

    /// <summary>Only include certificates signed with SHA-1.</summary>
    [Description("Only include certificates signed with SHA-1.")]
    [CommandOption("--sha1-signature-only")]
    public bool Sha1SignatureOnly { get; set; }

    /// <summary>Only include certificates that are not yet valid (NotBeforeUtc is in the future).</summary>
    [Description("Only include certificates that are not yet valid (NotBeforeUtc is in the future).")]
    [CommandOption("--not-yet-valid-only")]
    public bool NotYetValidOnly { get; set; }

    /// <summary>Only include certificates expiring within this many days.</summary>
    [Description("Only include certificates expiring within this many days.")]
    [CommandOption("--expiring-within-days <DAYS>")]
    public int? ExpiringWithinDays { get; set; }

    /// <summary>Authentication profile exact-match filter (for example ServerAuthOnly, ClientAuthOnly, MixedOrCustom).</summary>
    [Description("Authentication profile exact-match filter (for example ServerAuthOnly, ClientAuthOnly, MixedOrCustom).")]
    [CommandOption("--auth-profile <NAME>")]
    public string? AuthenticationProfileEquals { get; set; }

    /// <summary>Only evaluate the latest observed entry per endpoint (host+port) in the selected snapshot window.</summary>
    [Description("Only evaluate the latest observed entry per endpoint (host+port) in the selected snapshot window.")]
    [CommandOption("--latest-only")]
    public bool LatestOnly { get; set; }

    /// <summary>Maximum number of results returned.</summary>
    [Description("Maximum number of results returned.")]
    [CommandOption("--max-results <N>")]
    [DefaultValue(200)]
    public int MaxResults { get; set; } = 200;

    /// <summary>Output JSON instead of tables.</summary>
    [Description("Output JSON instead of tables.")]
    [CommandOption("--json")]
    public bool Json { get; set; }

    /// <summary>Show matched-entry breakdown tables (service/issuer/auth/chain/CT) for table output (ignored with --json).</summary>
    [Description("Show matched-entry breakdown tables (service/issuer/auth/chain/CT) for table output (ignored with --json).")]
    [CommandOption("--show-breakdown")]
    public bool ShowBreakdown { get; set; }
}

/// <summary>
/// Queries persisted certificate inventory entries using filters.
/// </summary>
internal sealed class CertificateInventoryQueryCommand : AsyncCommand<CertificateInventoryQuerySettings> {
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    public override Task<int> ExecuteAsync(CommandContext context, CertificateInventoryQuerySettings settings) {
        if (settings == null) {
            throw new ArgumentNullException(nameof(settings));
        }

        if (settings.MaxResults < 0) {
            AnsiConsole.MarkupLine("[red]--max-results must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ExpiringWithinDays.HasValue && settings.ExpiringWithinDays.Value < 0) {
            AnsiConsole.MarkupLine("[red]--expiring-within-days must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ExpiredOnly && settings.ExpiringWithinDays.HasValue) {
            AnsiConsole.MarkupLine("[red]--expired-only cannot be combined with --expiring-within-days.[/]");
            return Task.FromResult(1);
        }
        if (settings.ExpiredOnly && settings.NotYetValidOnly) {
            AnsiConsole.MarkupLine("[red]--expired-only cannot be combined with --not-yet-valid-only.[/]");
            return Task.FromResult(1);
        }

        var cacheDirectory = ResolveCacheDirectory(settings.CacheDirectory);
        var monitor = new CertificateMonitor {
            CacheDirectory = cacheDirectory,
            PersistInventorySnapshots = false
        };

        var query = new CertificateInventoryQuery {
            SinceUtc = ToUtc(settings.SinceUtc),
            UntilUtc = ToUtc(settings.UntilUtc),
            HostContains = settings.HostContains,
            SubjectContains = settings.SubjectContains,
            SanContains = settings.SanContains,
            ServiceEquals = settings.ServiceEquals,
            IssuerContains = settings.IssuerContains,
            AuthorityFamilyEquals = settings.AuthorityFamilyEquals,
            RootContains = settings.RootContains,
            RootAuthorityFamilyEquals = settings.RootAuthorityFamilyEquals,
            CtSourceContains = settings.CtSourceContains,
            CtTemplateErrorContains = settings.CtTemplateErrorContains,
            ChainSourceContains = settings.ChainSourceContains,
            ThumbprintEquals = settings.ThumbprintEquals,
            KnownAuthorityOnly = settings.KnownCaOnly ? true : null,
            KnownRootAuthorityOnly = settings.KnownRootCaOnly ? true : null,
            ValidOnly = settings.ValidOnly ? true : null,
            ExpiredOnly = settings.ExpiredOnly ? true : null,
            ChainCompleteOnly = settings.ChainIncompleteOnly ? false : null,
            HostnameMatchOnly = settings.HostnameMismatchOnly ? false : null,
            SelfSignedOnly = settings.SelfSignedOnly ? true : null,
            ReachableOnly = settings.UnreachableOnly ? false : null,
            PresentInCtOnly = settings.CtOnly ? true : null,
            AllowsServerAuthOnly = settings.ServerAuthOnly ? true : null,
            AllowsClientAuthOnly = settings.ClientAuthOnly ? true : null,
            AllowsSecureEmailOnly = settings.SecureEmailOnly ? true : null,
            WeakKeyOnly = settings.WeakKeyOnly ? true : null,
            Sha1SignatureOnly = settings.Sha1SignatureOnly ? true : null,
            NotYetValidOnly = settings.NotYetValidOnly ? true : null,
            ExpiringWithinDays = settings.ExpiringWithinDays,
            AuthenticationProfileEquals = settings.AuthenticationProfileEquals,
            LatestPerEndpointOnly = settings.LatestOnly,
            MaxResults = settings.MaxResults
        };
        var result = monitor.QueryInventoryEntries(query);

        if (settings.Json) {
            var json = JsonSerializer.Serialize(result, JsonOptions.Default);
            Console.WriteLine(json);
            return Task.FromResult(0);
        }

        var summary = new Table().Border(TableBorder.Rounded);
        summary.AddColumn("Metric");
        summary.AddColumn("Value");
        if (result.SkippedSnapshotCountByUntilUtc > 0) {
            summary.AddRow("Loaded Snapshots", result.LoadedSnapshotCount.ToString());
            summary.AddRow("Skipped by UntilUtc", result.SkippedSnapshotCountByUntilUtc.ToString());
        }
        summary.AddRow("Scanned Snapshots", result.ScannedSnapshotCount.ToString());
        summary.AddRow("Scanned Entries", result.ScannedEntryCount.ToString());
        if (settings.LatestOnly) {
            summary.AddRow("Latest Per Endpoint", "Yes");
            summary.AddRow("Skipped Older Endpoint Entries", result.SkippedByLatestPerEndpointCount.ToString());
        }
        summary.AddRow("Evaluated Entries", result.EvaluatedEntryCount.ToString());
        if (result.ExcludedByFiltersCount > 0) {
            summary.AddRow("Excluded by Filters", result.ExcludedByFiltersCount.ToString());
        }
        summary.AddRow("Matched Entries", result.MatchedEntryCount.ToString());
        summary.AddRow("Matched Unique Endpoints", result.MatchedUniqueEndpointCount.ToString());
        summary.AddRow("Returned Entries", result.Entries.Count.ToString());
        summary.AddRow("Truncated", result.Truncated ? "Yes" : "No");
        if (result.EntriesTruncatedByMaxResults > 0) {
            summary.AddRow("Truncated by Max Results", result.EntriesTruncatedByMaxResults.ToString());
        }
        AnsiConsole.Write(summary);

        if (result.Entries.Count == 0) {
            AnsiConsole.MarkupLine("[yellow]No inventory entries matched the query.[/]");
            return Task.FromResult(0);
        }

        var rows = new Table().Border(TableBorder.Rounded);
        rows.Title = new TableTitle("Certificate Inventory Query");
        rows.AddColumn("Captured");
        rows.AddColumn("Host");
        rows.AddColumn("Port");
        rows.AddColumn("Service");
        rows.AddColumn("Issuer");
        rows.AddColumn("Root");
        rows.AddColumn("Expires");
        rows.AddColumn("Known CA");
        rows.AddColumn("Valid");
        rows.AddColumn("Chain");
        rows.AddColumn("Auth");
        foreach (var observed in result.Entries.OrderByDescending(x => x.CapturedAtUtc)) {
            var entry = observed.Entry;
            var host = entry.ResolvedHost ?? entry.Host;
            var issuer = entry.CertificateIssuerNormalized ?? entry.CertificateIssuerOrganization ?? entry.CertificateIssuer ?? "-";
            var root = entry.CertificateRootIssuerNormalized ?? entry.CertificateRootIssuerOrganization ?? entry.CertificateRootIssuer ?? entry.CertificateRootSubject ?? "-";
            var expires = entry.NotAfterUtc?.UtcDateTime.ToString("yyyy-MM-dd") ?? "-";
            var authFlags = BuildAuthFlags(entry);
            rows.AddRow(
                observed.CapturedAtUtc.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss"),
                host,
                entry.Port.ToString(),
                entry.Service ?? "-",
                issuer,
                root,
                expires,
                entry.IsKnownCertificateAuthority ? "Yes" : "No",
                entry.Valid ? "Yes" : "No",
                entry.ChainComplete ? "Complete" : "Incomplete",
                authFlags);
        }
        AnsiConsole.Write(rows);
        if (settings.ShowBreakdown) {
            RenderCountTable("Matched Services", result.MatchedServiceCounts);
            RenderCountTable("Matched Issuers", result.MatchedIssuerCounts);
            RenderCountTable("Matched Root Issuers", result.MatchedRootIssuerCounts);
            RenderCountTable("Matched Auth Profiles", result.MatchedAuthenticationProfileCounts);
            RenderCountTable("Matched Chain Sources", result.MatchedChainSourceCounts);
            RenderCountTable("Matched CT Sources", result.MatchedCtSourceCounts);
            RenderCountTable("Matched CT Template Errors", result.MatchedCtTemplateErrorCounts);
        }
        return Task.FromResult(0);
    }

    private static string BuildAuthFlags(CertificateInventoryEntry entry) {
        var flags = string.Empty;
        if (entry.AllowsServerAuthentication) {
            flags += "S";
        }
        if (entry.AllowsClientAuthentication) {
            flags += "C";
        }
        if (entry.AllowsSecureEmail) {
            flags += "E";
        }

        return flags.Length == 0 ? "-" : flags;
    }

    private static void RenderCountTable(string title, Dictionary<string, int> counters) {
        if (counters.Count == 0) {
            return;
        }

        var table = new Table().Border(TableBorder.Rounded);
        var suffix = counters.Count > 20 ? $" (Top 20 of {counters.Count})" : string.Empty;
        table.Title = new TableTitle($"{title}{suffix}");
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
