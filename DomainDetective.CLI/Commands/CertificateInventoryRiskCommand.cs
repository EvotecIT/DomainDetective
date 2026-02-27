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

    /// <summary>Optional minimum severity filter (None means no additional score filter).</summary>
    [Description("Optional minimum severity filter (None means no additional score filter; other values: Low, Medium, High, Critical).")]
    [CommandOption("--minimum-severity <LEVEL>")]
    public string? MinimumSeverity { get; set; }

    /// <summary>Optional case-insensitive reason substring filter (for example CertificateExpired, WeakKey, CtNotObserved).</summary>
    [Description("Optional case-insensitive reason substring filter (for example CertificateExpired, WeakKey, CtNotObserved).")]
    [CommandOption("--reason-contains <TEXT>")]
    public string? ReasonContains { get; set; }

    /// <summary>Optional case-insensitive issuer/root-issuer substring filter (for example DigiCert, Let's Encrypt, ISRG).</summary>
    [Description("Optional case-insensitive issuer/root-issuer substring filter (for example DigiCert, Let's Encrypt, ISRG).")]
    [CommandOption("--issuer-contains <TEXT>")]
    public string? IssuerContains { get; set; }

    /// <summary>Optional leaf authority family exact-match filter (for example DigiCert, LetsEncrypt).</summary>
    [Description("Optional leaf authority family exact-match filter (for example DigiCert, LetsEncrypt).")]
    [CommandOption("--authority-family <NAME>")]
    public string? AuthorityFamilyEquals { get; set; }

    /// <summary>Optional root authority family exact-match filter (for example DigiCert, LetsEncrypt).</summary>
    [Description("Optional root authority family exact-match filter (for example DigiCert, LetsEncrypt).")]
    [CommandOption("--root-authority-family <NAME>")]
    public string? RootAuthorityFamilyEquals { get; set; }

    /// <summary>Optional CT/discovery source substring filter (for example crt.sh, shodan, censys).</summary>
    [Description("Optional CT/discovery source substring filter (for example crt.sh, shodan, censys).")]
    [CommandOption("--ct-source-contains <TEXT>")]
    public string? CtSourceContains { get; set; }

    /// <summary>Optional CT template/configuration error substring filter.</summary>
    [Description("Optional CT template/configuration error substring filter.")]
    [CommandOption("--ct-template-error-contains <TEXT>")]
    public string? CtTemplateErrorContains { get; set; }

    /// <summary>Optional chain-source substring filter (for example tls-handshake, aia-download).</summary>
    [Description("Optional chain-source substring filter (for example tls-handshake, aia-download).")]
    [CommandOption("--chain-source-contains <TEXT>")]
    public string? ChainSourceContains { get; set; }

    /// <summary>Optional leaf-certificate thumbprint exact-match filter (hex string expected).</summary>
    [Description("Optional leaf-certificate thumbprint exact-match filter (hex string expected).")]
    [CommandOption("--thumbprint <HEX>")]
    public string? ThumbprintEquals { get; set; }

    /// <summary>Optional root-certificate thumbprint exact-match filter (hex string expected).</summary>
    [Description("Optional root-certificate thumbprint exact-match filter (hex string expected).")]
    [CommandOption("--root-thumbprint <HEX>")]
    public string? RootThumbprintEquals { get; set; }

    /// <summary>Optional leaf-certificate serial-number exact-match filter (hex string expected).</summary>
    [Description("Optional leaf-certificate serial-number exact-match filter (hex string expected).")]
    [CommandOption("--serial-number <HEX>")]
    public string? SerialNumberEquals { get; set; }

    /// <summary>Optional case-insensitive host substring filter.</summary>
    [Description("Optional case-insensitive host substring filter.")]
    [CommandOption("--host-contains <TEXT>")]
    public string? HostContains { get; set; }

    /// <summary>Optional case-insensitive service exact-match filter (for example HTTPS, HTTPS-Alt, Custom TLS).</summary>
    [Description("Optional case-insensitive service exact-match filter (for example HTTPS, HTTPS-Alt, Custom TLS).")]
    [CommandOption("--service <NAME>")]
    public string? ServiceEquals { get; set; }

    /// <summary>Optional endpoint port exact-match filter (1-65535).</summary>
    [Description("Optional endpoint port exact-match filter (1-65535).")]
    [CommandOption("--port <N>")]
    public int? PortEquals { get; set; }

    /// <summary>Only include endpoints whose certificates were observed in CT logs.</summary>
    [Description("Only include endpoints whose certificates were observed in CT logs.")]
    [CommandOption("--ct-observed-only")]
    public bool CtObservedOnly { get; set; }

    /// <summary>Only include endpoints whose certificates were not observed in CT logs.</summary>
    [Description("Only include endpoints whose certificates were not observed in CT logs.")]
    [CommandOption("--ct-missing-only")]
    public bool CtMissingOnly { get; set; }

    /// <summary>Only include endpoints with complete certificate chains.</summary>
    [Description("Only include endpoints with complete certificate chains.")]
    [CommandOption("--chain-complete-only")]
    public bool ChainCompleteOnly { get; set; }

    /// <summary>Only include endpoints with incomplete certificate chains.</summary>
    [Description("Only include endpoints with incomplete certificate chains.")]
    [CommandOption("--chain-incomplete-only")]
    public bool ChainIncompleteOnly { get; set; }

    /// <summary>Only include endpoints reachable on the scanned endpoint.</summary>
    [Description("Only include endpoints reachable on the scanned endpoint.")]
    [CommandOption("--reachable-only")]
    public bool ReachableOnly { get; set; }

    /// <summary>Only include endpoints that were not reachable on the scanned endpoint.</summary>
    [Description("Only include endpoints that were not reachable on the scanned endpoint.")]
    [CommandOption("--unreachable-only")]
    public bool UnreachableOnly { get; set; }

    /// <summary>Only include endpoints whose certificate matches the requested hostname.</summary>
    [Description("Only include endpoints whose certificate matches the requested hostname.")]
    [CommandOption("--hostname-match-only")]
    public bool HostnameMatchOnly { get; set; }

    /// <summary>Only include endpoints whose certificate does not match the requested hostname.</summary>
    [Description("Only include endpoints whose certificate does not match the requested hostname.")]
    [CommandOption("--hostname-mismatch-only")]
    public bool HostnameMismatchOnly { get; set; }

    /// <summary>Only include endpoints using self-signed certificates.</summary>
    [Description("Only include endpoints using self-signed certificates.")]
    [CommandOption("--self-signed-only")]
    public bool SelfSignedOnly { get; set; }

    /// <summary>Only include endpoints using CA-signed certificates.</summary>
    [Description("Only include endpoints using CA-signed certificates.")]
    [CommandOption("--ca-signed-only")]
    public bool CaSignedOnly { get; set; }

    /// <summary>Only include endpoints with weak keys.</summary>
    [Description("Only include endpoints with weak keys.")]
    [CommandOption("--weak-key-only")]
    public bool WeakKeyOnly { get; set; }

    /// <summary>Only include endpoints without weak keys.</summary>
    [Description("Only include endpoints without weak keys.")]
    [CommandOption("--strong-key-only")]
    public bool StrongKeyOnly { get; set; }

    /// <summary>Only include endpoints using SHA-1 signatures.</summary>
    [Description("Only include endpoints using SHA-1 signatures.")]
    [CommandOption("--sha1-signature-only")]
    public bool Sha1SignatureOnly { get; set; }

    /// <summary>Only include endpoints not using SHA-1 signatures.</summary>
    [Description("Only include endpoints not using SHA-1 signatures.")]
    [CommandOption("--non-sha1-signature-only")]
    public bool NonSha1SignatureOnly { get; set; }

    /// <summary>Optional authentication profile exact-match filter (for example ServerAuthOnly, ClientAuthOnly, MixedOrCustom).</summary>
    [Description("Optional authentication profile exact-match filter (for example ServerAuthOnly, ClientAuthOnly, MixedOrCustom).")]
    [CommandOption("--auth-profile <NAME>")]
    public string? AuthenticationProfileEquals { get; set; }

    /// <summary>Only include endpoints with recognized public CAs as the leaf issuer.</summary>
    [Description("Only include endpoints with recognized public CAs as the leaf issuer.")]
    [CommandOption("--known-ca-only")]
    public bool KnownCaOnly { get; set; }

    /// <summary>Only include endpoints with unrecognized/private CAs as the leaf issuer.</summary>
    [Description("Only include endpoints with unrecognized/private CAs as the leaf issuer.")]
    [CommandOption("--unknown-ca-only")]
    public bool UnknownCaOnly { get; set; }

    /// <summary>Only include endpoints chaining to recognized public root CAs.</summary>
    [Description("Only include endpoints chaining to recognized public root CAs.")]
    [CommandOption("--known-root-ca-only")]
    public bool KnownRootCaOnly { get; set; }

    /// <summary>Only include endpoints chaining to unrecognized/private root CAs.</summary>
    [Description("Only include endpoints chaining to unrecognized/private root CAs.")]
    [CommandOption("--unknown-root-ca-only")]
    public bool UnknownRootCaOnly { get; set; }

    /// <summary>Only include endpoints whose certificate allows server authentication EKU.</summary>
    [Description("Only include endpoints whose certificate allows server authentication EKU.")]
    [CommandOption("--server-auth-only")]
    public bool ServerAuthOnly { get; set; }

    /// <summary>Only include endpoints whose certificate allows client authentication EKU.</summary>
    [Description("Only include endpoints whose certificate allows client authentication EKU.")]
    [CommandOption("--client-auth-only")]
    public bool ClientAuthOnly { get; set; }

    /// <summary>Only include endpoints whose certificate allows secure-email EKU.</summary>
    [Description("Only include endpoints whose certificate allows secure-email EKU.")]
    [CommandOption("--secure-email-only")]
    public bool SecureEmailOnly { get; set; }

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
        if (settings.PortEquals.HasValue && (settings.PortEquals.Value <= 0 || settings.PortEquals.Value > 65535)) {
            AnsiConsole.MarkupLine("[red]--port must be between 1 and 65535.[/]");
            return Task.FromResult(1);
        }
        if (settings.CtObservedOnly && settings.CtMissingOnly) {
            AnsiConsole.MarkupLine("[red]--ct-observed-only cannot be combined with --ct-missing-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.ChainCompleteOnly && settings.ChainIncompleteOnly) {
            AnsiConsole.MarkupLine("[red]--chain-complete-only cannot be combined with --chain-incomplete-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReachableOnly && settings.UnreachableOnly) {
            AnsiConsole.MarkupLine("[red]--reachable-only cannot be combined with --unreachable-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.HostnameMatchOnly && settings.HostnameMismatchOnly) {
            AnsiConsole.MarkupLine("[red]--hostname-match-only cannot be combined with --hostname-mismatch-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.SelfSignedOnly && settings.CaSignedOnly) {
            AnsiConsole.MarkupLine("[red]--self-signed-only cannot be combined with --ca-signed-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.WeakKeyOnly && settings.StrongKeyOnly) {
            AnsiConsole.MarkupLine("[red]--weak-key-only cannot be combined with --strong-key-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.Sha1SignatureOnly && settings.NonSha1SignatureOnly) {
            AnsiConsole.MarkupLine("[red]--sha1-signature-only cannot be combined with --non-sha1-signature-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.KnownCaOnly && settings.UnknownCaOnly) {
            AnsiConsole.MarkupLine("[red]--known-ca-only cannot be combined with --unknown-ca-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.KnownRootCaOnly && settings.UnknownRootCaOnly) {
            AnsiConsole.MarkupLine("[red]--known-root-ca-only cannot be combined with --unknown-root-ca-only.[/]");
            return Task.FromResult(1);
        }
        var normalizedMinimumSeverity = settings.MinimumSeverity;
        if (!string.IsNullOrWhiteSpace(settings.MinimumSeverity)) {
            if (!CertificateInventoryRiskAnalyzer.TryResolveMinimumSeverity(settings.MinimumSeverity, out _, out var normalized)) {
                AnsiConsole.MarkupLine($"[red]--minimum-severity must be one of: {CertificateInventoryRiskAnalyzer.MinimumSeverityAcceptedValues}.[/]");
                return Task.FromResult(1);
            }

            // Validate early for user-friendly CLI messaging; analyzer validates again for API callers.
            normalizedMinimumSeverity = normalized;
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
            maxEndpoints: settings.MaxEndpoints,
            minimumSeverity: normalizedMinimumSeverity,
            reasonContains: settings.ReasonContains,
            issuerContains: settings.IssuerContains,
            authorityFamilyEquals: settings.AuthorityFamilyEquals,
            rootAuthorityFamilyEquals: settings.RootAuthorityFamilyEquals,
            ctSourceContains: settings.CtSourceContains,
            ctTemplateErrorContains: settings.CtTemplateErrorContains,
            chainSourceContains: settings.ChainSourceContains,
            thumbprintEquals: settings.ThumbprintEquals,
            rootThumbprintEquals: settings.RootThumbprintEquals,
            serialNumberEquals: settings.SerialNumberEquals,
            hostContains: settings.HostContains,
            serviceEquals: settings.ServiceEquals,
            portEquals: settings.PortEquals,
            ctObservedOnly: settings.CtObservedOnly ? true : settings.CtMissingOnly ? false : null,
            chainCompleteOnly: settings.ChainCompleteOnly ? true : settings.ChainIncompleteOnly ? false : null,
            reachableOnly: settings.ReachableOnly ? true : settings.UnreachableOnly ? false : null,
            hostnameMatchOnly: settings.HostnameMatchOnly ? true : settings.HostnameMismatchOnly ? false : null,
            selfSignedOnly: settings.SelfSignedOnly ? true : settings.CaSignedOnly ? false : null,
            weakKeyOnly: settings.WeakKeyOnly ? true : settings.StrongKeyOnly ? false : null,
            sha1SignatureOnly: settings.Sha1SignatureOnly ? true : settings.NonSha1SignatureOnly ? false : null,
            knownAuthorityOnly: settings.KnownCaOnly ? true : settings.UnknownCaOnly ? false : null,
            knownRootAuthorityOnly: settings.KnownRootCaOnly ? true : settings.UnknownRootCaOnly ? false : null,
            authenticationProfileEquals: settings.AuthenticationProfileEquals,
            serverAuthOnly: settings.ServerAuthOnly,
            clientAuthOnly: settings.ClientAuthOnly,
            secureEmailOnly: settings.SecureEmailOnly);

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
        summary.AddRow("Matched Endpoints", risk.MatchedEndpointCount.ToString());
        summary.AddRow("Returned Endpoints", risk.Endpoints.Count.ToString());
        summary.AddRow("Truncated Endpoints", risk.EndpointsTruncatedByMaxEndpoints.ToString());
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

        if (risk.Truncated) {
            AnsiConsole.MarkupLine($"[yellow]Endpoint rows truncated by --max-endpoints:[/] {risk.EndpointsTruncatedByMaxEndpoints}");
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
