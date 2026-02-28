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

    /// <summary>Optional minimum endpoint risk score filter (0-100).</summary>
    [Description("Optional minimum endpoint risk score filter (0-100).")]
    [CommandOption("--score-min <N>")]
    public int? ScoreMin { get; set; }

    /// <summary>Optional maximum endpoint risk score filter (0-100).</summary>
    [Description("Optional maximum endpoint risk score filter (0-100).")]
    [CommandOption("--score-max <N>")]
    public int? ScoreMax { get; set; }

    /// <summary>Optional minimum reason-count filter (0 or greater).</summary>
    [Description("Optional minimum reason-count filter (0 or greater).")]
    [CommandOption("--reason-count-min <N>")]
    public int? ReasonCountMin { get; set; }

    /// <summary>Optional maximum reason-count filter (0 or greater).</summary>
    [Description("Optional maximum reason-count filter (0 or greater).")]
    [CommandOption("--reason-count-max <N>")]
    public int? ReasonCountMax { get; set; }

    /// <summary>Optional minimum certificate-reuse endpoint-count filter (1 or greater).</summary>
    [Description("Optional minimum certificate-reuse endpoint-count filter (1 or greater).")]
    [CommandOption("--reuse-endpoint-min <N>")]
    public int? ReuseEndpointCountMin { get; set; }

    /// <summary>Optional maximum certificate-reuse endpoint-count filter (1 or greater).</summary>
    [Description("Optional maximum certificate-reuse endpoint-count filter (1 or greater).")]
    [CommandOption("--reuse-endpoint-max <N>")]
    public int? ReuseEndpointCountMax { get; set; }

    /// <summary>Only include endpoints where the same certificate is reused across more than one distinct service.</summary>
    [Description("Only include endpoints where the same certificate is reused across more than one distinct service.")]
    [CommandOption("--reuse-cross-service-only")]
    public bool ReuseCrossServiceOnly { get; set; }

    /// <summary>Only include endpoints where the same certificate is reused within a single distinct service.</summary>
    [Description("Only include endpoints where the same certificate is reused within a single distinct service.")]
    [CommandOption("--reuse-single-service-only")]
    public bool ReuseSingleServiceOnly { get; set; }

    /// <summary>Optional minimum certificate-reuse distinct-service-count filter (1 or greater).</summary>
    [Description("Optional minimum certificate-reuse distinct-service-count filter (1 or greater).")]
    [CommandOption("--reuse-service-min <N>")]
    public int? ReuseServiceCountMin { get; set; }

    /// <summary>Optional maximum certificate-reuse distinct-service-count filter (1 or greater).</summary>
    [Description("Optional maximum certificate-reuse distinct-service-count filter (1 or greater).")]
    [CommandOption("--reuse-service-max <N>")]
    public int? ReuseServiceCountMax { get; set; }

    /// <summary>Optional minimum certificate-reuse distinct-port-count filter (1 or greater).</summary>
    [Description("Optional minimum certificate-reuse distinct-port-count filter (1 or greater).")]
    [CommandOption("--reuse-port-min <N>")]
    public int? ReusePortCountMin { get; set; }

    /// <summary>Optional maximum certificate-reuse distinct-port-count filter (1 or greater).</summary>
    [Description("Optional maximum certificate-reuse distinct-port-count filter (1 or greater).")]
    [CommandOption("--reuse-port-max <N>")]
    public int? ReusePortCountMax { get; set; }

    /// <summary>Only include endpoints where the same certificate is reused across more than one distinct port.</summary>
    [Description("Only include endpoints where the same certificate is reused across more than one distinct port.")]
    [CommandOption("--reuse-cross-port-only")]
    public bool ReuseCrossPortOnly { get; set; }

    /// <summary>Only include endpoints where the same certificate is reused within a single distinct port.</summary>
    [Description("Only include endpoints where the same certificate is reused within a single distinct port.")]
    [CommandOption("--reuse-single-port-only")]
    public bool ReuseSinglePortOnly { get; set; }

    /// <summary>Optional risk profile preset (Renewal14d, Renewal30d, FutureNotYetValid, Expired, HighRiskActive).</summary>
    [Description("Optional risk profile preset (Renewal14d, Renewal30d, FutureNotYetValid, Expired, HighRiskActive).")]
    [CommandOption("--risk-profile <NAME>")]
    public string? RiskProfile { get; set; }

    /// <summary>Optional case-insensitive reason substring filter (for example CertificateExpired, WeakKey, CtNotObserved).</summary>
    [Description("Optional case-insensitive reason substring filter (for example CertificateExpired, WeakKey, CtNotObserved).")]
    [CommandOption("--reason-contains <TEXT>")]
    public string? ReasonContains { get; set; }

    /// <summary>Optional exact reason filters where any value can match (repeat option).</summary>
    [Description("Optional exact reason filters where any value can match (repeat option). Example: CertificateExpired, WeakKey, CtNotObserved.")]
    [CommandOption("--reason-any <REASON>")]
    public string[]? ReasonAnyOf { get; set; }

    /// <summary>Optional exact reason filters where all values must match (repeat option).</summary>
    [Description("Optional exact reason filters where all values must match (repeat option). Example: CertificateExpired, WeakKey.")]
    [CommandOption("--reason-all <REASON>")]
    public string[]? ReasonAllOf { get; set; }

    /// <summary>Optional case-insensitive issuer/root-issuer substring filter (for example DigiCert, Let's Encrypt, ISRG).</summary>
    [Description("Optional case-insensitive issuer/root-issuer substring filter (for example DigiCert, Let's Encrypt, ISRG).")]
    [CommandOption("--issuer-contains <TEXT>")]
    public string? IssuerContains { get; set; }

    /// <summary>Optional case-insensitive issuer/root-issuer substring filters where any value can match (repeat option).</summary>
    [Description("Optional case-insensitive issuer/root-issuer substring filters where any value can match (repeat option).")]
    [CommandOption("--issuer-any <TEXT>")]
    public string[]? IssuerContainsAnyOf { get; set; }

    /// <summary>Optional case-insensitive issuer/root-issuer substring filters where all values must match (repeat option).</summary>
    [Description("Optional case-insensitive issuer/root-issuer substring filters where all values must match (repeat option).")]
    [CommandOption("--issuer-all <TEXT>")]
    public string[]? IssuerContainsAllOf { get; set; }

    /// <summary>Optional case-insensitive root-issuer substring filter.</summary>
    [Description("Optional case-insensitive root-issuer substring filter (for example ISRG Root, DigiCert Global Root).")]
    [CommandOption("--root-issuer-contains <TEXT>")]
    public string? RootIssuerContains { get; set; }

    /// <summary>Optional case-insensitive root-issuer substring filters where any value can match (repeat option).</summary>
    [Description("Optional case-insensitive root-issuer substring filters where any value can match (repeat option).")]
    [CommandOption("--root-issuer-any <TEXT>")]
    public string[]? RootIssuerContainsAnyOf { get; set; }

    /// <summary>Optional case-insensitive root-issuer substring filters where all values must match (repeat option).</summary>
    [Description("Optional case-insensitive root-issuer substring filters where all values must match (repeat option).")]
    [CommandOption("--root-issuer-all <TEXT>")]
    public string[]? RootIssuerContainsAllOf { get; set; }

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

    /// <summary>Only include endpoints whose observed chain length is greater than or equal to this value.</summary>
    [Description("Only include endpoints whose observed chain length is greater than or equal to this value.")]
    [CommandOption("--chain-length-min <N>")]
    public int? ChainLengthMin { get; set; }

    /// <summary>Only include endpoints whose observed chain length is less than or equal to this value.</summary>
    [Description("Only include endpoints whose observed chain length is less than or equal to this value.")]
    [CommandOption("--chain-length-max <N>")]
    public int? ChainLengthMax { get; set; }

    /// <summary>Only include endpoints whose observed intermediate count is greater than or equal to this value.</summary>
    [Description("Only include endpoints whose observed intermediate count is greater than or equal to this value.")]
    [CommandOption("--intermediate-count-min <N>")]
    public int? IntermediateCountMin { get; set; }

    /// <summary>Only include endpoints whose observed intermediate count is less than or equal to this value.</summary>
    [Description("Only include endpoints whose observed intermediate count is less than or equal to this value.")]
    [CommandOption("--intermediate-count-max <N>")]
    public int? IntermediateCountMax { get; set; }

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

    /// <summary>Only include endpoints with expired certificates.</summary>
    [Description("Only include endpoints with expired certificates.")]
    [CommandOption("--expired-only")]
    public bool ExpiredOnly { get; set; }

    /// <summary>Only include endpoints with non-expired certificates.</summary>
    [Description("Only include endpoints with non-expired certificates.")]
    [CommandOption("--not-expired-only")]
    public bool NotExpiredOnly { get; set; }

    /// <summary>Only include endpoints with certificates that are not yet valid.</summary>
    [Description("Only include endpoints with certificates that are not yet valid.")]
    [CommandOption("--not-yet-valid-only")]
    public bool NotYetValidOnly { get; set; }

    /// <summary>Only include endpoints with certificates that are already valid (not in future).</summary>
    [Description("Only include endpoints with certificates that are already valid (not in future).")]
    [CommandOption("--already-valid-only")]
    public bool AlreadyValidOnly { get; set; }

    /// <summary>Only include endpoints currently within certificate validity window.</summary>
    [Description("Only include endpoints currently within certificate validity window.")]
    [CommandOption("--currently-valid-only")]
    public bool CurrentlyValidOnly { get; set; }

    /// <summary>Only include endpoints currently outside certificate validity window.</summary>
    [Description("Only include endpoints currently outside certificate validity window.")]
    [CommandOption("--currently-invalid-only")]
    public bool CurrentlyInvalidOnly { get; set; }

    /// <summary>Only include endpoints whose days-to-expire is greater than or equal to this value.</summary>
    [Description("Only include endpoints whose days-to-expire is greater than or equal to this value.")]
    [CommandOption("--days-to-expire-min <N>")]
    public int? DaysToExpireMin { get; set; }

    /// <summary>Only include endpoints whose days-to-expire is less than or equal to this value.</summary>
    [Description("Only include endpoints whose days-to-expire is less than or equal to this value.")]
    [CommandOption("--days-to-expire-max <N>")]
    public int? DaysToExpireMax { get; set; }

    /// <summary>Only include endpoints whose days-until-valid is greater than or equal to this value.</summary>
    [Description("Only include endpoints whose days-until-valid is greater than or equal to this value.")]
    [CommandOption("--days-until-valid-min <N>")]
    public int? DaysUntilValidMin { get; set; }

    /// <summary>Only include endpoints whose days-until-valid is less than or equal to this value.</summary>
    [Description("Only include endpoints whose days-until-valid is less than or equal to this value.")]
    [CommandOption("--days-until-valid-max <N>")]
    public int? DaysUntilValidMax { get; set; }

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
        if (settings.ScoreMin.HasValue && (settings.ScoreMin.Value < 0 || settings.ScoreMin.Value > 100)) {
            AnsiConsole.MarkupLine("[red]--score-min must be between 0 and 100.[/]");
            return Task.FromResult(1);
        }
        if (settings.ScoreMax.HasValue && (settings.ScoreMax.Value < 0 || settings.ScoreMax.Value > 100)) {
            AnsiConsole.MarkupLine("[red]--score-max must be between 0 and 100.[/]");
            return Task.FromResult(1);
        }
        if (settings.ScoreMin.HasValue && settings.ScoreMax.HasValue && settings.ScoreMin.Value > settings.ScoreMax.Value) {
            AnsiConsole.MarkupLine("[red]--score-min cannot be greater than --score-max.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReasonCountMin.HasValue && settings.ReasonCountMin.Value < 0) {
            AnsiConsole.MarkupLine("[red]--reason-count-min must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReasonCountMax.HasValue && settings.ReasonCountMax.Value < 0) {
            AnsiConsole.MarkupLine("[red]--reason-count-max must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReasonCountMin.HasValue && settings.ReasonCountMax.HasValue && settings.ReasonCountMin.Value > settings.ReasonCountMax.Value) {
            AnsiConsole.MarkupLine("[red]--reason-count-min cannot be greater than --reason-count-max.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReuseEndpointCountMin.HasValue && settings.ReuseEndpointCountMin.Value < 1) {
            AnsiConsole.MarkupLine("[red]--reuse-endpoint-min must be 1 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReuseEndpointCountMax.HasValue && settings.ReuseEndpointCountMax.Value < 1) {
            AnsiConsole.MarkupLine("[red]--reuse-endpoint-max must be 1 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReuseEndpointCountMin.HasValue && settings.ReuseEndpointCountMax.HasValue && settings.ReuseEndpointCountMin.Value > settings.ReuseEndpointCountMax.Value) {
            AnsiConsole.MarkupLine("[red]--reuse-endpoint-min cannot be greater than --reuse-endpoint-max.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReuseCrossServiceOnly && settings.ReuseSingleServiceOnly) {
            AnsiConsole.MarkupLine("[red]--reuse-cross-service-only cannot be combined with --reuse-single-service-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReuseServiceCountMin.HasValue && settings.ReuseServiceCountMin.Value < 1) {
            AnsiConsole.MarkupLine("[red]--reuse-service-min must be 1 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReuseServiceCountMax.HasValue && settings.ReuseServiceCountMax.Value < 1) {
            AnsiConsole.MarkupLine("[red]--reuse-service-max must be 1 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReuseServiceCountMin.HasValue && settings.ReuseServiceCountMax.HasValue && settings.ReuseServiceCountMin.Value > settings.ReuseServiceCountMax.Value) {
            AnsiConsole.MarkupLine("[red]--reuse-service-min cannot be greater than --reuse-service-max.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReusePortCountMin.HasValue && settings.ReusePortCountMin.Value < 1) {
            AnsiConsole.MarkupLine("[red]--reuse-port-min must be 1 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReusePortCountMax.HasValue && settings.ReusePortCountMax.Value < 1) {
            AnsiConsole.MarkupLine("[red]--reuse-port-max must be 1 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReusePortCountMin.HasValue && settings.ReusePortCountMax.HasValue && settings.ReusePortCountMin.Value > settings.ReusePortCountMax.Value) {
            AnsiConsole.MarkupLine("[red]--reuse-port-min cannot be greater than --reuse-port-max.[/]");
            return Task.FromResult(1);
        }
        if (settings.ReuseCrossPortOnly && settings.ReuseSinglePortOnly) {
            AnsiConsole.MarkupLine("[red]--reuse-cross-port-only cannot be combined with --reuse-single-port-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.ChainLengthMin.HasValue && settings.ChainLengthMin.Value < 0) {
            AnsiConsole.MarkupLine("[red]--chain-length-min must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ChainLengthMax.HasValue && settings.ChainLengthMax.Value < 0) {
            AnsiConsole.MarkupLine("[red]--chain-length-max must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.ChainLengthMin.HasValue && settings.ChainLengthMax.HasValue && settings.ChainLengthMin.Value > settings.ChainLengthMax.Value) {
            AnsiConsole.MarkupLine("[red]--chain-length-min cannot be greater than --chain-length-max.[/]");
            return Task.FromResult(1);
        }
        if (settings.IntermediateCountMin.HasValue && settings.IntermediateCountMin.Value < 0) {
            AnsiConsole.MarkupLine("[red]--intermediate-count-min must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.IntermediateCountMax.HasValue && settings.IntermediateCountMax.Value < 0) {
            AnsiConsole.MarkupLine("[red]--intermediate-count-max must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.IntermediateCountMin.HasValue && settings.IntermediateCountMax.HasValue && settings.IntermediateCountMin.Value > settings.IntermediateCountMax.Value) {
            AnsiConsole.MarkupLine("[red]--intermediate-count-min cannot be greater than --intermediate-count-max.[/]");
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
        if (settings.ExpiredOnly && settings.NotExpiredOnly) {
            AnsiConsole.MarkupLine("[red]--expired-only cannot be combined with --not-expired-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.NotYetValidOnly && settings.AlreadyValidOnly) {
            AnsiConsole.MarkupLine("[red]--not-yet-valid-only cannot be combined with --already-valid-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.CurrentlyValidOnly && settings.CurrentlyInvalidOnly) {
            AnsiConsole.MarkupLine("[red]--currently-valid-only cannot be combined with --currently-invalid-only.[/]");
            return Task.FromResult(1);
        }
        if (settings.DaysToExpireMin.HasValue && settings.DaysToExpireMax.HasValue && settings.DaysToExpireMin.Value > settings.DaysToExpireMax.Value) {
            AnsiConsole.MarkupLine("[red]--days-to-expire-min cannot be greater than --days-to-expire-max.[/]");
            return Task.FromResult(1);
        }
        if (settings.DaysUntilValidMin.HasValue && settings.DaysUntilValidMin.Value < 0) {
            AnsiConsole.MarkupLine("[red]--days-until-valid-min must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.DaysUntilValidMax.HasValue && settings.DaysUntilValidMax.Value < 0) {
            AnsiConsole.MarkupLine("[red]--days-until-valid-max must be 0 or greater.[/]");
            return Task.FromResult(1);
        }
        if (settings.DaysUntilValidMin.HasValue && settings.DaysUntilValidMax.HasValue && settings.DaysUntilValidMin.Value > settings.DaysUntilValidMax.Value) {
            AnsiConsole.MarkupLine("[red]--days-until-valid-min cannot be greater than --days-until-valid-max.[/]");
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
        var normalizedRiskProfile = settings.RiskProfile;
        if (!string.IsNullOrWhiteSpace(settings.RiskProfile)) {
            if (!CertificateInventoryRiskAnalyzer.TryResolveRiskProfile(settings.RiskProfile, out var normalized)) {
                AnsiConsole.MarkupLine($"[red]--risk-profile must be one of: {CertificateInventoryRiskAnalyzer.RiskProfileAcceptedValues}.[/]");
                return Task.FromResult(1);
            }

            normalizedRiskProfile = normalized;
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
            scoreMin: settings.ScoreMin,
            scoreMax: settings.ScoreMax,
            reasonCountMin: settings.ReasonCountMin,
            reasonCountMax: settings.ReasonCountMax,
            certificateReuseEndpointCountMin: settings.ReuseEndpointCountMin,
            certificateReuseEndpointCountMax: settings.ReuseEndpointCountMax,
            certificateReuseCrossServiceOnly: settings.ReuseCrossServiceOnly ? true : settings.ReuseSingleServiceOnly ? false : null,
            certificateReuseDistinctServiceCountMin: settings.ReuseServiceCountMin,
            certificateReuseDistinctServiceCountMax: settings.ReuseServiceCountMax,
            certificateReuseDistinctPortCountMin: settings.ReusePortCountMin,
            certificateReuseDistinctPortCountMax: settings.ReusePortCountMax,
            certificateReuseCrossPortOnly: settings.ReuseCrossPortOnly ? true : settings.ReuseSinglePortOnly ? false : null,
            riskProfile: normalizedRiskProfile,
            reasonContains: settings.ReasonContains,
            reasonAnyOf: settings.ReasonAnyOf,
            reasonAllOf: settings.ReasonAllOf,
            issuerContains: settings.IssuerContains,
            issuerContainsAnyOf: settings.IssuerContainsAnyOf,
            issuerContainsAllOf: settings.IssuerContainsAllOf,
            rootIssuerContains: settings.RootIssuerContains,
            rootIssuerContainsAnyOf: settings.RootIssuerContainsAnyOf,
            rootIssuerContainsAllOf: settings.RootIssuerContainsAllOf,
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
            chainLengthMin: settings.ChainLengthMin,
            chainLengthMax: settings.ChainLengthMax,
            intermediateCountMin: settings.IntermediateCountMin,
            intermediateCountMax: settings.IntermediateCountMax,
            ctObservedOnly: settings.CtObservedOnly ? true : settings.CtMissingOnly ? false : null,
            chainCompleteOnly: settings.ChainCompleteOnly ? true : settings.ChainIncompleteOnly ? false : null,
            reachableOnly: settings.ReachableOnly ? true : settings.UnreachableOnly ? false : null,
            hostnameMatchOnly: settings.HostnameMatchOnly ? true : settings.HostnameMismatchOnly ? false : null,
            selfSignedOnly: settings.SelfSignedOnly ? true : settings.CaSignedOnly ? false : null,
            weakKeyOnly: settings.WeakKeyOnly ? true : settings.StrongKeyOnly ? false : null,
            sha1SignatureOnly: settings.Sha1SignatureOnly ? true : settings.NonSha1SignatureOnly ? false : null,
            expiredOnly: settings.ExpiredOnly ? true : settings.NotExpiredOnly ? false : null,
            notYetValidOnly: settings.NotYetValidOnly ? true : settings.AlreadyValidOnly ? false : null,
            currentlyValidOnly: settings.CurrentlyValidOnly ? true : settings.CurrentlyInvalidOnly ? false : null,
            daysToExpireMin: settings.DaysToExpireMin,
            daysToExpireMax: settings.DaysToExpireMax,
            daysUntilValidMin: settings.DaysUntilValidMin,
            daysUntilValidMax: settings.DaysUntilValidMax,
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
        rows.AddColumn("Reuse");
        rows.AddColumn("Chain");
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

            var chain = endpoint.ChainLength > 0
                ? $"{endpoint.ChainLength}/{endpoint.IntermediateCount}"
                : "-";
            var reuse = $"{endpoint.CertificateReuseEndpointCount}ep/{endpoint.CertificateReuseDistinctServiceCount}svc/{endpoint.CertificateReuseDistinctPortCount}prt";
            var auth = BuildAuthSummary(endpoint);
            var reasons = endpoint.Reasons.Count > 0 ? string.Join(",", endpoint.Reasons) : "-";
            rows.AddRow(
                endpoint.Host,
                endpoint.Port.ToString(),
                endpoint.Service,
                reuse,
                chain,
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
