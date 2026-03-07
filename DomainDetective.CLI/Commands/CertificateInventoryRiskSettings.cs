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

    /// <summary>Optional NDJSON output path for endpoint risk rows (one JSON object per line).</summary>
    [Description("Optional NDJSON output path for endpoint risk rows (one JSON object per line).")]
    [CommandOption("--ndjson-path <PATH>")]
    public string? NdjsonPath { get; set; }

    /// <summary>Optional CSV output path for endpoint risk rows.</summary>
    [Description("Optional CSV output path for endpoint risk rows.")]
    [CommandOption("--csv-path <PATH>")]
    public string? CsvPath { get; set; }
}
