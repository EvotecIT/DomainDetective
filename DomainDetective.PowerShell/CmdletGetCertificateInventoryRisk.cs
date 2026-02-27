using System;
using System.IO;
using System.Management.Automation;

namespace DomainDetective.PowerShell;

/// <summary>Builds endpoint-level certificate risk posture from persisted inventory snapshots.</summary>
/// <para>Scores endpoint certificate exposure, classifies severity, and returns top risk reasons to prioritize remediation.</para>
/// <example>
///   <summary>Assess risk posture for snapshots captured in the last 30 days</summary>
///   <code>Get-DDCertificateInventoryRisk -SinceUtc (Get-Date).ToUniversalTime().AddDays(-30)</code>
/// </example>
/// <example>
///   <summary>Include healthy endpoints and tune expiry thresholds</summary>
///   <code>Get-DDCertificateInventoryRisk -IncludeHealthy -ExpiringWithinDays 45 -CriticalExpiringWithinDays 10</code>
/// </example>
/// <example>
///   <summary>Return only high and critical endpoint rows</summary>
///   <code>Get-DDCertificateInventoryRisk -MinimumSeverity High</code>
/// </example>
[Cmdlet(VerbsCommon.Get, "DDCertificateInventoryRisk")]
[Alias("Get-CertificateInventoryRisk")]
[OutputType(typeof(CertificateInventoryRiskSummary))]
public sealed class CmdletGetCertificateInventoryRisk : PSCmdlet {
    /// <summary>Certificate monitor cache directory containing the inventory folder.</summary>
    [Parameter(Mandatory = false)]
    public string? CacheDirectory { get; set; }

    /// <summary>Only include snapshots captured since this UTC date/time.</summary>
    [Parameter(Mandatory = false)]
    public DateTime? SinceUtc { get; set; }

    /// <summary>Include endpoints without detected risk findings.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter IncludeHealthy { get; set; }

    /// <summary>Warning threshold window in days for expiring certificates.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int ExpiringWithinDays { get; set; } = 30;

    /// <summary>Critical threshold window in days for expiring certificates.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int CriticalExpiringWithinDays { get; set; } = 7;

    /// <summary>Maximum endpoint rows returned.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int MaxEndpoints { get; set; } = 300;

    /// <summary>Optional minimum severity filter (None means no additional score filter).</summary>
    [Parameter(Mandatory = false)]
    [ValidateSet("None", "Low", "Medium", "High", "Critical")]
    public string? MinimumSeverity { get; set; }

    /// <summary>Optional case-insensitive reason substring filter (for example CertificateExpired, WeakKey, CtNotObserved).</summary>
    [Parameter(Mandatory = false)]
    public string? ReasonContains { get; set; }

    /// <summary>Optional case-insensitive issuer/root-issuer substring filter (for example DigiCert, Let's Encrypt, ISRG).</summary>
    [Parameter(Mandatory = false)]
    public string? IssuerContains { get; set; }

    /// <summary>Optional leaf authority family exact-match filter (for example DigiCert, LetsEncrypt).</summary>
    [Parameter(Mandatory = false)]
    public string? AuthorityFamilyEquals { get; set; }

    /// <summary>Optional root authority family exact-match filter (for example DigiCert, LetsEncrypt).</summary>
    [Parameter(Mandatory = false)]
    public string? RootAuthorityFamilyEquals { get; set; }

    /// <summary>Optional CT/discovery source substring filter (for example crt.sh, shodan, censys).</summary>
    [Parameter(Mandatory = false)]
    public string? CtSourceContains { get; set; }

    /// <summary>Optional CT template/configuration error substring filter.</summary>
    [Parameter(Mandatory = false)]
    public string? CtTemplateErrorContains { get; set; }

    /// <summary>Optional chain-source substring filter (for example tls-handshake, aia-download).</summary>
    [Parameter(Mandatory = false)]
    public string? ChainSourceContains { get; set; }

    /// <summary>Optional leaf-certificate thumbprint exact-match filter (hex string expected).</summary>
    [Parameter(Mandatory = false)]
    public string? ThumbprintEquals { get; set; }

    /// <summary>Optional root-certificate thumbprint exact-match filter (hex string expected).</summary>
    [Parameter(Mandatory = false)]
    public string? RootThumbprintEquals { get; set; }

    /// <summary>Optional leaf-certificate serial-number exact-match filter (hex string expected).</summary>
    [Parameter(Mandatory = false)]
    public string? SerialNumberEquals { get; set; }

    /// <summary>Optional authentication profile exact-match filter (for example ServerAuthOnly, ClientAuthOnly, MixedOrCustom).</summary>
    [Parameter(Mandatory = false)]
    public string? AuthenticationProfileEquals { get; set; }

    /// <summary>Only include endpoints with recognized public CAs as the leaf issuer.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter KnownCaOnly { get; set; }

    /// <summary>Only include endpoints with unrecognized/private CAs as the leaf issuer.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter UnknownCaOnly { get; set; }

    /// <summary>Only include endpoints chaining to recognized public root CAs.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter KnownRootCaOnly { get; set; }

    /// <summary>Only include endpoints chaining to unrecognized/private root CAs.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter UnknownRootCaOnly { get; set; }

    /// <summary>Only include endpoints whose certificate allows server authentication EKU.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter ServerAuthOnly { get; set; }

    /// <summary>Only include endpoints whose certificate allows client authentication EKU.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter ClientAuthOnly { get; set; }

    /// <summary>Only include endpoints whose certificate allows secure-email EKU.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter SecureEmailOnly { get; set; }

    /// <summary>Executes the cmdlet.</summary>
    protected override void ProcessRecord() {
        if (CriticalExpiringWithinDays > ExpiringWithinDays) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-CriticalExpiringWithinDays cannot be greater than -ExpiringWithinDays.", nameof(CriticalExpiringWithinDays)),
                "CriticalExpiringWindowTooLarge",
                ErrorCategory.InvalidArgument,
                CriticalExpiringWithinDays));
            return;
        }
        if (KnownCaOnly.IsPresent && UnknownCaOnly.IsPresent) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-KnownCaOnly cannot be combined with -UnknownCaOnly.", nameof(UnknownCaOnly)),
                "KnownAndUnknownCaConflict",
                ErrorCategory.InvalidArgument,
                UnknownCaOnly));
            return;
        }
        if (KnownRootCaOnly.IsPresent && UnknownRootCaOnly.IsPresent) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-KnownRootCaOnly cannot be combined with -UnknownRootCaOnly.", nameof(UnknownRootCaOnly)),
                "KnownAndUnknownRootCaConflict",
                ErrorCategory.InvalidArgument,
                UnknownRootCaOnly));
            return;
        }

        var monitor = new CertificateMonitor {
            CacheDirectory = ResolveCacheDirectory(CacheDirectory),
            PersistInventorySnapshots = false
        };

        DateTimeOffset? since = null;
        if (SinceUtc.HasValue) {
            since = new DateTimeOffset(DateTime.SpecifyKind(SinceUtc.Value, DateTimeKind.Utc));
        }

        var risk = monitor.BuildInventoryRisk(
            sinceUtc: since,
            includeNoRisk: IncludeHealthy.IsPresent,
            expiringWithinDays: ExpiringWithinDays,
            criticalExpiringWithinDays: CriticalExpiringWithinDays,
            maxEndpoints: MaxEndpoints,
            minimumSeverity: MinimumSeverity,
            reasonContains: ReasonContains,
            issuerContains: IssuerContains,
            authorityFamilyEquals: AuthorityFamilyEquals,
            rootAuthorityFamilyEquals: RootAuthorityFamilyEquals,
            ctSourceContains: CtSourceContains,
            ctTemplateErrorContains: CtTemplateErrorContains,
            chainSourceContains: ChainSourceContains,
            thumbprintEquals: ThumbprintEquals,
            rootThumbprintEquals: RootThumbprintEquals,
            serialNumberEquals: SerialNumberEquals,
            knownAuthorityOnly: KnownCaOnly.IsPresent ? true : UnknownCaOnly.IsPresent ? false : null,
            knownRootAuthorityOnly: KnownRootCaOnly.IsPresent ? true : UnknownRootCaOnly.IsPresent ? false : null,
            authenticationProfileEquals: AuthenticationProfileEquals,
            serverAuthOnly: ServerAuthOnly.IsPresent,
            clientAuthOnly: ClientAuthOnly.IsPresent,
            secureEmailOnly: SecureEmailOnly.IsPresent);
        WriteObject(risk);
    }

    private static string ResolveCacheDirectory(string? configured) {
        if (!string.IsNullOrWhiteSpace(configured)) {
            return configured!;
        }

        return Path.Combine(Path.GetTempPath(), "DomainDetective", "cert-monitor");
    }
}
