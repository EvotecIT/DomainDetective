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

    /// <summary>Optional risk profile preset (Renewal14d, Renewal30d, FutureNotYetValid, Expired, HighRiskActive).</summary>
    [Parameter(Mandatory = false)]
    [ValidateSet("Renewal14d", "Renewal30d", "FutureNotYetValid", "Expired", "HighRiskActive")]
    public string? RiskProfile { get; set; }

    /// <summary>Optional case-insensitive reason substring filter (for example CertificateExpired, WeakKey, CtNotObserved).</summary>
    [Parameter(Mandatory = false)]
    public string? ReasonContains { get; set; }

    /// <summary>Optional exact reason filters where any value can match.</summary>
    [Parameter(Mandatory = false)]
    public string[]? ReasonAnyOf { get; set; }

    /// <summary>Optional exact reason filters where all values must match.</summary>
    [Parameter(Mandatory = false)]
    public string[]? ReasonAllOf { get; set; }

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

    /// <summary>Optional case-insensitive host substring filter.</summary>
    [Parameter(Mandatory = false)]
    public string? HostContains { get; set; }

    /// <summary>Optional case-insensitive service exact-match filter (for example HTTPS, HTTPS-Alt, Custom TLS).</summary>
    [Parameter(Mandatory = false)]
    public string? ServiceEquals { get; set; }

    /// <summary>Optional endpoint port exact-match filter (1-65535).</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(1, 65535)]
    public int? PortEquals { get; set; }

    /// <summary>Only include endpoints whose certificates were observed in CT logs.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter CtObservedOnly { get; set; }

    /// <summary>Only include endpoints whose certificates were not observed in CT logs.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter CtMissingOnly { get; set; }

    /// <summary>Only include endpoints with complete certificate chains.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter ChainCompleteOnly { get; set; }

    /// <summary>Only include endpoints with incomplete certificate chains.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter ChainIncompleteOnly { get; set; }

    /// <summary>Only include endpoints reachable on the scanned endpoint.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter ReachableOnly { get; set; }

    /// <summary>Only include endpoints that were not reachable on the scanned endpoint.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter UnreachableOnly { get; set; }

    /// <summary>Only include endpoints whose certificate matches the requested hostname.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter HostnameMatchOnly { get; set; }

    /// <summary>Only include endpoints whose certificate does not match the requested hostname.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter HostnameMismatchOnly { get; set; }

    /// <summary>Only include endpoints using self-signed certificates.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter SelfSignedOnly { get; set; }

    /// <summary>Only include endpoints using CA-signed certificates.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter CaSignedOnly { get; set; }

    /// <summary>Only include endpoints with weak keys.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter WeakKeyOnly { get; set; }

    /// <summary>Only include endpoints without weak keys.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter StrongKeyOnly { get; set; }

    /// <summary>Only include endpoints using SHA-1 signatures.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter Sha1SignatureOnly { get; set; }

    /// <summary>Only include endpoints not using SHA-1 signatures.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter NonSha1SignatureOnly { get; set; }

    /// <summary>Only include endpoints with expired certificates.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter ExpiredOnly { get; set; }

    /// <summary>Only include endpoints with non-expired certificates.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter NotExpiredOnly { get; set; }

    /// <summary>Only include endpoints with certificates that are not yet valid.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter NotYetValidOnly { get; set; }

    /// <summary>Only include endpoints with certificates that are already valid (not in future).</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter AlreadyValidOnly { get; set; }

    /// <summary>Only include endpoints currently within certificate validity window.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter CurrentlyValidOnly { get; set; }

    /// <summary>Only include endpoints currently outside certificate validity window.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter CurrentlyInvalidOnly { get; set; }

    /// <summary>Only include endpoints whose days-to-expire is greater than or equal to this value.</summary>
    [Parameter(Mandatory = false)]
    public int? DaysToExpireMin { get; set; }

    /// <summary>Only include endpoints whose days-to-expire is less than or equal to this value.</summary>
    [Parameter(Mandatory = false)]
    public int? DaysToExpireMax { get; set; }

    /// <summary>Only include endpoints whose days-until-valid is greater than or equal to this value.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? DaysUntilValidMin { get; set; }

    /// <summary>Only include endpoints whose days-until-valid is less than or equal to this value.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? DaysUntilValidMax { get; set; }

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
        if (CtObservedOnly.IsPresent && CtMissingOnly.IsPresent) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-CtObservedOnly cannot be combined with -CtMissingOnly.", nameof(CtMissingOnly)),
                "CtObservationConflict",
                ErrorCategory.InvalidArgument,
                CtMissingOnly));
            return;
        }
        if (ChainCompleteOnly.IsPresent && ChainIncompleteOnly.IsPresent) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-ChainCompleteOnly cannot be combined with -ChainIncompleteOnly.", nameof(ChainIncompleteOnly)),
                "ChainCompletenessConflict",
                ErrorCategory.InvalidArgument,
                ChainIncompleteOnly));
            return;
        }
        if (ReachableOnly.IsPresent && UnreachableOnly.IsPresent) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-ReachableOnly cannot be combined with -UnreachableOnly.", nameof(UnreachableOnly)),
                "ReachabilityConflict",
                ErrorCategory.InvalidArgument,
                UnreachableOnly));
            return;
        }
        if (HostnameMatchOnly.IsPresent && HostnameMismatchOnly.IsPresent) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-HostnameMatchOnly cannot be combined with -HostnameMismatchOnly.", nameof(HostnameMismatchOnly)),
                "HostnameValidationConflict",
                ErrorCategory.InvalidArgument,
                HostnameMismatchOnly));
            return;
        }
        if (SelfSignedOnly.IsPresent && CaSignedOnly.IsPresent) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-SelfSignedOnly cannot be combined with -CaSignedOnly.", nameof(CaSignedOnly)),
                "SelfSignedConflict",
                ErrorCategory.InvalidArgument,
                CaSignedOnly));
            return;
        }
        if (WeakKeyOnly.IsPresent && StrongKeyOnly.IsPresent) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-WeakKeyOnly cannot be combined with -StrongKeyOnly.", nameof(StrongKeyOnly)),
                "WeakKeyConflict",
                ErrorCategory.InvalidArgument,
                StrongKeyOnly));
            return;
        }
        if (Sha1SignatureOnly.IsPresent && NonSha1SignatureOnly.IsPresent) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-Sha1SignatureOnly cannot be combined with -NonSha1SignatureOnly.", nameof(NonSha1SignatureOnly)),
                "Sha1SignatureConflict",
                ErrorCategory.InvalidArgument,
                NonSha1SignatureOnly));
            return;
        }
        if (ExpiredOnly.IsPresent && NotExpiredOnly.IsPresent) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-ExpiredOnly cannot be combined with -NotExpiredOnly.", nameof(NotExpiredOnly)),
                "ExpiryStateConflict",
                ErrorCategory.InvalidArgument,
                NotExpiredOnly));
            return;
        }
        if (NotYetValidOnly.IsPresent && AlreadyValidOnly.IsPresent) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-NotYetValidOnly cannot be combined with -AlreadyValidOnly.", nameof(AlreadyValidOnly)),
                "NotYetValidStateConflict",
                ErrorCategory.InvalidArgument,
                AlreadyValidOnly));
            return;
        }
        if (CurrentlyValidOnly.IsPresent && CurrentlyInvalidOnly.IsPresent) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-CurrentlyValidOnly cannot be combined with -CurrentlyInvalidOnly.", nameof(CurrentlyInvalidOnly)),
                "CurrentValidityStateConflict",
                ErrorCategory.InvalidArgument,
                CurrentlyInvalidOnly));
            return;
        }
        if (DaysToExpireMin.HasValue && DaysToExpireMax.HasValue && DaysToExpireMin.Value > DaysToExpireMax.Value) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-DaysToExpireMin cannot be greater than -DaysToExpireMax.", nameof(DaysToExpireMin)),
                "DaysToExpireRangeConflict",
                ErrorCategory.InvalidArgument,
                DaysToExpireMin));
            return;
        }
        if (DaysUntilValidMin.HasValue && DaysUntilValidMax.HasValue && DaysUntilValidMin.Value > DaysUntilValidMax.Value) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-DaysUntilValidMin cannot be greater than -DaysUntilValidMax.", nameof(DaysUntilValidMin)),
                "DaysUntilValidRangeConflict",
                ErrorCategory.InvalidArgument,
                DaysUntilValidMin));
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
            riskProfile: RiskProfile,
            reasonContains: ReasonContains,
            reasonAnyOf: ReasonAnyOf,
            reasonAllOf: ReasonAllOf,
            issuerContains: IssuerContains,
            authorityFamilyEquals: AuthorityFamilyEquals,
            rootAuthorityFamilyEquals: RootAuthorityFamilyEquals,
            ctSourceContains: CtSourceContains,
            ctTemplateErrorContains: CtTemplateErrorContains,
            chainSourceContains: ChainSourceContains,
            thumbprintEquals: ThumbprintEquals,
            rootThumbprintEquals: RootThumbprintEquals,
            serialNumberEquals: SerialNumberEquals,
            hostContains: HostContains,
            serviceEquals: ServiceEquals,
            portEquals: PortEquals,
            ctObservedOnly: CtObservedOnly.IsPresent ? true : CtMissingOnly.IsPresent ? false : null,
            chainCompleteOnly: ChainCompleteOnly.IsPresent ? true : ChainIncompleteOnly.IsPresent ? false : null,
            reachableOnly: ReachableOnly.IsPresent ? true : UnreachableOnly.IsPresent ? false : null,
            hostnameMatchOnly: HostnameMatchOnly.IsPresent ? true : HostnameMismatchOnly.IsPresent ? false : null,
            selfSignedOnly: SelfSignedOnly.IsPresent ? true : CaSignedOnly.IsPresent ? false : null,
            weakKeyOnly: WeakKeyOnly.IsPresent ? true : StrongKeyOnly.IsPresent ? false : null,
            sha1SignatureOnly: Sha1SignatureOnly.IsPresent ? true : NonSha1SignatureOnly.IsPresent ? false : null,
            expiredOnly: ExpiredOnly.IsPresent ? true : NotExpiredOnly.IsPresent ? false : null,
            notYetValidOnly: NotYetValidOnly.IsPresent ? true : AlreadyValidOnly.IsPresent ? false : null,
            currentlyValidOnly: CurrentlyValidOnly.IsPresent ? true : CurrentlyInvalidOnly.IsPresent ? false : null,
            daysToExpireMin: DaysToExpireMin,
            daysToExpireMax: DaysToExpireMax,
            daysUntilValidMin: DaysUntilValidMin,
            daysUntilValidMax: DaysUntilValidMax,
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
