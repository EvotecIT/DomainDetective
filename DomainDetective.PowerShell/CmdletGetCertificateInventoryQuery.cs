using System;
using System.Management.Automation;

namespace DomainDetective.PowerShell;

/// <summary>Queries persisted certificate inventory snapshots using structured filters.</summary>
/// <para>Returns matched inventory entries with snapshot capture times and counters for scanned and matched records.</para>
/// <example>
///   <summary>Find known-CA certificates expiring within 30 days</summary>
///   <code>Get-DDCertificateInventoryQuery -KnownCaOnly -ExpiringWithinDays 30 -MaxResults 1000</code>
/// </example>
/// <example>
///   <summary>Find likely mTLS issues</summary>
///   <code>Get-DDCertificateInventoryQuery -ClientAuthOnly -ChainIncompleteOnly -HostnameMismatchOnly</code>
/// </example>
/// <example>
///   <summary>Filter by CA families and CT source</summary>
///   <code>Get-DDCertificateInventoryQuery -AuthorityFamilyEquals LetsEncrypt -KnownRootCaOnly -CtSourceContains shodan</code>
/// </example>
/// <example>
///   <summary>Find invalid but reachable endpoints</summary>
///   <code>Get-DDCertificateInventoryQuery -InvalidOnly -ReachableOnly</code>
/// </example>
/// <example>
///   <summary>Return only latest endpoint observations</summary>
///   <code>Get-DDCertificateInventoryQuery -LatestOnly -HostContains \"example.com\"</code>
/// </example>
[Cmdlet(VerbsCommon.Get, "DDCertificateInventoryQuery")]
[Alias("Get-CertificateInventoryQuery")]
[OutputType(typeof(CertificateInventoryQueryResult))]
public sealed class CmdletGetCertificateInventoryQuery : PSCmdlet {
    /// <summary>Certificate monitor cache directory containing the inventory folder.</summary>
    [Parameter(Mandatory = false)]
    public string? CacheDirectory { get; set; }

    /// <summary>Only include snapshots captured since this UTC date/time.</summary>
    [Parameter(Mandatory = false)]
    public DateTime? SinceUtc { get; set; }

    /// <summary>Only include snapshots captured up to this UTC date/time.</summary>
    [Parameter(Mandatory = false)]
    public DateTime? UntilUtc { get; set; }

    /// <summary>Host substring filter.</summary>
    [Parameter(Mandatory = false)]
    public string? HostContains { get; set; }

    /// <summary>Certificate subject substring filter.</summary>
    [Parameter(Mandatory = false)]
    public string? SubjectContains { get; set; }

    /// <summary>Certificate SAN substring filter.</summary>
    [Parameter(Mandatory = false)]
    public string? SanContains { get; set; }

    /// <summary>Service equality filter (for example HTTPS, HTTPS-Alt, Custom TLS).</summary>
    [Parameter(Mandatory = false)]
    public string? ServiceEquals { get; set; }

    /// <summary>Issuer substring filter.</summary>
    [Parameter(Mandatory = false)]
    public string? IssuerContains { get; set; }

    /// <summary>Leaf authority family exact-match filter.</summary>
    [Parameter(Mandatory = false)]
    public string? AuthorityFamilyEquals { get; set; }

    /// <summary>Root issuer/subject substring filter.</summary>
    [Parameter(Mandatory = false)]
    public string? RootContains { get; set; }

    /// <summary>Root authority family exact-match filter.</summary>
    [Parameter(Mandatory = false)]
    public string? RootAuthorityFamilyEquals { get; set; }

    /// <summary>CT source substring filter.</summary>
    [Parameter(Mandatory = false)]
    public string? CtSourceContains { get; set; }

    /// <summary>CT template/configuration error substring filter.</summary>
    [Parameter(Mandatory = false)]
    public string? CtTemplateErrorContains { get; set; }

    /// <summary>Certificate chain source substring filter.</summary>
    [Parameter(Mandatory = false)]
    public string? ChainSourceContains { get; set; }

    /// <summary>Leaf certificate thumbprint exact-match filter.</summary>
    [Parameter(Mandatory = false)]
    public string? ThumbprintEquals { get; set; }

    /// <summary>Root certificate thumbprint exact-match filter.</summary>
    [Parameter(Mandatory = false)]
    public string? RootThumbprintEquals { get; set; }

    /// <summary>Leaf certificate serial-number exact-match filter (hex string expected).</summary>
    [Parameter(Mandatory = false)]
    public string? SerialNumberEquals { get; set; }

    /// <summary>Only include certificates from recognized public CAs.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter KnownCaOnly { get; set; }

    /// <summary>Only include certificates from unrecognized or private CAs.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter UnknownCaOnly { get; set; }

    /// <summary>Only include certificates chaining to recognized public root CAs.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter KnownRootCaOnly { get; set; }

    /// <summary>Only include certificates chaining to unrecognized or private root CAs.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter UnknownRootCaOnly { get; set; }

    /// <summary>Only include entries with valid certificates.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter ValidOnly { get; set; }

    /// <summary>Only include entries with invalid certificates.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter InvalidOnly { get; set; }

    /// <summary>Only include expired certificates.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter ExpiredOnly { get; set; }

    /// <summary>Only include entries with incomplete chains.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter ChainIncompleteOnly { get; set; }

    /// <summary>Only include entries with complete chains.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter ChainCompleteOnly { get; set; }

    /// <summary>Only include entries where hostname validation failed.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter HostnameMismatchOnly { get; set; }

    /// <summary>Only include entries where hostname validation succeeded.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter HostnameMatchOnly { get; set; }

    /// <summary>Only include self-signed certificates.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter SelfSignedOnly { get; set; }

    /// <summary>Only include certificates that are not self-signed.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter NotSelfSignedOnly { get; set; }

    /// <summary>Only include unreachable endpoints.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter UnreachableOnly { get; set; }

    /// <summary>Only include reachable endpoints.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter ReachableOnly { get; set; }

    /// <summary>Only include certificates observed in CT logs.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter CtOnly { get; set; }

    /// <summary>Only include certificates not observed in CT logs.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter CtMissingOnly { get; set; }

    /// <summary>Only include certificates allowing server authentication EKU.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter ServerAuthOnly { get; set; }

    /// <summary>Only include certificates that do not allow server authentication EKU.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter NoServerAuthOnly { get; set; }

    /// <summary>Only include certificates allowing client authentication EKU.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter ClientAuthOnly { get; set; }

    /// <summary>Only include certificates that do not allow client authentication EKU.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter NoClientAuthOnly { get; set; }

    /// <summary>Only include certificates allowing secure email EKU.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter SecureEmailOnly { get; set; }

    /// <summary>Only include certificates that do not allow secure email EKU.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter NoSecureEmailOnly { get; set; }

    /// <summary>Only include certificates that use weak keys.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter WeakKeyOnly { get; set; }

    /// <summary>Only include certificates signed with SHA-1.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter Sha1SignatureOnly { get; set; }

    /// <summary>Only include certificates that are not yet valid.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter NotYetValidOnly { get; set; }

    /// <summary>Only include certificates expiring within this many days.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? ExpiringWithinDays { get; set; }

    /// <summary>Authentication profile exact-match filter.</summary>
    [Parameter(Mandatory = false)]
    public string? AuthenticationProfileEquals { get; set; }

    /// <summary>Only evaluate the latest observed entry per endpoint (host+port) in the selected snapshot window.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter LatestOnly { get; set; }

    /// <summary>Maximum number of results returned.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int MaxResults { get; set; } = 500;

    /// <summary>Executes the cmdlet.</summary>
    protected override void ProcessRecord() {
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
        if (ValidOnly.IsPresent && InvalidOnly.IsPresent) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-ValidOnly cannot be combined with -InvalidOnly.", nameof(InvalidOnly)),
                "ValidAndInvalidConflict",
                ErrorCategory.InvalidArgument,
                InvalidOnly));
            return;
        }
        if (ChainIncompleteOnly.IsPresent && ChainCompleteOnly.IsPresent) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-ChainIncompleteOnly cannot be combined with -ChainCompleteOnly.", nameof(ChainCompleteOnly)),
                "ChainIncompleteAndCompleteConflict",
                ErrorCategory.InvalidArgument,
                ChainCompleteOnly));
            return;
        }
        if (HostnameMismatchOnly.IsPresent && HostnameMatchOnly.IsPresent) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-HostnameMismatchOnly cannot be combined with -HostnameMatchOnly.", nameof(HostnameMatchOnly)),
                "HostnameMismatchAndMatchConflict",
                ErrorCategory.InvalidArgument,
                HostnameMatchOnly));
            return;
        }
        if (SelfSignedOnly.IsPresent && NotSelfSignedOnly.IsPresent) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-SelfSignedOnly cannot be combined with -NotSelfSignedOnly.", nameof(NotSelfSignedOnly)),
                "SelfSignedAndNotSelfSignedConflict",
                ErrorCategory.InvalidArgument,
                NotSelfSignedOnly));
            return;
        }
        if (UnreachableOnly.IsPresent && ReachableOnly.IsPresent) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-UnreachableOnly cannot be combined with -ReachableOnly.", nameof(ReachableOnly)),
                "UnreachableAndReachableConflict",
                ErrorCategory.InvalidArgument,
                ReachableOnly));
            return;
        }
        if (CtOnly.IsPresent && CtMissingOnly.IsPresent) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-CtOnly cannot be combined with -CtMissingOnly.", nameof(CtMissingOnly)),
                "CtPresentAndMissingConflict",
                ErrorCategory.InvalidArgument,
                CtMissingOnly));
            return;
        }
        if (ServerAuthOnly.IsPresent && NoServerAuthOnly.IsPresent) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-ServerAuthOnly cannot be combined with -NoServerAuthOnly.", nameof(NoServerAuthOnly)),
                "ServerAuthAndNoServerAuthConflict",
                ErrorCategory.InvalidArgument,
                NoServerAuthOnly));
            return;
        }
        if (ClientAuthOnly.IsPresent && NoClientAuthOnly.IsPresent) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-ClientAuthOnly cannot be combined with -NoClientAuthOnly.", nameof(NoClientAuthOnly)),
                "ClientAuthAndNoClientAuthConflict",
                ErrorCategory.InvalidArgument,
                NoClientAuthOnly));
            return;
        }
        if (SecureEmailOnly.IsPresent && NoSecureEmailOnly.IsPresent) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-SecureEmailOnly cannot be combined with -NoSecureEmailOnly.", nameof(NoSecureEmailOnly)),
                "SecureEmailAndNoSecureEmailConflict",
                ErrorCategory.InvalidArgument,
                NoSecureEmailOnly));
            return;
        }
        if (ExpiredOnly.IsPresent && ExpiringWithinDays.HasValue) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-ExpiredOnly cannot be combined with -ExpiringWithinDays.", nameof(ExpiringWithinDays)),
                "ExpiredAndExpiringConflict",
                ErrorCategory.InvalidArgument,
                ExpiringWithinDays));
            return;
        }
        if (ExpiredOnly.IsPresent && NotYetValidOnly.IsPresent) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-ExpiredOnly cannot be combined with -NotYetValidOnly.", nameof(NotYetValidOnly)),
                "ExpiredAndNotYetValidConflict",
                ErrorCategory.InvalidArgument,
                NotYetValidOnly));
            return;
        }
        if (ValidOnly.IsPresent && NotYetValidOnly.IsPresent) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-ValidOnly cannot be combined with -NotYetValidOnly.", nameof(NotYetValidOnly)),
                "ValidAndNotYetValidConflict",
                ErrorCategory.InvalidArgument,
                NotYetValidOnly));
            return;
        }

        var monitor = new CertificateMonitor {
            CacheDirectory = CertificateInventoryCmdletHelpers.ResolveCacheDirectory(CacheDirectory),
            PersistInventorySnapshots = false
        };

        var since = CertificateInventoryCmdletHelpers.ToUtc(SinceUtc);

        var until = CertificateInventoryCmdletHelpers.ToUtc(UntilUtc);

        var query = new CertificateInventoryQuery {
            SinceUtc = since,
            UntilUtc = until,
            HostContains = HostContains,
            SubjectContains = SubjectContains,
            SanContains = SanContains,
            ServiceEquals = ServiceEquals,
            IssuerContains = IssuerContains,
            AuthorityFamilyEquals = AuthorityFamilyEquals,
            RootContains = RootContains,
            RootAuthorityFamilyEquals = RootAuthorityFamilyEquals,
            CtSourceContains = CtSourceContains,
            CtTemplateErrorContains = CtTemplateErrorContains,
            ChainSourceContains = ChainSourceContains,
            ThumbprintEquals = ThumbprintEquals,
            RootThumbprintEquals = RootThumbprintEquals,
            SerialNumberEquals = SerialNumberEquals,
            KnownAuthorityOnly = KnownCaOnly.IsPresent ? true : UnknownCaOnly.IsPresent ? false : null,
            KnownRootAuthorityOnly = KnownRootCaOnly.IsPresent ? true : UnknownRootCaOnly.IsPresent ? false : null,
            ValidOnly = ValidOnly.IsPresent ? true : InvalidOnly.IsPresent ? false : null,
            ExpiredOnly = ExpiredOnly.IsPresent ? true : null,
            ChainCompleteOnly = ChainIncompleteOnly.IsPresent ? false : ChainCompleteOnly.IsPresent ? true : null,
            HostnameMatchOnly = HostnameMismatchOnly.IsPresent ? false : HostnameMatchOnly.IsPresent ? true : null,
            SelfSignedOnly = SelfSignedOnly.IsPresent ? true : NotSelfSignedOnly.IsPresent ? false : null,
            ReachableOnly = UnreachableOnly.IsPresent ? false : ReachableOnly.IsPresent ? true : null,
            PresentInCtOnly = CtOnly.IsPresent ? true : CtMissingOnly.IsPresent ? false : null,
            AllowsServerAuthOnly = ServerAuthOnly.IsPresent ? true : NoServerAuthOnly.IsPresent ? false : null,
            AllowsClientAuthOnly = ClientAuthOnly.IsPresent ? true : NoClientAuthOnly.IsPresent ? false : null,
            AllowsSecureEmailOnly = SecureEmailOnly.IsPresent ? true : NoSecureEmailOnly.IsPresent ? false : null,
            WeakKeyOnly = WeakKeyOnly.IsPresent ? true : null,
            Sha1SignatureOnly = Sha1SignatureOnly.IsPresent ? true : null,
            NotYetValidOnly = NotYetValidOnly.IsPresent ? true : null,
            ExpiringWithinDays = ExpiringWithinDays,
            AuthenticationProfileEquals = AuthenticationProfileEquals,
            LatestPerEndpointOnly = LatestOnly.IsPresent,
            MaxResults = MaxResults
        };

        var result = monitor.QueryInventoryEntries(query);
        WriteObject(result);
    }
}
