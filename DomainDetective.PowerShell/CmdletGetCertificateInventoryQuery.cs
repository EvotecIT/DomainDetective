using System;
using System.IO;
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

    /// <summary>Only include certificates from recognized public CAs.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter KnownCaOnly { get; set; }

    /// <summary>Only include certificates chaining to recognized public root CAs.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter KnownRootCaOnly { get; set; }

    /// <summary>Only include entries with valid certificates.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter ValidOnly { get; set; }

    /// <summary>Only include expired certificates.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter ExpiredOnly { get; set; }

    /// <summary>Only include entries with incomplete chains.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter ChainIncompleteOnly { get; set; }

    /// <summary>Only include entries where hostname validation failed.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter HostnameMismatchOnly { get; set; }

    /// <summary>Only include self-signed certificates.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter SelfSignedOnly { get; set; }

    /// <summary>Only include unreachable endpoints.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter UnreachableOnly { get; set; }

    /// <summary>Only include certificates observed in CT logs.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter CtOnly { get; set; }

    /// <summary>Only include certificates allowing server authentication EKU.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter ServerAuthOnly { get; set; }

    /// <summary>Only include certificates allowing client authentication EKU.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter ClientAuthOnly { get; set; }

    /// <summary>Only include certificates allowing secure email EKU.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter SecureEmailOnly { get; set; }

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
        if (ExpiredOnly.IsPresent && ExpiringWithinDays.HasValue) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-ExpiredOnly cannot be combined with -ExpiringWithinDays.", nameof(ExpiringWithinDays)),
                "ExpiredAndExpiringConflict",
                ErrorCategory.InvalidArgument,
                ExpiringWithinDays));
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

        DateTimeOffset? until = null;
        if (UntilUtc.HasValue) {
            until = new DateTimeOffset(DateTime.SpecifyKind(UntilUtc.Value, DateTimeKind.Utc));
        }

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
            KnownAuthorityOnly = KnownCaOnly.IsPresent ? true : null,
            KnownRootAuthorityOnly = KnownRootCaOnly.IsPresent ? true : null,
            ValidOnly = ValidOnly.IsPresent ? true : null,
            ExpiredOnly = ExpiredOnly.IsPresent ? true : null,
            ChainCompleteOnly = ChainIncompleteOnly.IsPresent ? false : null,
            HostnameMatchOnly = HostnameMismatchOnly.IsPresent ? false : null,
            SelfSignedOnly = SelfSignedOnly.IsPresent ? true : null,
            ReachableOnly = UnreachableOnly.IsPresent ? false : null,
            PresentInCtOnly = CtOnly.IsPresent ? true : null,
            AllowsServerAuthOnly = ServerAuthOnly.IsPresent ? true : null,
            AllowsClientAuthOnly = ClientAuthOnly.IsPresent ? true : null,
            AllowsSecureEmailOnly = SecureEmailOnly.IsPresent ? true : null,
            ExpiringWithinDays = ExpiringWithinDays,
            AuthenticationProfileEquals = AuthenticationProfileEquals,
            LatestPerEndpointOnly = LatestOnly.IsPresent,
            MaxResults = MaxResults
        };

        var result = monitor.QueryInventoryEntries(query);
        WriteObject(result);
    }

    private static string ResolveCacheDirectory(string? configured) {
        if (!string.IsNullOrWhiteSpace(configured)) {
            return configured!;
        }

        return Path.Combine(Path.GetTempPath(), "DomainDetective", "cert-monitor");
    }
}
