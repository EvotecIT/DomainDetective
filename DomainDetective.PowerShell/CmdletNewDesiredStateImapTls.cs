using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates an IMAP TLS desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Require strong IMAP TLS posture</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateImapTls -RequireCertificateValid $true -DisallowLegacyProtocols $true -MinimumGradeLevel B</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateImapTls")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateImapTls : PSCmdlet {
    /// <para>Enable/disable the IMAP TLS desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, warns if no TLS results were produced.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <para>When true, requires certificates to be valid.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireCertificateValid { get; set; }

    /// <para>When true, requires certificate chains to be valid.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireChainValid { get; set; }

    /// <para>When true, requires certificate hostname match.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireHostnameMatch { get; set; }

    /// <para>When true, disallows expired certificates.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowExpiredCertificates { get; set; }

    /// <para>Minimum certificate days remaining before expiry.</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, 36500)]
    public int? MinCertificateDaysToExpire { get; set; }

    /// <para>When true, disallows legacy TLS protocols (1.0/1.1) and legacy negotiation.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowLegacyProtocols { get; set; }

    /// <para>Minimum accepted TLS grade level.</para>
    [Parameter(Mandatory = false)]
    public GradeLevel? MinimumGradeLevel { get; set; }

    /// <summary>Creates an IMAP TLS policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            ImapTls = new DesiredStateMailTlsPolicy {
                Enabled = Enabled,
                RequireAtLeastOneResult = RequireAtLeastOneResult,
                RequireCertificateValid = RequireCertificateValid,
                RequireChainValid = RequireChainValid,
                RequireHostnameMatch = RequireHostnameMatch,
                DisallowExpiredCertificates = DisallowExpiredCertificates,
                MinCertificateDaysToExpire = MinCertificateDaysToExpire,
                DisallowLegacyProtocols = DisallowLegacyProtocols,
                MinimumGradeLevel = MinimumGradeLevel
            }
        };

        WriteObject(profile);
    }
}

