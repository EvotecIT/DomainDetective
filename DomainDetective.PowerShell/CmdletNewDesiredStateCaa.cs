using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a CAA desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Require a valid CAA policy and allow only Let's Encrypt</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateCaa -RequireValid $true -AllowedCertificateIssuers letsencrypt.org</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateCaa")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateCaa : PSCmdlet {
    /// <para>Enable/disable the CAA desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, require a CAA record to exist.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireRecord { get; set; }

    /// <para>When true, require the CAA policy to be valid.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireValid { get; set; }

    /// <para>Allowed issuers for issue tags.</para>
    [Parameter(Mandatory = false)]
    public string[]? AllowedCertificateIssuers { get; set; }

    /// <para>Allowed issuers for issuewild tags.</para>
    [Parameter(Mandatory = false)]
    public string[]? AllowedWildcardIssuers { get; set; }

    /// <para>When true, requires at least one iodef reporting endpoint.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireIodef { get; set; }

    /// <para>Allowed domain suffixes for iodef mailto/http reporting endpoints.</para>
    [Parameter(Mandatory = false)]
    public string[]? AllowedIodefDomainSuffixes { get; set; }

    /// <summary>Creates a CAA policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            Caa = new DesiredStateCaaPolicy {
                Enabled = Enabled,
                RequireRecord = RequireRecord,
                RequireValid = RequireValid,
                AllowedCertificateIssuers = AllowedCertificateIssuers,
                AllowedWildcardIssuers = AllowedWildcardIssuers,
                RequireIodef = RequireIodef,
                AllowedIodefDomainSuffixes = AllowedIodefDomainSuffixes
            }
        };

        WriteObject(profile);
    }
}

