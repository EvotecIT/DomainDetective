using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a security.txt desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Require security.txt to be present and valid</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateSecurityTxt -RequireRecord $true -RequireValid $true -DisallowFallback $true</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateSecurityTxt")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateSecurityTxt : PSCmdlet {
    /// <para>Enable/disable the security.txt desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, require security.txt to be present.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireRecord { get; set; }

    /// <para>When true, require security.txt to pass validation.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireValid { get; set; }

    /// <para>When true, disallows fallback to HTTP retrieval when HTTPS fails.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowFallback { get; set; }

    /// <para>When true, require security.txt to be PGP signed.</para>
    [Parameter(Mandatory = false)]
    public bool? RequirePgpSigned { get; set; }

    /// <para>When true, require security.txt to include at least one Contact mail address.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireContactEmail { get; set; }

    /// <para>Allowed suffixes for domains used in Contact email addresses.</para>
    [Parameter(Mandatory = false)]
    public string[]? AllowedContactEmailDomainSuffixes { get; set; }

    /// <summary>Creates a security.txt policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            SecurityTxt = new DesiredStateSecurityTxtPolicy {
                Enabled = Enabled,
                RequireRecord = RequireRecord,
                RequireValid = RequireValid,
                DisallowFallback = DisallowFallback,
                RequirePgpSigned = RequirePgpSigned,
                RequireContactEmail = RequireContactEmail,
                AllowedContactEmailDomainSuffixes = AllowedContactEmailDomainSuffixes
            }
        };

        WriteObject(profile);
    }
}

