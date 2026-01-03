using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a DMARC desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Require reject/quarantine and enforce a specific rua suffix</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateDmarc -Enabled $true -AllowedPolicies reject,quarantine -RequireRua $true -AllowedReportDomainSuffixes dmarc.powermarc.com</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateDmarc")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateDmarc : PSCmdlet {
    /// <para>Enable/disable the DMARC desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, require a DMARC record to exist.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireRecord { get; set; }

    /// <para>Allowed DMARC policy values (p=).</para>
    [Parameter(Mandatory = false)]
    [ValidateSet("none", "quarantine", "reject")]
    public string[]? AllowedPolicies { get; set; }

    /// <para>Allowed DMARC subdomain policy values (sp=).</para>
    [Parameter(Mandatory = false)]
    [ValidateSet("none", "quarantine", "reject")]
    public string[]? AllowedSubdomainPolicies { get; set; }

    /// <para>When true, requires an explicit sp= tag to be present.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireSubdomainPolicyTag { get; set; }

    /// <para>Allowed aspf alignment values (r/s).</para>
    [Parameter(Mandatory = false)]
    [ValidateSet("r", "s")]
    public string[]? AllowedAspfAlignments { get; set; }

    /// <para>Allowed adkim alignment values (r/s).</para>
    [Parameter(Mandatory = false)]
    [ValidateSet("r", "s")]
    public string[]? AllowedAdkimAlignments { get; set; }

    /// <para>When true, require at least one aggregate reporting URI (rua=).</para>
    [Parameter(Mandatory = false)]
    public bool? RequireRua { get; set; }

    /// <para>Allowed domain suffixes for DMARC rua/ruf URIs.</para>
    [Parameter(Mandatory = false)]
    public string[]? AllowedReportDomainSuffixes { get; set; }

    /// <para>When true, requires external reporting domains to be authorized via _report._dmarc.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireExternalReportAuthorization { get; set; }

    /// <summary>Creates a DMARC policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            Dmarc = new DesiredStateDmarcPolicy {
                Enabled = Enabled,
                RequireRecord = RequireRecord,
                AllowedPolicies = AllowedPolicies,
                AllowedSubdomainPolicies = AllowedSubdomainPolicies,
                RequireSubdomainPolicyTag = RequireSubdomainPolicyTag,
                AllowedAspfAlignments = AllowedAspfAlignments,
                AllowedAdkimAlignments = AllowedAdkimAlignments,
                RequireRua = RequireRua,
                AllowedReportDomainSuffixes = AllowedReportDomainSuffixes,
                RequireExternalReportAuthorization = RequireExternalReportAuthorization
            }
        };

        WriteObject(profile);
    }
}
