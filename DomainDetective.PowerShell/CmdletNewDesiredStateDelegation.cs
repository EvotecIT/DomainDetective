using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a delegation desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
[Cmdlet(VerbsCommon.New, "DDDesiredStateDelegation")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateDelegation : PSCmdlet {
    /// <para>Enable/disable the delegation desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, requires child delegation NS to match parent delegation NS.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireMatchesParent { get; set; }

    /// <para>When true, requires glue records to be present for in-bailiwick name servers.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireGlueComplete { get; set; }

    /// <para>When true, requires glue records to be consistent across authoritative name servers.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireGlueConsistent { get; set; }

    /// <summary>Creates a delegation policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            Delegation = new DesiredStateDelegationPolicy {
                Enabled = Enabled,
                RequireMatchesParent = RequireMatchesParent,
                RequireGlueComplete = RequireGlueComplete,
                RequireGlueConsistent = RequireGlueConsistent
            }
        };

        WriteObject(profile);
    }
}
