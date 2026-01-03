using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a dangling CNAME desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
[Cmdlet(VerbsCommon.New, "DDDesiredStateDanglingCname")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateDanglingCname : PSCmdlet {
    /// <para>Enable/disable the dangling CNAME desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, disallows a CNAME that exists but does not resolve.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowDangling { get; set; }

    /// <para>When true, disallows dangling CNAMEs that point to known takeover-prone services.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowUnclaimedService { get; set; }

    /// <summary>Creates a dangling CNAME policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            DanglingCname = new DesiredStateDanglingCnamePolicy {
                Enabled = Enabled,
                DisallowDangling = DisallowDangling,
                DisallowUnclaimedService = DisallowUnclaimedService
            }
        };

        WriteObject(profile);
    }
}

