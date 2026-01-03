using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a wildcard DNS desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
[Cmdlet(VerbsCommon.New, "DDDesiredStateWildcardDns")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateWildcardDns : PSCmdlet {
    /// <para>Enable/disable the wildcard DNS desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>Expected wildcard (catch-all) behavior. When null, no constraint is enforced.</para>
    [Parameter(Mandatory = false)]
    public bool? ExpectedCatchAll { get; set; }

    /// <summary>Creates a wildcard DNS policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            WildcardDns = new DesiredStateWildcardDnsPolicy {
                Enabled = Enabled,
                ExpectedCatchAll = ExpectedCatchAll
            }
        };

        WriteObject(profile);
    }
}

