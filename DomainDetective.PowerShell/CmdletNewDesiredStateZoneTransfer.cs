using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a zone transfer desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
[Cmdlet(VerbsCommon.New, "DDDesiredStateZoneTransfer")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateZoneTransfer : PSCmdlet {
    /// <para>Enable/disable the zone transfer desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, no authoritative server may allow unauthenticated AXFR.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowUnauthenticatedAxfr { get; set; }

    /// <summary>Creates a zone transfer policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            ZoneTransfer = new DesiredStateZoneTransferPolicy {
                Enabled = Enabled,
                DisallowUnauthenticatedAxfr = DisallowUnauthenticatedAxfr
            }
        };

        WriteObject(profile);
    }
}

