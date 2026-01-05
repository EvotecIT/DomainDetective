using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a DNSSEC desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Require a valid DNSSEC chain and at least 7 days of RRSIG validity remaining</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateDnssec -RequireChainValid $true -MinRrsigDaysRemaining 7</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateDnssec")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateDnssec : PSCmdlet {
    /// <para>Enable/disable the DNSSEC desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, requires a valid DNSSEC chain.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireChainValid { get; set; }

    /// <para>Minimum number of days remaining for any RRSIG on the zone.</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, 3650)]
    public int? MinRrsigDaysRemaining { get; set; }

    /// <summary>Creates a DNSSEC policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            DnsSec = new DesiredStateDnssecPolicy {
                Enabled = Enabled,
                RequireChainValid = RequireChainValid,
                MinRrsigDaysRemaining = MinRrsigDaysRemaining
            }
        };

        WriteObject(profile);
    }
}

