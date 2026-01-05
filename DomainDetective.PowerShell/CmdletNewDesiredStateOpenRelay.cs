using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates an open relay desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Disallow open relay for MX hosts</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateOpenRelay -Enabled $true -DisallowOpenRelay $true</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateOpenRelay")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateOpenRelay : PSCmdlet {
    /// <para>Enable/disable the open relay desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, require at least one open relay result to be present.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <para>When true, disallow MX hosts that allow unauthenticated relay.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowOpenRelay { get; set; }

    /// <para>When true, treat connection failures as drift.</para>
    [Parameter(Mandatory = false)]
    public bool? TreatConnectionFailuresAsDrift { get; set; }

    /// <summary>Creates an open relay policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            OpenRelay = new DesiredStateOpenRelayPolicy {
                Enabled = Enabled,
                RequireAtLeastOneResult = RequireAtLeastOneResult,
                DisallowOpenRelay = DisallowOpenRelay,
                TreatConnectionFailuresAsDrift = TreatConnectionFailuresAsDrift
            }
        };

        WriteObject(profile);
    }
}

