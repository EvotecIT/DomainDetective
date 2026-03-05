using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a certificate inventory desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
[Cmdlet(VerbsCommon.New, "DDDesiredStateCertificateInventory")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateCertificateInventory : PSCmdlet {
    /// <para>Enable/disable certificate inventory desired state evaluation.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>Baseline policy profile (Strict, Balanced, Legacy).</para>
    [Parameter(Mandatory = false)]
    [ValidateSet("Strict", "Balanced", "Legacy")]
    public string? BaselineProfile { get; set; }

    /// <para>Include endpoints with no policy violations.</para>
    [Parameter(Mandatory = false)]
    public bool? IncludeCompliant { get; set; }

    /// <para>Maximum endpoint rows returned by policy evaluation.</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MaxEndpoints { get; set; }

    /// <para>Optional JSON file path with certificate inventory policy overrides.</para>
    [Parameter(Mandatory = false)]
    public string? PolicyOverridesPath { get; set; }

    /// <summary>Creates a certificate inventory policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            CertificateInventory = new DesiredStateCertificateInventoryPolicy {
                Enabled = Enabled,
                BaselineProfile = BaselineProfile,
                IncludeCompliant = IncludeCompliant,
                MaxEndpoints = MaxEndpoints,
                PolicyOverridesPath = PolicyOverridesPath
            }
        };

        WriteObject(profile);
    }
}
