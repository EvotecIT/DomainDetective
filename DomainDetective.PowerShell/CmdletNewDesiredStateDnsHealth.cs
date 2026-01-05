using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a DNS health desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
[Cmdlet(VerbsCommon.New, "DDDesiredStateDnsHealth")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateDnsHealth : PSCmdlet {
    /// <para>Enable/disable the DNS health desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, warns if no DNS health results were analyzed.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <para>When true, requires authoritative servers to respond to DNS queries.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireServersResponsive { get; set; }

    /// <para>When true, requires SOA serial to be consistent across authoritative servers.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireSoaSerialConsistent { get; set; }

    /// <para>When true, requires apex A/AAAA results to be consistent across authoritative servers.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireApexAddressesConsistent { get; set; }

    /// <summary>Creates a DNS health policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            DnsHealth = new DesiredStateDnsHealthPolicy {
                Enabled = Enabled,
                RequireAtLeastOneResult = RequireAtLeastOneResult,
                RequireServersResponsive = RequireServersResponsive,
                RequireSoaSerialConsistent = RequireSoaSerialConsistent,
                RequireApexAddressesConsistent = RequireApexAddressesConsistent
            }
        };

        WriteObject(profile);
    }
}
