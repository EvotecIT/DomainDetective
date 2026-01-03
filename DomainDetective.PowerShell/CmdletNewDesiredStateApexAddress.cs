using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates an apex address desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
[Cmdlet(VerbsCommon.New, "DDDesiredStateApexAddress")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateApexAddress : PSCmdlet {
    /// <para>Enable/disable the apex address desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, requires at least one apex A/AAAA record.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAnyAddress { get; set; }

    /// <para>When true, disallows any apex A/AAAA records.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowAnyAddress { get; set; }

    /// <para>When true, disallow private IPv4/IPv6 addresses at the apex.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowPrivateAddresses { get; set; }

    /// <para>When true, disallow loopback addresses at the apex.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowLoopbackAddresses { get; set; }

    /// <para>When true, disallow link-local addresses at the apex.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowLinkLocalAddresses { get; set; }

    /// <para>When true, disallow multicast addresses at the apex.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowMulticastAddresses { get; set; }

    /// <para>When true, disallow documentation/example addresses at the apex.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowDocumentationAddresses { get; set; }

    /// <para>When true, disallow unique-local IPv6 addresses at the apex.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowUniqueLocalV6Addresses { get; set; }

    /// <para>Minimum distinct subnet count for apex IPv4 addresses.</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, 1000)]
    public int? MinDistinctSubnetCountV4 { get; set; }

    /// <para>Minimum distinct subnet count for apex IPv6 addresses.</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, 1000)]
    public int? MinDistinctSubnetCountV6 { get; set; }

    /// <para>When true, requires PTR records to exist for all discovered apex addresses.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAllPtrPresent { get; set; }

    /// <para>When true, requires forward-confirmed reverse DNS for all discovered apex addresses.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAllFcrDnsValid { get; set; }

    /// <summary>Creates an apex address policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            ApexAddress = new DesiredStateApexAddressPolicy {
                Enabled = Enabled,
                RequireAnyAddress = RequireAnyAddress,
                DisallowAnyAddress = DisallowAnyAddress,
                DisallowPrivateAddresses = DisallowPrivateAddresses,
                DisallowLoopbackAddresses = DisallowLoopbackAddresses,
                DisallowLinkLocalAddresses = DisallowLinkLocalAddresses,
                DisallowMulticastAddresses = DisallowMulticastAddresses,
                DisallowDocumentationAddresses = DisallowDocumentationAddresses,
                DisallowUniqueLocalV6Addresses = DisallowUniqueLocalV6Addresses,
                MinDistinctSubnetCountV4 = MinDistinctSubnetCountV4,
                MinDistinctSubnetCountV6 = MinDistinctSubnetCountV6,
                RequireAllPtrPresent = RequireAllPtrPresent,
                RequireAllFcrDnsValid = RequireAllFcrDnsValid
            }
        };

        WriteObject(profile);
    }
}
