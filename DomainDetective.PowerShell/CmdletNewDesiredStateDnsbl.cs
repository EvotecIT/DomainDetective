using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a DNSBL desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
[Cmdlet(VerbsCommon.New, "DDDesiredStateDnsbl")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateDnsbl : PSCmdlet {
    /// <para>Enable/disable the DNSBL desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, warns if no DNSBL results were analyzed.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <para>When true, non-ignored listings are treated as drift.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowListings { get; set; }

    /// <para>Blacklist domains to ignore (e.g., some providers produce false positives).</para>
    [Parameter(Mandatory = false)]
    public string[]? IgnoredBlacklists { get; set; }

    /// <para>Optional allow-list of query kinds to evaluate (Domain/IpAddressV4/IpAddressV6).</para>
    [Parameter(Mandatory = false)]
    public DnsblQueryKind[]? IncludeQueryKinds { get; set; }

    /// <para>Optional allow-list of IP sources to evaluate (MxA/MxAAAA/ApexA/ApexAAAA/Domain).</para>
    [Parameter(Mandatory = false)]
    public DnsblIpSource[]? IncludeIpSources { get; set; }

    /// <summary>Creates a DNSBL policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            Dnsbl = new DesiredStateDnsblPolicy {
                Enabled = Enabled,
                RequireAtLeastOneResult = RequireAtLeastOneResult,
                DisallowListings = DisallowListings,
                IgnoredBlacklists = IgnoredBlacklists,
                IncludeQueryKinds = IncludeQueryKinds,
                IncludeIpSources = IncludeIpSources
            }
        };

        WriteObject(profile);
    }
}

