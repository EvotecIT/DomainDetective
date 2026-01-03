using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates an NS desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Require at least two name servers and disallow duplicates</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateNs -RequireAtLeastTwo $true -DisallowDuplicates $true</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateNs")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateNs : PSCmdlet {
    /// <para>Enable/disable the NS desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, require NS records to exist.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireRecord { get; set; }

    /// <para>When true, require at least two NS records.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAtLeastTwo { get; set; }

    /// <para>When true, disallow duplicate NS targets.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowDuplicates { get; set; }

    /// <para>When true, requires all NS targets to have A/AAAA records.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAllHaveAOrAaaa { get; set; }

    /// <para>When true, disallow NS targets that resolve to CNAME.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowCnameTargets { get; set; }

    /// <para>When true, enforce diversity requirements for authoritative name servers.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireDiversity { get; set; }

    /// <para>Minimum distinct ASN count for authoritative name servers.</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, 1000)]
    public int? MinAsnDiversity { get; set; }

    /// <para>Allowed host suffixes for authoritative NS targets.</para>
    [Parameter(Mandatory = false)]
    public string[]? AllowedHostSuffixes { get; set; }

    /// <summary>Creates an NS policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            Ns = new DesiredStateNsPolicy {
                Enabled = Enabled,
                RequireRecord = RequireRecord,
                RequireAtLeastTwo = RequireAtLeastTwo,
                DisallowDuplicates = DisallowDuplicates,
                RequireAllHaveAOrAaaa = RequireAllHaveAOrAaaa,
                DisallowCnameTargets = DisallowCnameTargets,
                RequireDiversity = RequireDiversity,
                MinAsnDiversity = MinAsnDiversity,
                AllowedHostSuffixes = AllowedHostSuffixes
            }
        };

        WriteObject(profile);
    }
}

