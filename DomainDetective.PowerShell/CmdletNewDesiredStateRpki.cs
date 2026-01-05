using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates an RPKI desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
[Cmdlet(VerbsCommon.New, "DDDesiredStateRpki")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateRpki : PSCmdlet {
    /// <para>Enable/disable the RPKI desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, warns if no RPKI results were analyzed.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <para>When true, invalid (non-ignored) results are treated as drift.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowInvalid { get; set; }

    /// <para>When true, failed RPKI lookups are treated as drift.</para>
    [Parameter(Mandatory = false)]
    public bool? TreatQueryFailuresAsDrift { get; set; }

    /// <para>Optional allow-list of IP addresses to ignore.</para>
    [Parameter(Mandatory = false)]
    public string[]? IgnoredIpAddresses { get; set; }

    /// <para>Optional allow-list of prefixes to ignore (as returned by the provider).</para>
    [Parameter(Mandatory = false)]
    public string[]? IgnoredPrefixes { get; set; }

    /// <para>Optional allow-list of ASNs to ignore.</para>
    [Parameter(Mandatory = false)]
    public int[]? IgnoredAsns { get; set; }

    /// <summary>Creates an RPKI policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            Rpki = new DesiredStateRpkiPolicy {
                Enabled = Enabled,
                RequireAtLeastOneResult = RequireAtLeastOneResult,
                DisallowInvalid = DisallowInvalid,
                TreatQueryFailuresAsDrift = TreatQueryFailuresAsDrift,
                IgnoredIpAddresses = IgnoredIpAddresses,
                IgnoredPrefixes = IgnoredPrefixes,
                IgnoredAsns = IgnoredAsns
            }
        };

        WriteObject(profile);
    }
}

