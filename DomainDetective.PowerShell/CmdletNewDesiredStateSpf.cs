using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates an SPF desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Require strict SPF posture</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateSpf -Enabled $true -RequireRecord $true -AllowedAllMechanisms '-all' -MaxDnsLookups 10 -DisallowPtr $true</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateSpf")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateSpf : PSCmdlet {
    /// <para>Enable/disable the SPF desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, require an SPF record to exist.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireRecord { get; set; }

    /// <para>Allowed all mechanisms (e.g., -all, ~all).</para>
    [Parameter(Mandatory = false)]
    [ValidateSet("-all", "~all", "?all", "+all")]
    public string[]? AllowedAllMechanisms { get; set; }

    /// <para>Maximum allowed SPF DNS lookups.</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, 100)]
    public int? MaxDnsLookups { get; set; }

    /// <para>When true, requires the policy to deny all sending (v=spf1 -all).</para>
    [Parameter(Mandatory = false)]
    public bool? RequireDenyAll { get; set; }

    /// <para>Include domains that must be present in the SPF record.</para>
    [Parameter(Mandatory = false)]
    public string[]? RequiredIncludeDomains { get; set; }

    /// <para>When true, checks required include domains against the resolved include chain.</para>
    [Parameter(Mandatory = false)]
    public bool? MatchResolvedIncludes { get; set; }

    /// <para>When true, disallows the SPF ptr mechanism.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowPtr { get; set; }

    /// <para>When true, disallows unknown mechanisms/modifiers.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowUnknownMechanisms { get; set; }

    /// <para>When true, disallows the redirect= modifier.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowRedirect { get; set; }

    /// <para>When true, requires the redirect= modifier to be present.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireRedirect { get; set; }

    /// <para>Allowed domain suffixes for redirect= target.</para>
    [Parameter(Mandatory = false)]
    public string[]? AllowedRedirectDomainSuffixes { get; set; }

    /// <summary>Creates an SPF policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            Spf = new DesiredStateSpfPolicy {
                Enabled = Enabled,
                RequireRecord = RequireRecord,
                AllowedAllMechanisms = AllowedAllMechanisms,
                MaxDnsLookups = MaxDnsLookups,
                RequireDenyAll = RequireDenyAll,
                RequiredIncludeDomains = RequiredIncludeDomains,
                MatchResolvedIncludes = MatchResolvedIncludes,
                DisallowPtr = DisallowPtr,
                DisallowUnknownMechanisms = DisallowUnknownMechanisms,
                DisallowRedirect = DisallowRedirect,
                RequireRedirect = RequireRedirect,
                AllowedRedirectDomainSuffixes = AllowedRedirectDomainSuffixes
            }
        };

        WriteObject(profile);
    }
}
