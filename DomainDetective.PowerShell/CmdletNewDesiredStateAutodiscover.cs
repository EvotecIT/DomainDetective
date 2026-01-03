using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates an Autodiscover desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Require Autodiscover records to point to Microsoft 365</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateAutodiscover -RequireAutodiscoverCname $true -AllowedAutodiscoverCnameTargetSuffixes outlook.com -RequireAnyValidEndpoint $true</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateAutodiscover")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateAutodiscover : PSCmdlet {
    /// <para>Enable/disable the Autodiscover desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, require an _autodiscover._tcp SRV record to exist.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireSrvRecord { get; set; }

    /// <para>When true, require an autodiscover.&lt;domain&gt; CNAME record to exist.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAutodiscoverCname { get; set; }

    /// <para>When true, require an autoconfig.&lt;domain&gt; CNAME record to exist.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAutoconfigCname { get; set; }

    /// <para>Allowed suffixes for _autodiscover._tcp SRV target.</para>
    [Parameter(Mandatory = false)]
    public string[]? AllowedSrvTargetSuffixes { get; set; }

    /// <para>Allowed suffixes for autodiscover.&lt;domain&gt; CNAME target.</para>
    [Parameter(Mandatory = false)]
    public string[]? AllowedAutodiscoverCnameTargetSuffixes { get; set; }

    /// <para>Allowed suffixes for autoconfig.&lt;domain&gt; CNAME target.</para>
    [Parameter(Mandatory = false)]
    public string[]? AllowedAutoconfigCnameTargetSuffixes { get; set; }

    /// <para>When true, requires at least one Autodiscover endpoint to return valid XML or JSON.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAnyValidEndpoint { get; set; }

    /// <para>Allowed suffixes for hosts of valid Autodiscover endpoints.</para>
    [Parameter(Mandatory = false)]
    public string[]? AllowedValidEndpointHostSuffixes { get; set; }

    /// <summary>Creates an Autodiscover policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            Autodiscover = new DesiredStateAutodiscoverPolicy {
                Enabled = Enabled,
                RequireSrvRecord = RequireSrvRecord,
                RequireAutodiscoverCname = RequireAutodiscoverCname,
                RequireAutoconfigCname = RequireAutoconfigCname,
                AllowedSrvTargetSuffixes = AllowedSrvTargetSuffixes,
                AllowedAutodiscoverCnameTargetSuffixes = AllowedAutodiscoverCnameTargetSuffixes,
                AllowedAutoconfigCnameTargetSuffixes = AllowedAutoconfigCnameTargetSuffixes,
                RequireAnyValidEndpoint = RequireAnyValidEndpoint,
                AllowedValidEndpointHostSuffixes = AllowedValidEndpointHostSuffixes
            }
        };

        WriteObject(profile);
    }
}

