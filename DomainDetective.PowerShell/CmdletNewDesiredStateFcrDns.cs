using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates an FCrDNS desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Require all PTR hostnames to be forward-confirmed</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateFcrDns -RequireAllForwardConfirmed $true</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateFcrDns")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateFcrDns : PSCmdlet {
    /// <para>Enable/disable the FCrDNS desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, warns if no FCrDNS results were analyzed.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <para>When true, requires all IPs to be forward-confirmed.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAllForwardConfirmed { get; set; }

    /// <summary>Creates an FCrDNS policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            FcrDns = new DesiredStateFcrDnsPolicy {
                Enabled = Enabled,
                RequireAtLeastOneResult = RequireAtLeastOneResult,
                RequireAllForwardConfirmed = RequireAllForwardConfirmed
            }
        };

        WriteObject(profile);
    }
}

