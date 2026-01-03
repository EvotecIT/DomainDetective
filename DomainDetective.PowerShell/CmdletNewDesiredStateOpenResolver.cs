using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates an open resolver desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Disallow open recursion on authoritative DNS servers</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateOpenResolver -Enabled $true -DisallowOpenResolver $true</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateOpenResolver")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateOpenResolver : PSCmdlet {
    /// <para>Enable/disable the open resolver desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, require at least one open resolver result to be present.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <para>When true, disallow authoritative name servers that allow recursion.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowOpenResolver { get; set; }

    /// <summary>Creates an open resolver policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            OpenResolver = new DesiredStateOpenResolverPolicy {
                Enabled = Enabled,
                RequireAtLeastOneResult = RequireAtLeastOneResult,
                DisallowOpenResolver = DisallowOpenResolver
            }
        };

        WriteObject(profile);
    }
}

