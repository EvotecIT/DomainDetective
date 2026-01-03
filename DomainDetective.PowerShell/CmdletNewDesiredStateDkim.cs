using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a DKIM desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Require two selectors and a minimum key length</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateDkim -Enabled $true -RequiredSelectors selector1,selector2 -MinKeyBits 2048</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateDkim")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateDkim : PSCmdlet {
    /// <para>Enable/disable the DKIM desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, requires at least one DKIM selector to be analyzed.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAtLeastOneSelector { get; set; }

    /// <para>Selectors that must exist and publish DKIM records (organization-specific).</para>
    [Parameter(Mandatory = false)]
    public string[]? RequiredSelectors { get; set; }

    /// <para>Minimum accepted key length in bits for selectors.</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, 16384)]
    public int? MinKeyBits { get; set; }

    /// <para>Allowed domain suffixes for selector CNAME targets (vendor-hosted DKIM).</para>
    [Parameter(Mandatory = false)]
    public string[]? AllowedCnameTargetSuffixes { get; set; }

    /// <summary>Creates a DKIM policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            Dkim = new DesiredStateDkimPolicy {
                Enabled = Enabled,
                RequireAtLeastOneSelector = RequireAtLeastOneSelector,
                RequiredSelectors = RequiredSelectors,
                MinKeyBits = MinKeyBits,
                AllowedCnameTargetSuffixes = AllowedCnameTargetSuffixes
            }
        };

        WriteObject(profile);
    }
}
