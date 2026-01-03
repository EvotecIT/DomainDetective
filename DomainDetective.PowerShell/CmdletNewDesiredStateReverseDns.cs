using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a reverse DNS desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Require PTR presence and forward-confirmed reverse DNS</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateReverseDns -RequirePtrPresent $true -RequireForwardConfirmed $true</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateReverseDns")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateReverseDns : PSCmdlet {
    /// <para>Enable/disable the reverse DNS desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, warns if no reverse DNS results were analyzed.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <para>When true, requires each analyzed IP address to have at least one PTR record.</para>
    [Parameter(Mandatory = false)]
    public bool? RequirePtrPresent { get; set; }

    /// <para>When true, requires at least one PTR record to match the expected host name.</para>
    [Parameter(Mandatory = false)]
    public bool? RequirePtrMatchesExpectedHost { get; set; }

    /// <para>Allowed PTR hostname suffixes (e.g., mail.protection.outlook.com).</para>
    [Parameter(Mandatory = false)]
    public string[]? AllowedPtrSuffixes { get; set; }

    /// <para>When true, requires forward-confirmed reverse DNS (FCrDNS) for each IP.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireForwardConfirmed { get; set; }

    /// <summary>Creates a reverse DNS policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            ReverseDns = new DesiredStateReverseDnsPolicy {
                Enabled = Enabled,
                RequireAtLeastOneResult = RequireAtLeastOneResult,
                RequirePtrPresent = RequirePtrPresent,
                RequirePtrMatchesExpectedHost = RequirePtrMatchesExpectedHost,
                AllowedPtrSuffixes = AllowedPtrSuffixes,
                RequireForwardConfirmed = RequireForwardConfirmed
            }
        };

        WriteObject(profile);
    }
}

