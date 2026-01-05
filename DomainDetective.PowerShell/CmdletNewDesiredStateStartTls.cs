using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a STARTTLS desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Require STARTTLS support and disallow downgrade signals</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateStartTls -RequireAllServersSupported $true -DisallowDowngradeDetected $true</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateStartTls")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateStartTls : PSCmdlet {
    /// <para>Enable/disable the STARTTLS desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, warns if no STARTTLS results were produced.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <para>When true, requires at least one server to support STARTTLS.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAnyServerSupported { get; set; }

    /// <para>When true, requires all servers to support STARTTLS.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAllServersSupported { get; set; }

    /// <para>When true, treats STARTTLS downgrade detection as drift.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowDowngradeDetected { get; set; }

    /// <summary>Creates a STARTTLS policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            StartTls = new DesiredStateStartTlsPolicy {
                Enabled = Enabled,
                RequireAtLeastOneResult = RequireAtLeastOneResult,
                RequireAnyServerSupported = RequireAnyServerSupported,
                RequireAllServersSupported = RequireAllServersSupported,
                DisallowDowngradeDetected = DisallowDowngradeDetected
            }
        };

        WriteObject(profile);
    }
}

