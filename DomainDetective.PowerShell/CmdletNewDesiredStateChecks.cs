using System;
using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a desired state fragment that controls which checks are executed.</summary>
/// <para>Use this to enable/disable specific HealthCheckType modules for the effective profile.</para>
/// <example>
///   <summary>Run only DMARC/SPF/DKIM checks</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateChecks -Checks DMARC,SPF,DKIM</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateChecks")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateChecks : PSCmdlet {
    /// <para>Checks to execute for the desired state profile.</para>
    [Parameter(Mandatory = true)]
    [ValidateNotNull]
    public HealthCheckType[] Checks { get; set; } = Array.Empty<HealthCheckType>();

    /// <summary>Creates a checks fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        WriteObject(new DesiredStateProfile { Checks = Checks });
    }
}
