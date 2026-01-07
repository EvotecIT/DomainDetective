using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates best-practice settings for Desired State evaluation.</summary>
/// <para>The returned object can be applied in New-DDDesiredState to override the best-practice check set.</para>
/// <example>
///   <summary>Enable active mail probes for best-practice gaps</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateBestPractices -IncludeActiveMailProbes</code>
///   <para>Adds SMTP/IMAP/POP probes to the recommended best-practice checks.</para>
/// </example>
/// <example>
///   <summary>Override the best-practice check set</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateBestPractices -Checks DMARC,SPF,DKIM,MTASTS,TLSRPT</code>
///   <para>Uses only the specified checks when DesiredStateMode is BestPracticesForUnspecified.</para>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateBestPractices")]
[OutputType(typeof(DesiredStateBestPracticeSettings))]
public sealed class CmdletNewDesiredStateBestPractices : PSCmdlet {
    /// <summary>Optional list of checks to use as the best-practice baseline.</summary>
    [Parameter(Mandatory = false)]
    public HealthCheckType[]? Checks { get; set; }

    /// <summary>Include SMTP/IMAP/POP active probes in the best-practice set.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter IncludeActiveMailProbes { get; set; }

    /// <summary>Writes the best-practice settings object.</summary>
    protected override void ProcessRecord() {
        var settings = new DesiredStateBestPracticeSettings {
            Checks = Checks,
            IncludeActiveMailProbes = IncludeActiveMailProbes.IsPresent
        };

        WriteObject(settings);
    }
}
