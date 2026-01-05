using System.Management.Automation;
using DomainDetective.Definitions;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a DANE desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
[Cmdlet(VerbsCommon.New, "DDDesiredStateDane")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateDane : PSCmdlet {
    /// <para>Enable/disable the DANE desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, requires a DANE record to exist (overall or for selected services).</para>
    [Parameter(Mandatory = false)]
    public bool? RequireRecord { get; set; }

    /// <para>When true, requires DANE records to be valid.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireValidRecords { get; set; }

    /// <para>When true, disallows duplicate TLSA records.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowDuplicates { get; set; }

    /// <para>Service types for which DANE is required.</para>
    [Parameter(Mandatory = false)]
    public ServiceType[]? RequiredServices { get; set; }

    /// <para>When true, requires recommended DANE configuration for SMTP.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireRecommendedForSmtp { get; set; }

    /// <para>When true, requires recommended DANE configuration for HTTPS.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireRecommendedForHttps { get; set; }

    /// <summary>Creates a DANE policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            Dane = new DesiredStateDanePolicy {
                Enabled = Enabled,
                RequireRecord = RequireRecord,
                RequireValidRecords = RequireValidRecords,
                DisallowDuplicates = DisallowDuplicates,
                RequiredServices = RequiredServices,
                RequireRecommendedForSmtp = RequireRecommendedForSmtp,
                RequireRecommendedForHttps = RequireRecommendedForHttps
            }
        };

        WriteObject(profile);
    }
}

