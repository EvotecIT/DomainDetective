using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a TLS-RPT desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Require a valid policy and a vendor-specific rua suffix</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateTlsRpt -Enabled $true -RequireRecord $true -RequireValidPolicy $true -AllowedReportDomainSuffixes tlsrpt.vendor.example</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateTlsRpt")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateTlsRpt : PSCmdlet {
    /// <para>Enable/disable the TLS-RPT desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, require a TLS-RPT record to exist.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireRecord { get; set; }

    /// <para>When true, require at least one reporting URI (rua=).</para>
    [Parameter(Mandatory = false)]
    public bool? RequireRua { get; set; }

    /// <para>When true, require the TLS-RPT record to be syntactically valid.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireValidPolicy { get; set; }

    /// <para>Allowed domain suffixes for TLS-RPT rua endpoints (mailto domains / HTTPS hosts).</para>
    [Parameter(Mandatory = false)]
    public string[]? AllowedReportDomainSuffixes { get; set; }

    /// <summary>Creates a TLS-RPT policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            TlsRpt = new DesiredStateTlsRptPolicy {
                Enabled = Enabled,
                RequireRecord = RequireRecord,
                RequireRua = RequireRua,
                RequireValidPolicy = RequireValidPolicy,
                AllowedReportDomainSuffixes = AllowedReportDomainSuffixes
            }
        };

        WriteObject(profile);
    }
}
