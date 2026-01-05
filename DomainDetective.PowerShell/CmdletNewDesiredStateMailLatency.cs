using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a mail latency desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Require all MX hosts to respond within thresholds</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateMailLatency -Enabled $true -RequireAllConnectSuccess $true -MaxConnectTimeMs 2000 -MaxBannerTimeMs 2000</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateMailLatency")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateMailLatency : PSCmdlet {
    /// <para>Enable/disable the mail latency desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, require at least one latency result to be present.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <para>When true, require all servers to successfully connect.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAllConnectSuccess { get; set; }

    /// <para>When true, require all servers to successfully return an SMTP banner.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAllBannerSuccess { get; set; }

    /// <para>Maximum allowed connect time in milliseconds.</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(1, int.MaxValue)]
    public int? MaxConnectTimeMs { get; set; }

    /// <para>Maximum allowed banner read time in milliseconds.</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(1, int.MaxValue)]
    public int? MaxBannerTimeMs { get; set; }

    /// <summary>Creates a mail latency policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            MailLatency = new DesiredStateMailLatencyPolicy {
                Enabled = Enabled,
                RequireAtLeastOneResult = RequireAtLeastOneResult,
                RequireAllConnectSuccess = RequireAllConnectSuccess,
                RequireAllBannerSuccess = RequireAllBannerSuccess,
                MaxConnectTimeMs = MaxConnectTimeMs,
                MaxBannerTimeMs = MaxBannerTimeMs
            }
        };

        WriteObject(profile);
    }
}

