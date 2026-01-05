using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates an EDNS support desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
[Cmdlet(VerbsCommon.New, "DDDesiredStateEdnsSupport")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateEdnsSupport : PSCmdlet {
    /// <para>Enable/disable the EDNS support desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, warns if no EDNS results were analyzed.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <para>When true, requires all authoritative server endpoints to support EDNS.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAllServersSupported { get; set; }

    /// <para>Optional maximum EDNS UDP payload size (bytes) that servers are allowed to advertise.</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MaxUdpPayloadSize { get; set; }

    /// <para>When true, requires EDNS version 0.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireVersionZero { get; set; }

    /// <para>When true, requires authoritative servers to support DNS Cookies.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireCookieSupport { get; set; }

    /// <summary>Creates an EDNS support policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            EdnsSupport = new DesiredStateEdnsSupportPolicy {
                Enabled = Enabled,
                RequireAtLeastOneResult = RequireAtLeastOneResult,
                RequireAllServersSupported = RequireAllServersSupported,
                MaxUdpPayloadSize = MaxUdpPayloadSize,
                RequireVersionZero = RequireVersionZero,
                RequireCookieSupport = RequireCookieSupport
            }
        };

        WriteObject(profile);
    }
}

