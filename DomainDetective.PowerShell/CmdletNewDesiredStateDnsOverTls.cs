using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a DNS over TLS desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
[Cmdlet(VerbsCommon.New, "DDDesiredStateDnsOverTls")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateDnsOverTls : PSCmdlet {
    /// <para>Enable/disable the DNS over TLS desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, warns if no DNS over TLS results were analyzed.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <para>When true, requires at least one authoritative server to support DNS over TLS.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAnySupported { get; set; }

    /// <para>When true, requires all probed authoritative servers to support DNS over TLS.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAllSupported { get; set; }

    /// <para>When true, requires supported servers to present a valid certificate chain.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireCertificateValid { get; set; }

    /// <para>When true, requires supported servers to present a certificate matching the name server hostname.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireHostnameMatch { get; set; }

    /// <summary>Creates a DNS over TLS policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            DnsOverTls = new DesiredStateDnsOverTlsPolicy {
                Enabled = Enabled,
                RequireAtLeastOneResult = RequireAtLeastOneResult,
                RequireAnySupported = RequireAnySupported,
                RequireAllSupported = RequireAllSupported,
                RequireCertificateValid = RequireCertificateValid,
                RequireHostnameMatch = RequireHostnameMatch
            }
        };

        WriteObject(profile);
    }
}

