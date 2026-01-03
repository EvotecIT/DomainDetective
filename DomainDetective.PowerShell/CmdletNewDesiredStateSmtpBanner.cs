using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates an SMTP banner desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Require banners to present an expected domain suffix</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateSmtpBanner -Enabled $true -AllowedServerDomainSuffixes protection.outlook.com</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateSmtpBanner")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateSmtpBanner : PSCmdlet {
    /// <para>Enable/disable the SMTP banner desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, require at least one SMTP banner result to be present.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <para>When true, require RFC-compliant banner format.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireValidFormat { get; set; }

    /// <para>When true, require banners to start with 220.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireStartsWith220 { get; set; }

    /// <para>When true, require banners to include a domain name.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireDomainPresent { get; set; }

    /// <para>When true, disallow truncated banners.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowTruncated { get; set; }

    /// <para>Maximum allowed banner response time in milliseconds.</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(1, int.MaxValue)]
    public int? MaxResponseTimeMs { get; set; }

    /// <para>When true, require the banner to advertise TLS.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireTlsAdvertised { get; set; }

    /// <para>When true, disallow banners leaking software versions.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowVersionLeak { get; set; }

    /// <para>Allowed suffixes for the hostname found in the 220 greeting.</para>
    [Parameter(Mandatory = false)]
    public string[]? AllowedServerDomainSuffixes { get; set; }

    /// <summary>Creates an SMTP banner policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            SmtpBanner = new DesiredStateSmtpBannerPolicy {
                Enabled = Enabled,
                RequireAtLeastOneResult = RequireAtLeastOneResult,
                RequireValidFormat = RequireValidFormat,
                RequireStartsWith220 = RequireStartsWith220,
                RequireDomainPresent = RequireDomainPresent,
                DisallowTruncated = DisallowTruncated,
                MaxResponseTimeMs = MaxResponseTimeMs,
                RequireTlsAdvertised = RequireTlsAdvertised,
                DisallowVersionLeak = DisallowVersionLeak,
                AllowedServerDomainSuffixes = AllowedServerDomainSuffixes
            }
        };

        WriteObject(profile);
    }
}

