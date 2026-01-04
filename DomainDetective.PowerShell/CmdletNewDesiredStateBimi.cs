using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a BIMI desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Require a valid location and allow only vendor-hosted indicator URLs</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateBimi -Enabled $true -RequireValidLocation $true -AllowedLocationHostSuffixes cdn.vendor.example -SkipIndicatorDownload $true</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateBimi")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateBimi : PSCmdlet {
    /// <para>Enable/disable the BIMI desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, require a BIMI DNS record to exist.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireRecord { get; set; }

    /// <para>When true, requires the domain not to decline publishing a BIMI indicator.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireIndicator { get; set; }

    /// <para>When true, requires a valid https://...svg(.svgz) location.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireValidLocation { get; set; }

    /// <para>Allowed host suffixes for the indicator URL (vendor-hosted BIMI).</para>
    [Parameter(Mandatory = false)]
    public string[]? AllowedLocationHostSuffixes { get; set; }

    /// <para>When true, requires an authority (VMC) URL.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAuthority { get; set; }

    /// <para>Allowed host suffixes for the authority URL (vendor-hosted VMC).</para>
    [Parameter(Mandatory = false)]
    public string[]? AllowedAuthorityHostSuffixes { get; set; }

    /// <para>When true, do not download the indicator SVG as part of the BIMI check.</para>
    [Parameter(Mandatory = false)]
    public bool? SkipIndicatorDownload { get; set; }

    /// <summary>Creates a BIMI policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var allowedLocationHostSuffixes = DesiredStateCmdletValidation.NormalizeDomainSuffixes(this, nameof(AllowedLocationHostSuffixes), AllowedLocationHostSuffixes);
        var allowedAuthorityHostSuffixes = DesiredStateCmdletValidation.NormalizeDomainSuffixes(this, nameof(AllowedAuthorityHostSuffixes), AllowedAuthorityHostSuffixes);

        var profile = new DesiredStateProfile {
            Bimi = new DesiredStateBimiPolicy {
                Enabled = Enabled,
                RequireRecord = RequireRecord,
                RequireIndicator = RequireIndicator,
                RequireValidLocation = RequireValidLocation,
                AllowedLocationHostSuffixes = allowedLocationHostSuffixes,
                RequireAuthority = RequireAuthority,
                AllowedAuthorityHostSuffixes = allowedAuthorityHostSuffixes,
                SkipIndicatorDownload = SkipIndicatorDownload
            }
        };

        WriteObject(profile);
    }
}
