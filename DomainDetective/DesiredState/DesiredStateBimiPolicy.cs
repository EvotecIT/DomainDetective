using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state bimi policy functionality.</summary>
public sealed class DesiredStateBimiPolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>Gets or sets the require record value.</summary>
    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    /// <summary>When true, requires the domain not to decline publishing a BIMI indicator (l= and/or a= must be present).</summary>
    [JsonPropertyName("requireIndicator")]
    public bool? RequireIndicator { get; set; }

    /// <summary>When true, requires a valid https://...svg(.svgz) location.</summary>
    [JsonPropertyName("requireValidLocation")]
    public bool? RequireValidLocation { get; set; }

    /// <summary>Allowed host suffixes for the indicator URL (vendor-hosted BIMI).</summary>
    [JsonPropertyName("allowedLocationHostSuffixes")]
    public string[]? AllowedLocationHostSuffixes { get; set; }

    /// <summary>When true, requires an authority (VMC) URL.</summary>
    [JsonPropertyName("requireAuthority")]
    public bool? RequireAuthority { get; set; }

    /// <summary>Allowed host suffixes for the authority URL (vendor-hosted VMC).</summary>
    [JsonPropertyName("allowedAuthorityHostSuffixes")]
    public string[]? AllowedAuthorityHostSuffixes { get; set; }

    /// <summary>When true, do not download the indicator SVG as part of the BIMI check.</summary>
    [JsonPropertyName("skipIndicatorDownload")]
    public bool? SkipIndicatorDownload { get; set; }

    /// <summary>Executes the clone operation.</summary>
    public DesiredStateBimiPolicy Clone() {
        return new DesiredStateBimiPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            RequireIndicator = RequireIndicator,
            RequireValidLocation = RequireValidLocation,
            AllowedLocationHostSuffixes = AllowedLocationHostSuffixes?.ToArray(),
            RequireAuthority = RequireAuthority,
            AllowedAuthorityHostSuffixes = AllowedAuthorityHostSuffixes?.ToArray(),
            SkipIndicatorDownload = SkipIndicatorDownload
        };
    }

    /// <summary>Executes the apply operation.</summary>
    public void Apply(DesiredStateBimiPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.RequireIndicator.HasValue) RequireIndicator = overlay.RequireIndicator;
        if (overlay.RequireValidLocation.HasValue) RequireValidLocation = overlay.RequireValidLocation;
        if (overlay.AllowedLocationHostSuffixes != null) AllowedLocationHostSuffixes = overlay.AllowedLocationHostSuffixes.ToArray();
        if (overlay.RequireAuthority.HasValue) RequireAuthority = overlay.RequireAuthority;
        if (overlay.AllowedAuthorityHostSuffixes != null) AllowedAuthorityHostSuffixes = overlay.AllowedAuthorityHostSuffixes.ToArray();
        if (overlay.SkipIndicatorDownload.HasValue) SkipIndicatorDownload = overlay.SkipIndicatorDownload;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireRecord ??= false;
        RequireIndicator ??= false;
        RequireValidLocation ??= false;
        RequireAuthority ??= false;
        SkipIndicatorDownload ??= true;
    }
}
