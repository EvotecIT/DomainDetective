using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state smtp banner policy functionality.</summary>
public sealed class DesiredStateSmtpBannerPolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>Gets or sets the require at least one result value.</summary>
    [JsonPropertyName("requireAtLeastOneResult")]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <summary>Gets or sets the require valid format value.</summary>
    [JsonPropertyName("requireValidFormat")]
    public bool? RequireValidFormat { get; set; }

    /// <summary>Gets or sets the require starts with220 value.</summary>
    [JsonPropertyName("requireStartsWith220")]
    public bool? RequireStartsWith220 { get; set; }

    /// <summary>Gets or sets the require domain present value.</summary>
    [JsonPropertyName("requireDomainPresent")]
    public bool? RequireDomainPresent { get; set; }

    /// <summary>Gets or sets the disallow truncated value.</summary>
    [JsonPropertyName("disallowTruncated")]
    public bool? DisallowTruncated { get; set; }

    /// <summary>Gets or sets the max response time ms value.</summary>
    [JsonPropertyName("maxResponseTimeMs")]
    public int? MaxResponseTimeMs { get; set; }

    /// <summary>Gets or sets the require tls advertised value.</summary>
    [JsonPropertyName("requireTlsAdvertised")]
    public bool? RequireTlsAdvertised { get; set; }

    /// <summary>Gets or sets the disallow version leak value.</summary>
    [JsonPropertyName("disallowVersionLeak")]
    public bool? DisallowVersionLeak { get; set; }

    /// <summary>Allowed suffixes for the hostname found in the 220 greeting (e.g., mx.provider.example).</summary>
    [JsonPropertyName("allowedServerDomainSuffixes")]
    public string[]? AllowedServerDomainSuffixes { get; set; }

    /// <summary>Executes the clone operation.</summary>
    public DesiredStateSmtpBannerPolicy Clone() {
        return new DesiredStateSmtpBannerPolicy {
            Enabled = Enabled,
            RequireAtLeastOneResult = RequireAtLeastOneResult,
            RequireValidFormat = RequireValidFormat,
            RequireStartsWith220 = RequireStartsWith220,
            RequireDomainPresent = RequireDomainPresent,
            DisallowTruncated = DisallowTruncated,
            MaxResponseTimeMs = MaxResponseTimeMs,
            RequireTlsAdvertised = RequireTlsAdvertised,
            DisallowVersionLeak = DisallowVersionLeak,
            AllowedServerDomainSuffixes = AllowedServerDomainSuffixes?.ToArray()
        };
    }

    /// <summary>Executes the apply operation.</summary>
    public void Apply(DesiredStateSmtpBannerPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireAtLeastOneResult.HasValue) RequireAtLeastOneResult = overlay.RequireAtLeastOneResult;
        if (overlay.RequireValidFormat.HasValue) RequireValidFormat = overlay.RequireValidFormat;
        if (overlay.RequireStartsWith220.HasValue) RequireStartsWith220 = overlay.RequireStartsWith220;
        if (overlay.RequireDomainPresent.HasValue) RequireDomainPresent = overlay.RequireDomainPresent;
        if (overlay.DisallowTruncated.HasValue) DisallowTruncated = overlay.DisallowTruncated;
        if (overlay.MaxResponseTimeMs.HasValue) MaxResponseTimeMs = overlay.MaxResponseTimeMs;
        if (overlay.RequireTlsAdvertised.HasValue) RequireTlsAdvertised = overlay.RequireTlsAdvertised;
        if (overlay.DisallowVersionLeak.HasValue) DisallowVersionLeak = overlay.DisallowVersionLeak;
        if (overlay.AllowedServerDomainSuffixes != null) AllowedServerDomainSuffixes = overlay.AllowedServerDomainSuffixes.ToArray();
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireAtLeastOneResult ??= false;
        RequireValidFormat ??= false;
        RequireStartsWith220 ??= false;
        RequireDomainPresent ??= false;
        DisallowTruncated ??= false;
        RequireTlsAdvertised ??= false;
        DisallowVersionLeak ??= false;
    }
}

