using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateSmtpBannerPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireAtLeastOneResult")]
    public bool? RequireAtLeastOneResult { get; set; }

    [JsonPropertyName("requireValidFormat")]
    public bool? RequireValidFormat { get; set; }

    [JsonPropertyName("requireStartsWith220")]
    public bool? RequireStartsWith220 { get; set; }

    [JsonPropertyName("requireDomainPresent")]
    public bool? RequireDomainPresent { get; set; }

    [JsonPropertyName("disallowTruncated")]
    public bool? DisallowTruncated { get; set; }

    [JsonPropertyName("maxResponseTimeMs")]
    public int? MaxResponseTimeMs { get; set; }

    [JsonPropertyName("requireTlsAdvertised")]
    public bool? RequireTlsAdvertised { get; set; }

    [JsonPropertyName("disallowVersionLeak")]
    public bool? DisallowVersionLeak { get; set; }

    /// <summary>Allowed suffixes for the hostname found in the 220 greeting (e.g., mx.provider.example).</summary>
    [JsonPropertyName("allowedServerDomainSuffixes")]
    public string[]? AllowedServerDomainSuffixes { get; set; }

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

