using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateRobotsPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    /// <summary>When true, disallows fallback to HTTP when HTTPS retrieval fails.</summary>
    [JsonPropertyName("disallowFallback")]
    public bool? DisallowFallback { get; set; }

    /// <summary>When true, requires at least one AI bot rule to be present.</summary>
    [JsonPropertyName("requireAiBotRules")]
    public bool? RequireAiBotRules { get; set; }

    /// <summary>When true, requires at least one sitemap entry.</summary>
    [JsonPropertyName("requireSitemap")]
    public bool? RequireSitemap { get; set; }

    public DesiredStateRobotsPolicy Clone() {
        return new DesiredStateRobotsPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            DisallowFallback = DisallowFallback,
            RequireAiBotRules = RequireAiBotRules,
            RequireSitemap = RequireSitemap
        };
    }

    public void Apply(DesiredStateRobotsPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.DisallowFallback.HasValue) DisallowFallback = overlay.DisallowFallback;
        if (overlay.RequireAiBotRules.HasValue) RequireAiBotRules = overlay.RequireAiBotRules;
        if (overlay.RequireSitemap.HasValue) RequireSitemap = overlay.RequireSitemap;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireRecord ??= false;
        DisallowFallback ??= false;
        RequireAiBotRules ??= false;
        RequireSitemap ??= false;
    }
}

