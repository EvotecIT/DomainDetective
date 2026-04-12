using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state mail latency policy functionality.</summary>
public sealed class DesiredStateMailLatencyPolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>Gets or sets the require at least one result value.</summary>
    [JsonPropertyName("requireAtLeastOneResult")]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <summary>Gets or sets the require all connect success value.</summary>
    [JsonPropertyName("requireAllConnectSuccess")]
    public bool? RequireAllConnectSuccess { get; set; }

    /// <summary>Gets or sets the require all banner success value.</summary>
    [JsonPropertyName("requireAllBannerSuccess")]
    public bool? RequireAllBannerSuccess { get; set; }

    /// <summary>Gets or sets the max connect time ms value.</summary>
    [JsonPropertyName("maxConnectTimeMs")]
    public int? MaxConnectTimeMs { get; set; }

    /// <summary>Gets or sets the max banner time ms value.</summary>
    [JsonPropertyName("maxBannerTimeMs")]
    public int? MaxBannerTimeMs { get; set; }

    /// <summary>Executes the clone operation.</summary>
    public DesiredStateMailLatencyPolicy Clone() {
        return new DesiredStateMailLatencyPolicy {
            Enabled = Enabled,
            RequireAtLeastOneResult = RequireAtLeastOneResult,
            RequireAllConnectSuccess = RequireAllConnectSuccess,
            RequireAllBannerSuccess = RequireAllBannerSuccess,
            MaxConnectTimeMs = MaxConnectTimeMs,
            MaxBannerTimeMs = MaxBannerTimeMs
        };
    }

    /// <summary>Executes the apply operation.</summary>
    public void Apply(DesiredStateMailLatencyPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireAtLeastOneResult.HasValue) RequireAtLeastOneResult = overlay.RequireAtLeastOneResult;
        if (overlay.RequireAllConnectSuccess.HasValue) RequireAllConnectSuccess = overlay.RequireAllConnectSuccess;
        if (overlay.RequireAllBannerSuccess.HasValue) RequireAllBannerSuccess = overlay.RequireAllBannerSuccess;
        if (overlay.MaxConnectTimeMs.HasValue) MaxConnectTimeMs = overlay.MaxConnectTimeMs;
        if (overlay.MaxBannerTimeMs.HasValue) MaxBannerTimeMs = overlay.MaxBannerTimeMs;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireAtLeastOneResult ??= false;
        RequireAllConnectSuccess ??= false;
        RequireAllBannerSuccess ??= false;
    }
}

