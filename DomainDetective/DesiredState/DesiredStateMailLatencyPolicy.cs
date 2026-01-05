using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateMailLatencyPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireAtLeastOneResult")]
    public bool? RequireAtLeastOneResult { get; set; }

    [JsonPropertyName("requireAllConnectSuccess")]
    public bool? RequireAllConnectSuccess { get; set; }

    [JsonPropertyName("requireAllBannerSuccess")]
    public bool? RequireAllBannerSuccess { get; set; }

    [JsonPropertyName("maxConnectTimeMs")]
    public int? MaxConnectTimeMs { get; set; }

    [JsonPropertyName("maxBannerTimeMs")]
    public int? MaxBannerTimeMs { get; set; }

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

