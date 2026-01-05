using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateStartTlsPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>When true, warns if no STARTTLS results were produced.</summary>
    [JsonPropertyName("requireAtLeastOneResult")]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <summary>When true, requires at least one server to support STARTTLS.</summary>
    [JsonPropertyName("requireAnyServerSupported")]
    public bool? RequireAnyServerSupported { get; set; }

    /// <summary>When true, requires all servers to support STARTTLS.</summary>
    [JsonPropertyName("requireAllServersSupported")]
    public bool? RequireAllServersSupported { get; set; }

    /// <summary>When true, treats STARTTLS downgrade detection as drift.</summary>
    [JsonPropertyName("disallowDowngradeDetected")]
    public bool? DisallowDowngradeDetected { get; set; }

    public DesiredStateStartTlsPolicy Clone() {
        return new DesiredStateStartTlsPolicy {
            Enabled = Enabled,
            RequireAtLeastOneResult = RequireAtLeastOneResult,
            RequireAnyServerSupported = RequireAnyServerSupported,
            RequireAllServersSupported = RequireAllServersSupported,
            DisallowDowngradeDetected = DisallowDowngradeDetected
        };
    }

    public void Apply(DesiredStateStartTlsPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireAtLeastOneResult.HasValue) RequireAtLeastOneResult = overlay.RequireAtLeastOneResult;
        if (overlay.RequireAnyServerSupported.HasValue) RequireAnyServerSupported = overlay.RequireAnyServerSupported;
        if (overlay.RequireAllServersSupported.HasValue) RequireAllServersSupported = overlay.RequireAllServersSupported;
        if (overlay.DisallowDowngradeDetected.HasValue) DisallowDowngradeDetected = overlay.DisallowDowngradeDetected;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireAtLeastOneResult ??= false;
        RequireAnyServerSupported ??= false;
        RequireAllServersSupported ??= true;
        DisallowDowngradeDetected ??= true;
    }
}
