using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state dangling cname policy functionality.</summary>
public sealed class DesiredStateDanglingCnamePolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>When true, disallows a CNAME that exists but does not resolve.</summary>
    [JsonPropertyName("disallowDangling")]
    public bool? DisallowDangling { get; set; }

    /// <summary>When true, disallows dangling CNAMEs that point to known takeover-prone services.</summary>
    [JsonPropertyName("disallowUnclaimedService")]
    public bool? DisallowUnclaimedService { get; set; }

    /// <summary>Executes the clone operation.</summary>
    public DesiredStateDanglingCnamePolicy Clone() {
        return new DesiredStateDanglingCnamePolicy {
            Enabled = Enabled,
            DisallowDangling = DisallowDangling,
            DisallowUnclaimedService = DisallowUnclaimedService
        };
    }

    /// <summary>Executes the apply operation.</summary>
    public void Apply(DesiredStateDanglingCnamePolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.DisallowDangling.HasValue) DisallowDangling = overlay.DisallowDangling;
        if (overlay.DisallowUnclaimedService.HasValue) DisallowUnclaimedService = overlay.DisallowUnclaimedService;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        DisallowDangling ??= true;
        DisallowUnclaimedService ??= true;
    }
}
