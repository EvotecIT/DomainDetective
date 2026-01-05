using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateDelegationPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireMatchesParent")]
    public bool? RequireMatchesParent { get; set; }

    [JsonPropertyName("requireGlueComplete")]
    public bool? RequireGlueComplete { get; set; }

    [JsonPropertyName("requireGlueConsistent")]
    public bool? RequireGlueConsistent { get; set; }

    public DesiredStateDelegationPolicy Clone() {
        return new DesiredStateDelegationPolicy {
            Enabled = Enabled,
            RequireMatchesParent = RequireMatchesParent,
            RequireGlueComplete = RequireGlueComplete,
            RequireGlueConsistent = RequireGlueConsistent
        };
    }

    public void Apply(DesiredStateDelegationPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireMatchesParent.HasValue) RequireMatchesParent = overlay.RequireMatchesParent;
        if (overlay.RequireGlueComplete.HasValue) RequireGlueComplete = overlay.RequireGlueComplete;
        if (overlay.RequireGlueConsistent.HasValue) RequireGlueConsistent = overlay.RequireGlueConsistent;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireMatchesParent ??= true;
        RequireGlueComplete ??= true;
        RequireGlueConsistent ??= true;
    }
}
