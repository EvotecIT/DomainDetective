using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state delegation policy functionality.</summary>
public sealed class DesiredStateDelegationPolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>Gets or sets the require matches parent value.</summary>
    [JsonPropertyName("requireMatchesParent")]
    public bool? RequireMatchesParent { get; set; }

    /// <summary>Gets or sets the require glue complete value.</summary>
    [JsonPropertyName("requireGlueComplete")]
    public bool? RequireGlueComplete { get; set; }

    /// <summary>Gets or sets the require glue consistent value.</summary>
    [JsonPropertyName("requireGlueConsistent")]
    public bool? RequireGlueConsistent { get; set; }

    /// <summary>Executes the clone operation.</summary>
    public DesiredStateDelegationPolicy Clone() {
        return new DesiredStateDelegationPolicy {
            Enabled = Enabled,
            RequireMatchesParent = RequireMatchesParent,
            RequireGlueComplete = RequireGlueComplete,
            RequireGlueConsistent = RequireGlueConsistent
        };
    }

    /// <summary>Executes the apply operation.</summary>
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
