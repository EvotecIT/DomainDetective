using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state open relay policy functionality.</summary>
public sealed class DesiredStateOpenRelayPolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>Gets or sets the require at least one result value.</summary>
    [JsonPropertyName("requireAtLeastOneResult")]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <summary>Gets or sets the disallow open relay value.</summary>
    [JsonPropertyName("disallowOpenRelay")]
    public bool? DisallowOpenRelay { get; set; }

    /// <summary>Gets or sets the treat connection failures as drift value.</summary>
    [JsonPropertyName("treatConnectionFailuresAsDrift")]
    public bool? TreatConnectionFailuresAsDrift { get; set; }

    /// <summary>Executes the clone operation.</summary>
    public DesiredStateOpenRelayPolicy Clone() {
        return new DesiredStateOpenRelayPolicy {
            Enabled = Enabled,
            RequireAtLeastOneResult = RequireAtLeastOneResult,
            DisallowOpenRelay = DisallowOpenRelay,
            TreatConnectionFailuresAsDrift = TreatConnectionFailuresAsDrift
        };
    }

    /// <summary>Executes the apply operation.</summary>
    public void Apply(DesiredStateOpenRelayPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireAtLeastOneResult.HasValue) RequireAtLeastOneResult = overlay.RequireAtLeastOneResult;
        if (overlay.DisallowOpenRelay.HasValue) DisallowOpenRelay = overlay.DisallowOpenRelay;
        if (overlay.TreatConnectionFailuresAsDrift.HasValue) TreatConnectionFailuresAsDrift = overlay.TreatConnectionFailuresAsDrift;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireAtLeastOneResult ??= false;
        DisallowOpenRelay ??= true;
        TreatConnectionFailuresAsDrift ??= false;
    }
}

