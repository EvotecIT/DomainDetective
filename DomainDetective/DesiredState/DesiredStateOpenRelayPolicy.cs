using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateOpenRelayPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireAtLeastOneResult")]
    public bool? RequireAtLeastOneResult { get; set; }

    [JsonPropertyName("disallowOpenRelay")]
    public bool? DisallowOpenRelay { get; set; }

    [JsonPropertyName("treatConnectionFailuresAsDrift")]
    public bool? TreatConnectionFailuresAsDrift { get; set; }

    public DesiredStateOpenRelayPolicy Clone() {
        return new DesiredStateOpenRelayPolicy {
            Enabled = Enabled,
            RequireAtLeastOneResult = RequireAtLeastOneResult,
            DisallowOpenRelay = DisallowOpenRelay,
            TreatConnectionFailuresAsDrift = TreatConnectionFailuresAsDrift
        };
    }

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

