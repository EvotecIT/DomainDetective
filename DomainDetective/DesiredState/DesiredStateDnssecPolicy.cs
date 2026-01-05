using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateDnssecPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireChainValid")]
    public bool? RequireChainValid { get; set; }

    /// <summary>Minimum number of days remaining for any RRSIG on the zone.</summary>
    [JsonPropertyName("minRrsigDaysRemaining")]
    public int? MinRrsigDaysRemaining { get; set; }

    public DesiredStateDnssecPolicy Clone() {
        return new DesiredStateDnssecPolicy {
            Enabled = Enabled,
            RequireChainValid = RequireChainValid,
            MinRrsigDaysRemaining = MinRrsigDaysRemaining
        };
    }

    public void Apply(DesiredStateDnssecPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireChainValid.HasValue) RequireChainValid = overlay.RequireChainValid;
        if (overlay.MinRrsigDaysRemaining.HasValue) MinRrsigDaysRemaining = overlay.MinRrsigDaysRemaining;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireChainValid ??= true;
    }
}
