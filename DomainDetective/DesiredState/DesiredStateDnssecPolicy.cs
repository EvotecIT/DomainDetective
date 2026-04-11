using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state dnssec policy functionality.</summary>
public sealed class DesiredStateDnssecPolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>Gets or sets the require chain valid value.</summary>
    [JsonPropertyName("requireChainValid")]
    public bool? RequireChainValid { get; set; }

    /// <summary>Minimum number of days remaining for any RRSIG on the zone.</summary>
    [JsonPropertyName("minRrsigDaysRemaining")]
    public int? MinRrsigDaysRemaining { get; set; }

    /// <summary>Executes the clone operation.</summary>
    public DesiredStateDnssecPolicy Clone() {
        return new DesiredStateDnssecPolicy {
            Enabled = Enabled,
            RequireChainValid = RequireChainValid,
            MinRrsigDaysRemaining = MinRrsigDaysRemaining
        };
    }

    /// <summary>Executes the apply operation.</summary>
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
