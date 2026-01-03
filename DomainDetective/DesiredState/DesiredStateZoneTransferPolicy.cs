using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateZoneTransferPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>When true, no authoritative server may allow unauthenticated AXFR.</summary>
    [JsonPropertyName("disallowUnauthenticatedAxfr")]
    public bool? DisallowUnauthenticatedAxfr { get; set; }

    public DesiredStateZoneTransferPolicy Clone() {
        return new DesiredStateZoneTransferPolicy {
            Enabled = Enabled,
            DisallowUnauthenticatedAxfr = DisallowUnauthenticatedAxfr
        };
    }

    public void Apply(DesiredStateZoneTransferPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.DisallowUnauthenticatedAxfr.HasValue) DisallowUnauthenticatedAxfr = overlay.DisallowUnauthenticatedAxfr;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        DisallowUnauthenticatedAxfr ??= true;
    }
}
