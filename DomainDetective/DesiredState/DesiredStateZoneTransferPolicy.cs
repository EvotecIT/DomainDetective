using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state zone transfer policy functionality.</summary>
public sealed class DesiredStateZoneTransferPolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>When true, no authoritative server may allow unauthenticated AXFR.</summary>
    [JsonPropertyName("disallowUnauthenticatedAxfr")]
    public bool? DisallowUnauthenticatedAxfr { get; set; }

    /// <summary>Executes the clone operation.</summary>
    public DesiredStateZoneTransferPolicy Clone() {
        return new DesiredStateZoneTransferPolicy {
            Enabled = Enabled,
            DisallowUnauthenticatedAxfr = DisallowUnauthenticatedAxfr
        };
    }

    /// <summary>Executes the apply operation.</summary>
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
