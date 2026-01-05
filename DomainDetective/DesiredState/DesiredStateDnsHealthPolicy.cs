using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateDnsHealthPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>When true, warns if no DNS health results were analyzed.</summary>
    [JsonPropertyName("requireAtLeastOneResult")]
    public bool? RequireAtLeastOneResult { get; set; }

    [JsonPropertyName("requireServersResponsive")]
    public bool? RequireServersResponsive { get; set; }

    [JsonPropertyName("requireSoaSerialConsistent")]
    public bool? RequireSoaSerialConsistent { get; set; }

    [JsonPropertyName("requireApexAddressesConsistent")]
    public bool? RequireApexAddressesConsistent { get; set; }

    public DesiredStateDnsHealthPolicy Clone() {
        return new DesiredStateDnsHealthPolicy {
            Enabled = Enabled,
            RequireAtLeastOneResult = RequireAtLeastOneResult,
            RequireServersResponsive = RequireServersResponsive,
            RequireSoaSerialConsistent = RequireSoaSerialConsistent,
            RequireApexAddressesConsistent = RequireApexAddressesConsistent
        };
    }

    public void Apply(DesiredStateDnsHealthPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireAtLeastOneResult.HasValue) RequireAtLeastOneResult = overlay.RequireAtLeastOneResult;
        if (overlay.RequireServersResponsive.HasValue) RequireServersResponsive = overlay.RequireServersResponsive;
        if (overlay.RequireSoaSerialConsistent.HasValue) RequireSoaSerialConsistent = overlay.RequireSoaSerialConsistent;
        if (overlay.RequireApexAddressesConsistent.HasValue) RequireApexAddressesConsistent = overlay.RequireApexAddressesConsistent;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireAtLeastOneResult ??= false;
        RequireServersResponsive ??= false;
        RequireSoaSerialConsistent ??= false;
        RequireApexAddressesConsistent ??= false;
    }
}
