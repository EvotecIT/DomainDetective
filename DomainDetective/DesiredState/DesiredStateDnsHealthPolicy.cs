using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state dns health policy functionality.</summary>
public sealed class DesiredStateDnsHealthPolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>When true, warns if no DNS health results were analyzed.</summary>
    [JsonPropertyName("requireAtLeastOneResult")]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <summary>Gets or sets the require servers responsive value.</summary>
    [JsonPropertyName("requireServersResponsive")]
    public bool? RequireServersResponsive { get; set; }

    /// <summary>Gets or sets the require soa serial consistent value.</summary>
    [JsonPropertyName("requireSoaSerialConsistent")]
    public bool? RequireSoaSerialConsistent { get; set; }

    /// <summary>Gets or sets the require apex addresses consistent value.</summary>
    [JsonPropertyName("requireApexAddressesConsistent")]
    public bool? RequireApexAddressesConsistent { get; set; }

    /// <summary>Executes the clone operation.</summary>
    public DesiredStateDnsHealthPolicy Clone() {
        return new DesiredStateDnsHealthPolicy {
            Enabled = Enabled,
            RequireAtLeastOneResult = RequireAtLeastOneResult,
            RequireServersResponsive = RequireServersResponsive,
            RequireSoaSerialConsistent = RequireSoaSerialConsistent,
            RequireApexAddressesConsistent = RequireApexAddressesConsistent
        };
    }

    /// <summary>Executes the apply operation.</summary>
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
