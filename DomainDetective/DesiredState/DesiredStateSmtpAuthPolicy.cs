using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state smtp auth policy functionality.</summary>
public sealed class DesiredStateSmtpAuthPolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>Gets or sets the require at least one result value.</summary>
    [JsonPropertyName("requireAtLeastOneResult")]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <summary>When true, disallows any SMTP AUTH advertisement on any server.</summary>
    [JsonPropertyName("disallowAuthAdvertisement")]
    public bool? DisallowAuthAdvertisement { get; set; }

    /// <summary>When specified, all advertised mechanisms must be within this allow list.</summary>
    [JsonPropertyName("allowedMechanisms")]
    public string[]? AllowedMechanisms { get; set; }

    /// <summary>When specified, none of the advertised mechanisms may be present.</summary>
    [JsonPropertyName("disallowedMechanisms")]
    public string[]? DisallowedMechanisms { get; set; }

    /// <summary>When specified, requires at least one of the mechanisms to be present per server advertising AUTH.</summary>
    [JsonPropertyName("requiredMechanismsAnyOf")]
    public string[]? RequiredMechanismsAnyOf { get; set; }

    /// <summary>When true, requires STARTTLS capability to be advertised alongside AUTH.</summary>
    [JsonPropertyName("requireStartTlsCapabilityWhenAuth")]
    public bool? RequireStartTlsCapabilityWhenAuth { get; set; }

    /// <summary>Executes the clone operation.</summary>
    public DesiredStateSmtpAuthPolicy Clone() {
        return new DesiredStateSmtpAuthPolicy {
            Enabled = Enabled,
            RequireAtLeastOneResult = RequireAtLeastOneResult,
            DisallowAuthAdvertisement = DisallowAuthAdvertisement,
            AllowedMechanisms = AllowedMechanisms?.ToArray(),
            DisallowedMechanisms = DisallowedMechanisms?.ToArray(),
            RequiredMechanismsAnyOf = RequiredMechanismsAnyOf?.ToArray(),
            RequireStartTlsCapabilityWhenAuth = RequireStartTlsCapabilityWhenAuth
        };
    }

    /// <summary>Executes the apply operation.</summary>
    public void Apply(DesiredStateSmtpAuthPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireAtLeastOneResult.HasValue) RequireAtLeastOneResult = overlay.RequireAtLeastOneResult;
        if (overlay.DisallowAuthAdvertisement.HasValue) DisallowAuthAdvertisement = overlay.DisallowAuthAdvertisement;
        if (overlay.AllowedMechanisms != null) AllowedMechanisms = overlay.AllowedMechanisms.ToArray();
        if (overlay.DisallowedMechanisms != null) DisallowedMechanisms = overlay.DisallowedMechanisms.ToArray();
        if (overlay.RequiredMechanismsAnyOf != null) RequiredMechanismsAnyOf = overlay.RequiredMechanismsAnyOf.ToArray();
        if (overlay.RequireStartTlsCapabilityWhenAuth.HasValue) RequireStartTlsCapabilityWhenAuth = overlay.RequireStartTlsCapabilityWhenAuth;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireAtLeastOneResult ??= false;
        DisallowAuthAdvertisement ??= false;
        RequireStartTlsCapabilityWhenAuth ??= false;
    }
}

