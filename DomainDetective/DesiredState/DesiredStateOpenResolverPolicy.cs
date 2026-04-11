using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state open resolver policy functionality.</summary>
public sealed class DesiredStateOpenResolverPolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>Gets or sets the require at least one result value.</summary>
    [JsonPropertyName("requireAtLeastOneResult")]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <summary>Gets or sets the disallow open resolver value.</summary>
    [JsonPropertyName("disallowOpenResolver")]
    public bool? DisallowOpenResolver { get; set; }

    /// <summary>Executes the clone operation.</summary>
    public DesiredStateOpenResolverPolicy Clone() {
        return new DesiredStateOpenResolverPolicy {
            Enabled = Enabled,
            RequireAtLeastOneResult = RequireAtLeastOneResult,
            DisallowOpenResolver = DisallowOpenResolver
        };
    }

    /// <summary>Executes the apply operation.</summary>
    public void Apply(DesiredStateOpenResolverPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireAtLeastOneResult.HasValue) RequireAtLeastOneResult = overlay.RequireAtLeastOneResult;
        if (overlay.DisallowOpenResolver.HasValue) DisallowOpenResolver = overlay.DisallowOpenResolver;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireAtLeastOneResult ??= false;
        DisallowOpenResolver ??= true;
    }
}

