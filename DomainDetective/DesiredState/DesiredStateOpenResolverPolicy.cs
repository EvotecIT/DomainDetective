using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateOpenResolverPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireAtLeastOneResult")]
    public bool? RequireAtLeastOneResult { get; set; }

    [JsonPropertyName("disallowOpenResolver")]
    public bool? DisallowOpenResolver { get; set; }

    public DesiredStateOpenResolverPolicy Clone() {
        return new DesiredStateOpenResolverPolicy {
            Enabled = Enabled,
            RequireAtLeastOneResult = RequireAtLeastOneResult,
            DisallowOpenResolver = DisallowOpenResolver
        };
    }

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

