using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateDkimPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>When true, requires at least one DKIM selector to be analyzed.</summary>
    [JsonPropertyName("requireAtLeastOneSelector")]
    public bool? RequireAtLeastOneSelector { get; set; }

    /// <summary>When true, requires DKIM records to start with v=DKIM1.</summary>
    [JsonPropertyName("requireStartsCorrectly")]
    public bool? RequireStartsCorrectly { get; set; }

    /// <summary>When true, requires DKIM records to contain a non-empty p= public key.</summary>
    [JsonPropertyName("requirePublicKey")]
    public bool? RequirePublicKey { get; set; }

    /// <summary>When true, requires DKIM public keys to be parseable/valid.</summary>
    [JsonPropertyName("requireValidPublicKey")]
    public bool? RequireValidPublicKey { get; set; }

    /// <summary>When true, requires DKIM key type to be recognized (rsa/ed25519).</summary>
    [JsonPropertyName("requireValidKeyType")]
    public bool? RequireValidKeyType { get; set; }

    /// <summary>Selectors that must exist and publish DKIM records (organization-specific).</summary>
    [JsonPropertyName("requiredSelectors")]
    public string[]? RequiredSelectors { get; set; }

    /// <summary>Minimum accepted key length in bits for selectors (best-effort, RSA-focused).</summary>
    [JsonPropertyName("minKeyBits")]
    public int? MinKeyBits { get; set; }

    /// <summary>When true, disallows weak RSA keys (under 2048 bits).</summary>
    [JsonPropertyName("disallowWeakKeys")]
    public bool? DisallowWeakKeys { get; set; }

    /// <summary>Maximum allowed key age in days when a creation date can be inferred.</summary>
    [JsonPropertyName("maxKeyAgeDays")]
    public int? MaxKeyAgeDays { get; set; }

    /// <summary>When true, disallows deprecated DKIM tags/values (e.g., g/q tags, sha1 hashes).</summary>
    [JsonPropertyName("disallowDeprecatedTags")]
    public bool? DisallowDeprecatedTags { get; set; }

    /// <summary>When true, disallows invalid DKIM flags (unknown flag characters).</summary>
    [JsonPropertyName("disallowInvalidFlags")]
    public bool? DisallowInvalidFlags { get; set; }

    /// <summary>When true, disallows unknown canonicalization modes.</summary>
    [JsonPropertyName("disallowUnknownCanonicalizationModes")]
    public bool? DisallowUnknownCanonicalizationModes { get; set; }

    /// <summary>When true, disallows invalid canonicalization strings (when c= is present).</summary>
    [JsonPropertyName("disallowInvalidCanonicalization")]
    public bool? DisallowInvalidCanonicalization { get; set; }

    /// <summary>Allowed domain suffixes for selector CNAME targets (vendor-hosted DKIM).</summary>
    [JsonPropertyName("allowedCnameTargetSuffixes")]
    public string[]? AllowedCnameTargetSuffixes { get; set; }

    public DesiredStateDkimPolicy Clone() {
        return new DesiredStateDkimPolicy {
            Enabled = Enabled,
            RequireAtLeastOneSelector = RequireAtLeastOneSelector,
            RequireStartsCorrectly = RequireStartsCorrectly,
            RequirePublicKey = RequirePublicKey,
            RequireValidPublicKey = RequireValidPublicKey,
            RequireValidKeyType = RequireValidKeyType,
            RequiredSelectors = RequiredSelectors?.ToArray(),
            MinKeyBits = MinKeyBits,
            DisallowWeakKeys = DisallowWeakKeys,
            MaxKeyAgeDays = MaxKeyAgeDays,
            DisallowDeprecatedTags = DisallowDeprecatedTags,
            DisallowInvalidFlags = DisallowInvalidFlags,
            DisallowUnknownCanonicalizationModes = DisallowUnknownCanonicalizationModes,
            DisallowInvalidCanonicalization = DisallowInvalidCanonicalization,
            AllowedCnameTargetSuffixes = AllowedCnameTargetSuffixes?.ToArray()
        };
    }

    public void Apply(DesiredStateDkimPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireAtLeastOneSelector.HasValue) RequireAtLeastOneSelector = overlay.RequireAtLeastOneSelector;
        if (overlay.RequireStartsCorrectly.HasValue) RequireStartsCorrectly = overlay.RequireStartsCorrectly;
        if (overlay.RequirePublicKey.HasValue) RequirePublicKey = overlay.RequirePublicKey;
        if (overlay.RequireValidPublicKey.HasValue) RequireValidPublicKey = overlay.RequireValidPublicKey;
        if (overlay.RequireValidKeyType.HasValue) RequireValidKeyType = overlay.RequireValidKeyType;
        if (overlay.RequiredSelectors != null) RequiredSelectors = overlay.RequiredSelectors.ToArray();
        if (overlay.MinKeyBits.HasValue) MinKeyBits = overlay.MinKeyBits;
        if (overlay.DisallowWeakKeys.HasValue) DisallowWeakKeys = overlay.DisallowWeakKeys;
        if (overlay.MaxKeyAgeDays.HasValue) MaxKeyAgeDays = overlay.MaxKeyAgeDays;
        if (overlay.DisallowDeprecatedTags.HasValue) DisallowDeprecatedTags = overlay.DisallowDeprecatedTags;
        if (overlay.DisallowInvalidFlags.HasValue) DisallowInvalidFlags = overlay.DisallowInvalidFlags;
        if (overlay.DisallowUnknownCanonicalizationModes.HasValue) DisallowUnknownCanonicalizationModes = overlay.DisallowUnknownCanonicalizationModes;
        if (overlay.DisallowInvalidCanonicalization.HasValue) DisallowInvalidCanonicalization = overlay.DisallowInvalidCanonicalization;
        if (overlay.AllowedCnameTargetSuffixes != null) AllowedCnameTargetSuffixes = overlay.AllowedCnameTargetSuffixes.ToArray();
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireStartsCorrectly ??= false;
        RequirePublicKey ??= false;
        RequireValidPublicKey ??= false;
        RequireValidKeyType ??= false;
        DisallowWeakKeys ??= false;
        DisallowDeprecatedTags ??= false;
        DisallowInvalidFlags ??= false;
        DisallowUnknownCanonicalizationModes ??= false;
        DisallowInvalidCanonicalization ??= false;
    }
}
