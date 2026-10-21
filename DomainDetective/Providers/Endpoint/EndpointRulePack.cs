using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DomainDetective.Providers.Endpoint;

/// <summary>Typed evidence predicates supported by portable endpoint rule data.</summary>
[JsonConverter(typeof(EndpointMatcherTypeConverter))]
[System.ComponentModel.TypeConverter(typeof(EndpointMatcherConfigurationConverter))]
public enum EndpointMatcherType {
    /// <summary>An unspecified matcher is invalid.</summary>
    Undefined,
    /// <summary>A prefix of the normalized hostname, normally ending with a label separator.</summary>
    LabelPrefix,
    /// <summary>A hostname suffix, with a DNS label boundary.</summary>
    HostnameSuffix,
    /// <summary>A bounded regular expression over the normalized hostname.</summary>
    HostnameRegex,
    /// <summary>An observed IPv4 or IPv6 address inside a configured CIDR.</summary>
    IpCidr,
    /// <summary>A target in the observed CNAME chain.</summary>
    CnameSuffix,
    /// <summary>The live certificate's issuer text.</summary>
    LiveIssuer,
    /// <summary>A valid four-octet address embedded in the hostname.</summary>
    IpEmbeddedLabel,
    /// <summary>An address inside an externally supplied Azure service tag.</summary>
    AzureServiceTag,
    /// <summary>A bounded regular expression over an observed CNAME target.</summary>
    CnameRegex
}

/// <summary>Presentation effects carried by rules; applying organizational policy belongs to the consumer.</summary>
[JsonConverter(typeof(EndpointRuleEffectConverter))]
[System.ComponentModel.TypeConverter(typeof(EndpointEffectConfigurationConverter))]
public enum EndpointRuleEffect {
    /// <summary>Preserve all ordinary actions and add a tag.</summary>
    TagOnly,
    /// <summary>Leave the evidence available and omit it from owner projections.</summary>
    ExcludeFromOwnerViews,
    /// <summary>Keep evidence in a separately auditable quarantine projection.</summary>
    Quarantine
}

/// <summary>One typed matcher; any configured value satisfies the matcher.</summary>
public sealed class EndpointRuleMatcher {
    /// <summary>Evidence operation to evaluate.</summary>
    public EndpointMatcherType Type { get; set; }
    /// <summary>Matcher operands. The embedded-address detector needs no operands.</summary>
    public List<string> Values { get; set; } = new();
}

/// <summary>A versioned, explainable classification rule, optionally also used by the attribution scorer.</summary>
public sealed class EndpointPackRule {
    /// <summary>Stable rule identifier within the pack.</summary>
    public string Id { get; set; } = string.Empty;
    /// <summary>Three-part data revision.</summary>
    public string Version { get; set; } = "1.0.0";
    /// <summary>Whether this rule participates.</summary>
    public bool Enabled { get; set; } = true;
    /// <summary>Whether exact classification participates, independently of a legacy scoring candidate.</summary>
    public bool ClassificationEnabled { get; set; } = true;
    /// <summary>Optional earlier report key for configuration migration.</summary>
    public string LegacyKey { get; set; } = string.Empty;
    /// <summary>Readable tag.</summary>
    public string Label { get; set; } = string.Empty;
    /// <summary>Purpose of the rule; actual matched evidence is recorded separately.</summary>
    public string Reason { get; set; } = string.Empty;
    /// <summary>Default effect unless the deployment overrides its pack.</summary>
    public EndpointRuleEffect Effect { get; set; }
    /// <summary>Every matcher in this collection must pass.</summary>
    public List<EndpointRuleMatcher> AllOf { get; set; } = new();
    /// <summary>At least one matcher must pass when this collection is nonempty.</summary>
    public List<EndpointRuleMatcher> AnyOf { get; set; } = new();
    /// <summary>Optional provider identifier for the existing attribution scorer.</summary>
    public string ProviderId { get; set; } = string.Empty;
    /// <summary>Service identifier for technical attribution, independent of policy.</summary>
    public string ServiceId { get; set; } = string.Empty;
    /// <summary>Optional stable legacy attribution rule id.</summary>
    public string AttributionRuleId { get; set; } = string.Empty;
    /// <summary>Ports this rule can classify; empty permits any port.</summary>
    public List<int> Ports { get; set; } = new();
    /// <summary>Services this rule can classify; empty permits any service.</summary>
    public List<string> Services { get; set; } = new();
    /// <summary>Legacy attribution score threshold.</summary>
    public double MinimumScore { get; set; } = .5;
    /// <summary>Require independent corroboration for a point-in-time address seed in the scorer.</summary>
    public bool RequireAddressCorroboration { get; set; }
    /// <summary>Use CNAME suffix data for redirect-target attribution as well.</summary>
    public bool MatchRedirectTargets { get; set; }
}

/// <summary>A portable data pack. Deployment overlays replace rules by id without mutating built-ins.</summary>
public sealed class EndpointRulePack {
    /// <summary>Stable pack identifier.</summary>
    public string Id { get; set; } = string.Empty;
    /// <summary>Three-part version; overlays may inherit the built-in version.</summary>
    public string Version { get; set; } = string.Empty;
    /// <summary>Operator-facing purpose/provenance.</summary>
    public string Description { get; set; } = string.Empty;
    /// <summary>Whether the pack is enabled.</summary>
    public bool Enabled { get; set; } = true;
    /// <summary>Explicit deployment expectation, separate from a technical provider tag.</summary>
    public bool Expected { get; set; }
    /// <summary>Optional override of the contained rules' default effects.</summary>
    public EndpointRuleEffect? Effect { get; set; }
    /// <summary>Versioned rule definitions or rule overlays.</summary>
    public List<EndpointPackRule> Rules { get; set; } = new();
}

/// <summary>Deployment pack configuration; provider expectations are always opt-in.</summary>
public sealed class EndpointRulePackOptions {
    /// <summary>Include embedded generic pack data before applying deployment overlays.</summary>
    public bool UseBuiltInPacks { get; set; } = true;
    /// <summary>Additional packs or overrides matched by pack and rule id.</summary>
    public List<EndpointRulePack> Packs { get; set; } = new();
}

/// <summary>Serializes matcher names using the portable kebab-case contract.</summary>
public sealed class EndpointMatcherTypeConverter : JsonConverter<EndpointMatcherType> {
    /// <inheritdoc />
    public override EndpointMatcherType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) {
        string value = reader.GetString() ?? string.Empty;
        if (string.IsNullOrEmpty(value) || !char.IsLetter(value[0]) || !Enum.TryParse(value.Replace("-", ""), true, out EndpointMatcherType result) || result == EndpointMatcherType.Undefined || !Enum.IsDefined(typeof(EndpointMatcherType), result))
            throw new JsonException("Unsupported endpoint matcher type.");
        return result;
    }
    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, EndpointMatcherType value, JsonSerializerOptions options)
        => writer.WriteStringValue(System.Text.RegularExpressions.Regex.Replace(value.ToString(), "(?<!^)([A-Z])", "-$1").ToLowerInvariant());
}

/// <summary>Serializes effect names using the portable contract.</summary>
public sealed class EndpointRuleEffectConverter : JsonConverter<EndpointRuleEffect> {
    /// <inheritdoc />
    public override EndpointRuleEffect Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) => reader.GetString() switch {
        "tag-only" => EndpointRuleEffect.TagOnly,
        "exclude-from-owner-views" => EndpointRuleEffect.ExcludeFromOwnerViews,
        "quarantine" => EndpointRuleEffect.Quarantine,
        _ => throw new JsonException("Unsupported endpoint rule effect.")
    };
    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, EndpointRuleEffect value, JsonSerializerOptions options) => writer.WriteStringValue(value switch {
        EndpointRuleEffect.TagOnly => "tag-only",
        EndpointRuleEffect.ExcludeFromOwnerViews => "exclude-from-owner-views",
        EndpointRuleEffect.Quarantine => "quarantine",
        _ => throw new JsonException("Unsupported endpoint rule effect.")
    });
}
