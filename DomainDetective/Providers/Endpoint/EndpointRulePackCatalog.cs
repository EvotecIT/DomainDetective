using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace DomainDetective.Providers.Endpoint;

/// <summary>Loads versioned pack data and resolves deployment overlays without changing shared defaults.</summary>
public static class EndpointRulePackCatalog {
    internal static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true, UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow };

    /// <summary>Loads a fresh copy of the generic built-ins embedded from maintained JSON data.</summary>
    public static IReadOnlyList<EndpointRulePack> LoadBuiltIns() {
        using Stream stream = typeof(EndpointRulePackCatalog).Assembly.GetManifestResourceStream("DomainDetective.EndpointRulePacks.json")
            ?? throw new InvalidOperationException("Embedded endpoint rule packs are missing.");
        using var reader = new StreamReader(stream);
        return Parse(reader.ReadToEnd());
    }

    /// <summary>Parses and validates pack data from a deployment file without accessing network or credentials.</summary>
    public static IReadOnlyList<EndpointRulePack> Parse(string json) {
        var options = JsonSerializer.Deserialize<EndpointRulePackOptions>(json, JsonOptions)
            ?? throw new FormatException("Endpoint rule-pack data is empty.");
        // Parsing a document never implicitly imports the embedded defaults.
        options.UseBuiltInPacks = false;
        return Resolve(options);
    }

    /// <summary>Adds, overrides or disables packs and rules by stable identifiers.</summary>
    public static IReadOnlyList<EndpointRulePack> Resolve(EndpointRulePackOptions? options) {
        options ??= new EndpointRulePackOptions();
        var packs = (options.UseBuiltInPacks ? LoadBuiltIns() : Array.Empty<EndpointRulePack>()).ToDictionary(p => p.Id, StringComparer.OrdinalIgnoreCase);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (EndpointRulePack overlay in options.Packs ?? throw new ArgumentException("Packs cannot be null.")) {
            Require(overlay != null && ValidId(overlay.Id), "A pack needs a lower-case stable id.");
            Require(seen.Add(overlay!.Id), "A deployment defines the same pack more than once.");
            EndpointRulePack copy = Clone(overlay);
            if (packs.TryGetValue(copy.Id, out EndpointRulePack? original)) {
                if (string.IsNullOrWhiteSpace(copy.Version)) copy.Version = original.Version;
                if (string.IsNullOrWhiteSpace(copy.Description)) copy.Description = original.Description;
                var rules = original.Rules.ToDictionary(r => r.Id, StringComparer.OrdinalIgnoreCase);
                var ruleIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (EndpointPackRule rule in copy.Rules ?? throw new ArgumentException("Rules cannot be null.")) {
                    Require(rule != null && ValidId(rule.Id) && ruleIds.Add(rule.Id), "An overlay has a missing or duplicate rule id.");
                    rules[rule!.Id] = rule;
                }
                copy.Rules = rules.Values.ToList();
            }
            packs[copy.Id] = copy;
        }
        foreach (EndpointRulePack pack in packs.Values) Validate(pack);
        return packs.Values.OrderBy(p => p.Id, StringComparer.Ordinal).ToArray();
    }

    internal static void Validate(EndpointRulePack pack) {
        Require(ValidId(pack.Id), "A pack needs a lower-case stable id.");
        if (!pack.Enabled) return;
        Require(Version.TryParse(pack.Version, out Version? version) && version.Build >= 0 && version.Revision < 0, "A pack needs a three-part version.");
        Require(pack.Effect == null || Enum.IsDefined(typeof(EndpointRuleEffect), pack.Effect.Value), "Invalid pack effect.");
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (EndpointPackRule rule in pack.Rules ?? throw new ArgumentException("Rules cannot be null.")) {
            Require(rule != null && ValidId(rule.Id) && ids.Add(rule.Id), "A pack has a missing or duplicate rule id.");
            if (!rule!.Enabled) continue;
            Require(Version.TryParse(rule.Version, out Version? revision) && revision.Build >= 0 && revision.Revision < 0, "A rule needs a three-part version.");
            Require(!string.IsNullOrWhiteSpace(rule.Label), "An enabled rule needs a label.");
            Require(Enum.IsDefined(typeof(EndpointRuleEffect), rule.Effect), "Invalid rule effect.");
            Require(rule.AllOf != null && rule.AnyOf != null && rule.AllOf.Count + rule.AnyOf.Count > 0, "An enabled rule needs match criteria.");
            Require(rule.Ports != null && rule.Ports.All(p => p is > 0 and <= 65535), "Invalid rule port.");
            Require(rule.Services != null && rule.Services.All(s => !string.IsNullOrWhiteSpace(s)), "Invalid rule service.");
            foreach (EndpointRuleMatcher matcher in rule.AllOf!.Concat(rule.AnyOf!)) EndpointRulePackEvaluator.ValidateMatcher(matcher);
        }
    }

    private static bool ValidId(string? id) => !string.IsNullOrWhiteSpace(id) && id![0] is >= 'a' and <= 'z' && id.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '.');
    private static EndpointRulePack Clone(EndpointRulePack pack) => JsonSerializer.Deserialize<EndpointRulePack>(JsonSerializer.Serialize(pack, JsonOptions), JsonOptions)!;
    internal static void Require(bool condition, string message) { if (!condition) throw new ArgumentException(message); }

    /// <summary>Builds the existing scoring catalogue from the same provider signatures used by pack matching.</summary>
    internal static EndpointAttributionCatalog CreateAttributionCatalog() {
        var catalog = new EndpointAttributionCatalog();
        foreach (EndpointRulePack pack in LoadBuiltIns()) {
            foreach (EndpointPackRule source in pack.Rules.Where(r => !string.IsNullOrWhiteSpace(r.AttributionRuleId))) {
                var rule = new EndpointAttributionRule {
                    RuleId = source.AttributionRuleId, RuleVersion = EndpointAttributionCatalog.BuiltInVersion,
                    ProviderId = source.ProviderId, ServiceId = source.ServiceId, DisplayName = source.Label,
                    Source = pack.Description, MinimumScore = source.MinimumScore,
                    RequireCorroborationForIpAddressPrimary = source.RequireAddressCorroboration
                };
                rule.ApplicablePorts.AddRange(source.Ports);
                rule.ApplicableServices.AddRange(source.Services);
                foreach (EndpointRuleMatcher matcher in source.AllOf.Concat(source.AnyOf).Where(m => m.AttributionEnabled)) {
                    switch (matcher.Type) {
                        case EndpointMatcherType.LabelPrefix: rule.HostnamePrefixes.AddRange(matcher.Values); break;
                        case EndpointMatcherType.CnameSuffix:
                            rule.CnameSuffixes.AddRange(matcher.Values);
                            if (source.MatchRedirectTargets) rule.RedirectTargetSuffixes.AddRange(matcher.Values);
                            break;
                        case EndpointMatcherType.LiveIssuer: rule.CertificateIssuerContains.AddRange(matcher.Values); break;
                        case EndpointMatcherType.IpCidr: rule.IpAddressPrefixes.AddRange(matcher.Values); break;
                        case EndpointMatcherType.AzureServiceTag: rule.AzureServiceTagNames.AddRange(matcher.Values); break;
                    }
                }
                if (source.RequireAddressCorroboration) rule.IpAddressPrimaryCorroboratingSignals.AddRange(new[] { EndpointAttributionSignalKind.Cname, EndpointAttributionSignalKind.RedirectTarget });
                catalog.Rules.Add(rule);
            }
        }
        return catalog;
    }
}
