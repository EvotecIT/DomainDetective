using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace DomainDetective.Providers.Endpoint;

/// <summary>Compiles portable technical rule data once and evaluates endpoint-specific evidence without network access.</summary>
public sealed class EndpointRulePackEvaluator {
    private readonly CompiledRule[] _rules;
    private static readonly TimeSpan RegexBudget = TimeSpan.FromMilliseconds(100);
    private static readonly Regex EmbeddedAddress = new(@"(?:^|[.-])(?:\d{1,3}[.-]){3}\d{1,3}(?:[.-]|$)", RegexOptions.CultureInvariant, RegexBudget);

    private sealed class CompiledRule {
        internal EndpointRulePack Pack = null!;
        internal EndpointPackRule Rule = null!;
        internal Func<EndpointAttributionInput, EndpointRuleSignal?>[] All = Array.Empty<Func<EndpointAttributionInput, EndpointRuleSignal?>>();
        internal Func<EndpointAttributionInput, EndpointRuleSignal?>[] Any = Array.Empty<Func<EndpointAttributionInput, EndpointRuleSignal?>>();
    }

    /// <summary>Snapshots built-in data plus deployment overrides, validating matchers before processing inventory.</summary>
    public EndpointRulePackEvaluator(EndpointRulePackOptions? options = null) {
        _rules = EndpointRulePackCatalog.Resolve(options).Where(p => p.Enabled).SelectMany(pack => pack.Rules.Where(r => r.Enabled && r.ClassificationEnabled).Select(rule => new CompiledRule {
            Pack = pack, Rule = rule, All = rule.AllOf.Select(Compile).ToArray(), Any = rule.AnyOf.Select(Compile).ToArray()
        })).ToArray();
    }

    /// <summary>Returns every matching rule with actual evidence. Input and identity must refer to the same endpoint.</summary>
    public IReadOnlyList<EndpointRuleHit> Evaluate(EndpointAttributionInput input, CertificateObservationIdentity identity, DateTimeOffset observedAtUtc) {
        if (input == null) throw new ArgumentNullException(nameof(input));
        if (identity == null) throw new ArgumentNullException(nameof(identity));
        var endpoint = CertificateEndpointIdentity.Create(input.HostName, input.Port, input.Service);
        if (!endpoint.Equals(identity.Endpoint)) throw new ArgumentException("Classification input and observation refer to different endpoints.", nameof(input));
        // Issuance names may match name rules, but never supply live endpoint evidence.
        if (!identity.IsEndpointObservation) input = new EndpointAttributionInput { HostName = input.HostName, Port = input.Port, Service = input.Service };
        var hits = new List<EndpointRuleHit>();
        foreach (CompiledRule compiled in _rules) {
            EndpointPackRule rule = compiled.Rule;
            if (!identity.IsEndpointObservation && (rule.Ports.Count > 0 || rule.Services.Count > 0)) continue;
            if (rule.Ports.Count > 0 && !rule.Ports.Contains(input.Port)) continue;
            if (rule.Services.Count > 0 && !rule.Services.Contains(input.Service, StringComparer.OrdinalIgnoreCase)) continue;
            var signals = compiled.All.Select(m => m(input)).ToArray();
            if (signals.Any(s => s == null)) continue;
            EndpointRuleSignal[] alternatives = compiled.Any.Select(m => m(input)).OfType<EndpointRuleSignal>().ToArray();
            if (compiled.Any.Length > 0 && alternatives.Length == 0) continue;
            EndpointRuleSignal[] evidence = signals.OfType<EndpointRuleSignal>().Concat(alternatives).ToArray();
            hits.Add(new EndpointRuleHit {
                PackId = compiled.Pack.Id, PackVersion = compiled.Pack.Version, RuleId = rule.Id, RuleVersion = rule.Version,
                Label = rule.Label, ProviderId = rule.ProviderId, ServiceId = rule.ServiceId,
                Effect = compiled.Pack.Effect ?? rule.Effect, Expected = compiled.Pack.Expected,
                Identity = identity, ObservedAtUtc = observedAtUtc, Signals = evidence,
                Reason = rule.Reason + " " + string.Join("; ", evidence.Select(s => $"{s.Type}: {s.Observed} matched {s.Matched}"))
            });
        }
        return hits;
    }

    /// <summary>Counts unique observations/endpoints and per-rule overlaps over exactly the supplied population.</summary>
    public EndpointRuleHitSummary Summarize(IEnumerable<EndpointRuleHit> hits) {
        if (hits == null) throw new ArgumentNullException(nameof(hits));
        EndpointRuleHit[] distinct = hits.GroupBy(h => h.PackId + "\u001f" + h.RuleId + "\u001f" + h.Identity.Key, StringComparer.Ordinal).Select(g => g.First()).ToArray();
        EndpointRuleHit[] excluded = distinct.Where(h => h.Effect != EndpointRuleEffect.TagOnly).ToArray();
        int unique = excluded.Select(h => h.Identity.Key).Distinct(StringComparer.Ordinal).Count();
        return new EndpointRuleHitSummary {
            Rules = _rules.Select(r => {
                EndpointRuleHit[] matching = distinct.Where(h => h.PackId == r.Pack.Id && h.RuleId == r.Rule.Id).ToArray();
                return new EndpointRuleHitCount {
                    PackId = r.Pack.Id, RuleId = r.Rule.Id,
                    MatchedObservations = matching.Select(h => h.Identity.Key).Distinct(StringComparer.Ordinal).Count(),
                    MatchedEndpoints = matching.Where(h => h.Identity.IsEndpointObservation).Select(h => h.Identity.Endpoint.Key).Distinct(StringComparer.Ordinal).Count(),
                    MatchedHosts = matching.Select(h => h.Identity.Endpoint.Host).Distinct(StringComparer.OrdinalIgnoreCase).Count()
                };
            }).ToArray(),
            ExcludedObservations = unique, ExcludedEndpoints = excluded.Where(h => h.Identity.IsEndpointObservation).Select(h => h.Identity.Endpoint.Key).Distinct(StringComparer.Ordinal).Count(),
            MatchedRuleCount = excluded.Select(h => h.PackId + "\u001f" + h.RuleId).Distinct(StringComparer.Ordinal).Count(),
            OverlappingHits = excluded.Length - unique
        };
    }

    internal static void ValidateMatcher(EndpointRuleMatcher matcher) {
        EndpointRulePackCatalog.Require(matcher != null && matcher.Type != EndpointMatcherType.Undefined && Enum.IsDefined(typeof(EndpointMatcherType), matcher.Type), "An enabled rule needs a supported matcher type.");
        EndpointRulePackCatalog.Require(matcher!.Values != null && (matcher.Type == EndpointMatcherType.IpEmbeddedLabel || matcher.Values.Count > 0) && matcher.Values.All(v => !string.IsNullOrWhiteSpace(v)), "A matcher needs nonempty operands.");
        foreach (string value in matcher.Values!) {
            if (matcher.Type == EndpointMatcherType.IpCidr) EndpointRulePackCatalog.Require(IpCidrRange.TryParse(value, out _), "Invalid CIDR operand.");
            if (matcher.Type is EndpointMatcherType.HostnameRegex or EndpointMatcherType.CnameRegex) _ = new Regex(value, RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, RegexBudget);
        }
    }

    private static Func<EndpointAttributionInput, EndpointRuleSignal?> Compile(EndpointRuleMatcher matcher) {
        ValidateMatcher(matcher);
        string[] values = matcher.Values.Select(v => v.Trim()).ToArray();
        Regex[] regexes = matcher.Type is EndpointMatcherType.HostnameRegex or EndpointMatcherType.CnameRegex ? values.Select(v => new Regex(v, RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, RegexBudget)).ToArray() : Array.Empty<Regex>();
        IpCidrRange[] ranges = matcher.Type == EndpointMatcherType.IpCidr ? values.Select(IpCidrRange.Parse).ToArray() : Array.Empty<IpCidrRange>();
        return input => {
            string host = (input.HostName ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
            IEnumerable<string> observed = matcher.Type switch {
                EndpointMatcherType.CnameSuffix or EndpointMatcherType.CnameRegex => input.CnameChain ?? Array.Empty<string>(),
                EndpointMatcherType.IpCidr or EndpointMatcherType.AzureServiceTag => input.IpAddresses ?? Array.Empty<string>(),
                EndpointMatcherType.LiveIssuer => new[] { input.CertificateIssuer ?? string.Empty },
                _ => new[] { host }
            };
            foreach (string raw in observed) {
                if (string.IsNullOrWhiteSpace(raw)) continue;
                if (matcher.Type == EndpointMatcherType.IpEmbeddedLabel) {
                    foreach (Match match in EmbeddedAddress.Matches(host)) {
                        string address = match.Value.Trim('.', '-').Replace('-', '.');
                        if (IPAddress.TryParse(address, out IPAddress? parsed) && parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            return Signal(matcher.Type, host, address);
                    }
                    continue;
                }
                for (int i = 0; i < values.Length; i++) {
                    bool matches = matcher.Type switch {
                        EndpointMatcherType.LabelPrefix => host.StartsWith(values[i], StringComparison.OrdinalIgnoreCase),
                        EndpointMatcherType.HostnameSuffix or EndpointMatcherType.CnameSuffix => Suffix(raw, values[i]),
                        EndpointMatcherType.HostnameRegex => MatchesWithinBudget(regexes[i], host),
                        EndpointMatcherType.CnameRegex => MatchesWithinBudget(regexes[i], raw.Trim().TrimEnd('.')),
                        EndpointMatcherType.LiveIssuer => raw.IndexOf(values[i], StringComparison.OrdinalIgnoreCase) >= 0,
                        EndpointMatcherType.IpCidr => IPAddress.TryParse(raw, out IPAddress? address) && ranges[i].Contains(address),
                        EndpointMatcherType.AzureServiceTag => IPAddress.TryParse(raw, out IPAddress? ip) && input.AzureServiceTags != null && input.AzureServiceTags.Entries.Any(e => string.Equals(e.Name, values[i], StringComparison.OrdinalIgnoreCase) && e.AddressPrefixes.Any(p => p.Contains(ip))),
                        _ => false
                    };
                    if (matches) return Signal(matcher.Type, raw, values[i]);
                }
            }
            return null;
        };
    }

    private static bool MatchesWithinBudget(Regex regex, string value) {
        try {
            return regex.IsMatch(value);
        } catch (RegexMatchTimeoutException) {
            return false;
        }
    }

    private static bool Suffix(string value, string suffix) {
        string host = value.Trim().TrimEnd('.');
        string target = suffix.Trim().TrimStart('*', '.').TrimEnd('.');
        return host.Equals(target, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + target, StringComparison.OrdinalIgnoreCase);
    }
    private static EndpointRuleSignal Signal(EndpointMatcherType type, string observed, string matched) => new() { Type = type, Observed = observed, Matched = matched };
}
