using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using DomainDetective.Helpers;

namespace DomainDetective.Providers.Endpoint;

/// <summary>Evaluates explainable, multi-signal provider and managed-service attribution rules.</summary>
public sealed class EndpointAttributionDetector {
    private readonly EndpointAttributionCatalog _catalog;

    /// <summary>Creates a detector using the built-in catalog.</summary>
    public EndpointAttributionDetector()
        : this(EndpointAttributionCatalog.CreateDefault()) {
    }

    /// <summary>Creates a detector using an explicit catalog.</summary>
    public EndpointAttributionDetector(EndpointAttributionCatalog catalog) {
        _catalog = catalog ?? throw new ArgumentNullException(nameof(catalog));
    }

    /// <summary>Evaluates all rules and returns both primary and review candidates.</summary>
    public EndpointAttributionResult Detect(
        EndpointAttributionInput input,
        DateTimeOffset? evaluatedAtUtc = null) {
        if (input == null) {
            throw new ArgumentNullException(nameof(input));
        }

        var candidates = new List<EndpointAttributionCandidate>();
        foreach (EndpointAttributionRule rule in _catalog.Rules) {
            EndpointAttributionCandidate? candidate = Evaluate(rule, input);
            if (candidate != null) {
                candidates.Add(candidate);
            }
        }

        List<EndpointAttributionCandidate> ordered = candidates
            .OrderByDescending(candidate => candidate.Score)
            .ThenBy(candidate => candidate.ProviderId, StringComparer.OrdinalIgnoreCase)
            .ThenBy(candidate => candidate.ServiceId, StringComparer.OrdinalIgnoreCase)
            .ToList();

        List<EndpointAttributionCandidate> eligible = ordered
            .Where(candidate => candidate.EligibleAsPrimary)
            .ToList();
        double? topEligibleScore = eligible.Count == 0 ? null : eligible[0].Score;
        int topIdentityCount = topEligibleScore.HasValue
            ? eligible
                .Where(candidate => Math.Abs(candidate.Score - topEligibleScore.Value) < 0.000001d)
                .Select(candidate => candidate.ProviderId + "\u001f" + candidate.ServiceId)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count()
            : 0;
        bool ambiguous = topIdentityCount > 1;

        return new EndpointAttributionResult {
            Primary = ambiguous ? null : eligible.FirstOrDefault(),
            Candidates = ordered,
            CatalogVersion = _catalog.Version,
            EvaluatedAtUtc = evaluatedAtUtc ?? DateTimeOffset.UtcNow,
            IsAmbiguous = ambiguous,
            AzureServiceTagSource = input.AzureServiceTags?.Source ?? string.Empty,
            AzureServiceTagChangeNumber = input.AzureServiceTags?.ChangeNumber ?? string.Empty,
            AzureServiceTagCloud = input.AzureServiceTags?.Cloud ?? string.Empty,
            AzureServiceTagRetrievedAtUtc = input.AzureServiceTags?.RetrievedAtUtc
        };
    }

    private static EndpointAttributionCandidate? Evaluate(
        EndpointAttributionRule rule,
        EndpointAttributionInput input) {
        if (!AppliesToEndpoint(rule, input)) {
            return null;
        }
        var evidence = new List<EndpointAttributionEvidence>();
        bool hasStrongSignal = false;

        if (TryMatchPrefix(input.HostName, rule.HostnamePrefixes, out string hostnamePattern)) {
            AddEvidence(evidence, EndpointAttributionSignalKind.Hostname, input.HostName, hostnamePattern, 0.25, rule.Source);
        }

        if (TryMatchSuffix(input.CnameChain, rule.CnameSuffixes, out string cname, out string cnameSuffix)) {
            AddEvidence(evidence, EndpointAttributionSignalKind.Cname, cname, cnameSuffix, 0.85, rule.Source);
            hasStrongSignal = true;
        }

        if (TryMatchIpPrefix(input.IpAddresses, rule.IpAddressPrefixes, out string ipAddress, out string ipPrefix)) {
            AddEvidence(evidence, EndpointAttributionSignalKind.IpAddress, ipAddress, ipPrefix, 0.65, rule.Source);
            hasStrongSignal = true;
        }

        if (TryMatchAzureServiceTag(input, rule, out string serviceTagAddress, out string serviceTagName)) {
            string source = input.AzureServiceTags?.Source ?? rule.Source;
            AddEvidence(evidence, EndpointAttributionSignalKind.AzureServiceTag, serviceTagAddress, serviceTagName, 0.75, source);
            hasStrongSignal = true;
        }

        if (TryMatchContains(input.CertificateIssuer, rule.CertificateIssuerContains, out string issuerPattern)) {
            AddEvidence(evidence, EndpointAttributionSignalKind.CertificateIssuer, input.CertificateIssuer, issuerPattern, 0.15, rule.Source);
        }

        if (TryMatchSuffix(input.RedirectTargets, rule.RedirectTargetSuffixes, out string redirect, out string redirectSuffix)) {
            AddEvidence(evidence, EndpointAttributionSignalKind.RedirectTarget, redirect, redirectSuffix, 0.65, rule.Source);
            hasStrongSignal = true;
        }

        if (TryMatchSuffix(input.ReverseDnsNames, rule.ReverseDnsSuffixes, out string reverseDns, out string reverseDnsSuffix)) {
            AddEvidence(evidence, EndpointAttributionSignalKind.ReverseDns, reverseDns, reverseDnsSuffix, 0.55, rule.Source);
            hasStrongSignal = true;
        }

        if (TryMatchExact(input.AutonomousSystemNumbers, rule.AutonomousSystemNumbers, out string autonomousSystem)) {
            AddEvidence(evidence, EndpointAttributionSignalKind.AutonomousSystem, autonomousSystem, autonomousSystem, 0.55, rule.Source);
            hasStrongSignal = true;
        }

        if (evidence.Count == 0) {
            return null;
        }

        double score = Math.Min(1d, evidence.Sum(item => item.Score));
        bool ipNeedsCorroboration = rule.RequireCorroborationForIpAddressPrimary &&
                                    evidence.Any(item => item.Kind == EndpointAttributionSignalKind.IpAddress) &&
                                    !HasAllowedIpCorroboration(rule, evidence);
        bool eligible = score >= Math.Max(0d, Math.Min(1d, rule.MinimumScore)) &&
                        (hasStrongSignal || rule.AllowWeakSignalsAsPrimary) &&
                        !ipNeedsCorroboration;
        return new EndpointAttributionCandidate {
            ProviderId = rule.ProviderId,
            ServiceId = rule.ServiceId,
            DisplayName = rule.DisplayName,
            Score = score,
            Confidence = ResolveConfidence(score),
            EligibleAsPrimary = eligible,
            RuleId = rule.RuleId,
            RuleVersion = rule.RuleVersion,
            Evidence = evidence
        };
    }

    private static bool HasAllowedIpCorroboration(
        EndpointAttributionRule rule,
        IReadOnlyCollection<EndpointAttributionEvidence> evidence) {
        if (rule.IpAddressPrimaryCorroboratingSignals.Count == 0) {
            return evidence.Any(item => item.Kind != EndpointAttributionSignalKind.IpAddress);
        }
        return evidence.Any(item => rule.IpAddressPrimaryCorroboratingSignals.Contains(item.Kind));
    }

    private static bool AppliesToEndpoint(EndpointAttributionRule rule, EndpointAttributionInput input) {
        if (rule.ApplicablePorts.Count > 0 && !rule.ApplicablePorts.Contains(input.Port)) {
            return false;
        }
        if (rule.ApplicableServices.Count == 0) {
            return true;
        }
        string service = (input.Service ?? string.Empty).Trim();
        return rule.ApplicableServices.Any(candidate =>
            string.Equals(candidate?.Trim(), service, StringComparison.OrdinalIgnoreCase));
    }

    private static EndpointAttributionConfidence ResolveConfidence(double score) {
        if (score >= 0.75d) {
            return EndpointAttributionConfidence.High;
        }
        if (score >= 0.5d) {
            return EndpointAttributionConfidence.Medium;
        }
        return EndpointAttributionConfidence.Low;
    }

    private static bool TryMatchPrefix(string? value, IEnumerable<string> patterns, out string pattern) {
        string normalized = NormalizeHost(value);
        foreach (string candidate in patterns.Where(item => !string.IsNullOrWhiteSpace(item))) {
            if (normalized.StartsWith(candidate.Trim(), StringComparison.OrdinalIgnoreCase)) {
                pattern = candidate.Trim();
                return true;
            }
        }
        pattern = string.Empty;
        return false;
    }

    private static bool TryMatchSuffix(
        IEnumerable<string>? values,
        IEnumerable<string> suffixes,
        out string value,
        out string suffix) {
        foreach (string observed in values ?? Array.Empty<string>()) {
            string normalized = NormalizeHost(observed);
            if (normalized.Length == 0) {
                continue;
            }
            foreach (string candidate in suffixes.Where(item => !string.IsNullOrWhiteSpace(item))) {
                string normalizedSuffix = NormalizeHost(candidate);
                if (DomainHelper.IsDomainOrSubdomainOf(normalized, normalizedSuffix)) {
                    value = normalized;
                    suffix = normalizedSuffix;
                    return true;
                }
            }
        }
        value = string.Empty;
        suffix = string.Empty;
        return false;
    }

    private static bool TryMatchIpPrefix(
        IEnumerable<string>? addresses,
        IEnumerable<string> prefixes,
        out string address,
        out string prefix) {
        var parsedPrefixes = prefixes
            .Select(value => IpCidrRange.TryParse(value, out IpCidrRange range) ? (IpCidrRange?)range : null)
            .Where(range => range.HasValue)
            .Select(range => range!.Value)
            .ToList();
        foreach (string observed in addresses ?? Array.Empty<string>()) {
            if (!IPAddress.TryParse((observed ?? string.Empty).Trim(), out IPAddress? parsed) || parsed == null) {
                continue;
            }
            IpCidrRange? matched = parsedPrefixes
                .Where(range => range.Contains(parsed))
                .Select(range => (IpCidrRange?)range)
                .FirstOrDefault();
            if (matched.HasValue) {
                address = parsed.ToString();
                prefix = matched.Value.ToString();
                return true;
            }
        }
        address = string.Empty;
        prefix = string.Empty;
        return false;
    }

    private static bool TryMatchAzureServiceTag(
        EndpointAttributionInput input,
        EndpointAttributionRule rule,
        out string address,
        out string tagName) {
        if (input.AzureServiceTags == null || rule.AzureServiceTagNames.Count == 0) {
            address = string.Empty;
            tagName = string.Empty;
            return false;
        }

        foreach (string observed in input.IpAddresses ?? Array.Empty<string>()) {
            if (!IPAddress.TryParse((observed ?? string.Empty).Trim(), out IPAddress? parsed) || parsed == null) {
                continue;
            }
            IReadOnlyList<string> tags = input.AzureServiceTags.FindTags(parsed, rule.AzureServiceTagNames);
            if (tags.Count > 0) {
                address = parsed.ToString();
                tagName = tags[0];
                return true;
            }
        }

        address = string.Empty;
        tagName = string.Empty;
        return false;
    }

    private static bool TryMatchContains(string? value, IEnumerable<string> patterns, out string pattern) {
        string observed = (value ?? string.Empty).Trim();
        foreach (string candidate in patterns.Where(item => !string.IsNullOrWhiteSpace(item))) {
            if (observed.IndexOf(candidate.Trim(), StringComparison.OrdinalIgnoreCase) >= 0) {
                pattern = candidate.Trim();
                return true;
            }
        }
        pattern = string.Empty;
        return false;
    }

    private static bool TryMatchExact(
        IEnumerable<string>? values,
        IEnumerable<string> patterns,
        out string value) {
        var expected = new HashSet<string>(
            patterns.Where(item => !string.IsNullOrWhiteSpace(item)).Select(item => item.Trim()),
            StringComparer.OrdinalIgnoreCase);
        foreach (string observed in values ?? Array.Empty<string>()) {
            string normalized = (observed ?? string.Empty).Trim();
            if (expected.Contains(normalized)) {
                value = normalized;
                return true;
            }
        }
        value = string.Empty;
        return false;
    }

    private static void AddEvidence(
        ICollection<EndpointAttributionEvidence> evidence,
        EndpointAttributionSignalKind kind,
        string observedValue,
        string matchedValue,
        double score,
        string source) {
        evidence.Add(new EndpointAttributionEvidence {
            Kind = kind,
            ObservedValue = observedValue,
            MatchedValue = matchedValue,
            Score = score,
            Source = source
        });
    }

    private static string NormalizeHost(string? value) =>
        (value ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
}
