using DomainDetective.Helpers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DomainDetective;

/// <summary>
/// Organization policy override configuration for certificate inventory policy evaluation.
/// </summary>
public sealed class CertificateInventoryPolicyOverrides {
    public const int SupportedVersion = 1;

    [JsonPropertyName("$schema")]
    public string? Schema { get; set; }

    [JsonPropertyName("version")]
    public int Version { get; set; } = 1;

    [JsonPropertyName("defaults")]
    public CertificateInventoryPolicyOverrideAction Defaults { get; set; } = new();

    [JsonPropertyName("rules")]
    public List<CertificateInventoryPolicyOverrideRule> Rules { get; set; } = new();

    /// <summary>
    /// Loads and validates policy override configuration from disk.
    /// </summary>
    public static CertificateInventoryPolicyOverrides Load(string path) {
        if (string.IsNullOrWhiteSpace(path)) {
            throw new ArgumentException("Path cannot be empty or whitespace.", nameof(path));
        }

        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath)) {
            throw new FileNotFoundException($"Policy overrides configuration file not found: '{fullPath}'.", fullPath);
        }

        const long maxBytes = 1L * 1024L * 1024L;
        var fileInfo = new FileInfo(fullPath);
        if (fileInfo.Length > maxBytes) {
            throw new InvalidOperationException($"Policy overrides configuration file is too large ({fileInfo.Length} bytes > {maxBytes} bytes): '{fullPath}'.");
        }

        string json;
        try {
            json = File.ReadAllText(fullPath, Encoding.UTF8);
        } catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) {
            throw new IOException($"Failed to read policy overrides configuration file: '{fullPath}'.", ex);
        }

        var overrides = JsonSerializer.Deserialize<CertificateInventoryPolicyOverrides>(json, JsonOptions.Default)
                        ?? throw new InvalidOperationException($"Failed to deserialize policy overrides configuration from '{fullPath}'.");

        overrides.ValidateAndNormalize();
        return overrides;
    }

    internal CertificateInventoryPolicyResolvedOverride ResolveForEndpoint(
        string host,
        string service,
        int port,
        string fallbackBaselineProfile) {
        var effectiveBaselineProfile = fallbackBaselineProfile;
        var suppressedViolationCodes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var appliedRuleNames = new List<string>();

        var defaults = Defaults ?? new CertificateInventoryPolicyOverrideAction();
        var rules = Rules ?? new List<CertificateInventoryPolicyOverrideRule>();

        ApplyAction(defaults, "defaults");
        for (var i = 0; i < rules.Count; i++) {
            var rule = rules[i];
            if (rule == null) {
                continue;
            }

            if (!rule.IsMatch(host, service, port)) {
                continue;
            }

            var ruleName = string.IsNullOrWhiteSpace(rule.Name) ? $"rule-{i + 1}" : rule.Name!.Trim();
            appliedRuleNames.Add(ruleName);
            ApplyAction(rule.Action, $"rules[{i}]");
        }

        return new CertificateInventoryPolicyResolvedOverride {
            EffectiveBaselineProfile = effectiveBaselineProfile,
            SuppressedViolationCodes = suppressedViolationCodes.OrderBy(code => code, StringComparer.OrdinalIgnoreCase).ToList(),
            AppliedRuleNames = appliedRuleNames
        };

        void ApplyAction(CertificateInventoryPolicyOverrideAction action, string source) {
            if (action == null) {
                return;
            }

            if (!string.IsNullOrWhiteSpace(action.BaselineProfile)) {
                if (!CertificateInventoryPolicyAnalyzer.TryResolveBaselineProfile(action.BaselineProfile, out var normalizedProfile)) {
                    throw new InvalidOperationException(
                        $"Policy overrides {source}.baselineProfile '{action.BaselineProfile}' must be one of: {CertificateInventoryPolicyAnalyzer.BaselineProfileAcceptedValues}.");
                }

                effectiveBaselineProfile = normalizedProfile;
            }

            foreach (var code in NormalizeValues(action.SuppressViolationCodes)) {
                suppressedViolationCodes.Add(code);
            }
        }
    }

    private void ValidateAndNormalize() {
        if (Version < 1) {
            throw new InvalidOperationException($"Policy overrides version must be >= 1 (found {Version}).");
        }

        if (Version > SupportedVersion) {
            throw new InvalidOperationException($"Policy overrides version {Version} is newer than supported version {SupportedVersion}.");
        }

        Defaults ??= new CertificateInventoryPolicyOverrideAction();
        Rules ??= new List<CertificateInventoryPolicyOverrideRule>();

        ValidateAction(Defaults, "defaults");
        Defaults.SuppressViolationCodes = NormalizeValues(Defaults.SuppressViolationCodes);

        for (var i = 0; i < Rules.Count; i++) {
            var rule = Rules[i] ?? new CertificateInventoryPolicyOverrideRule();
            Rules[i] = rule;

            var match = rule.Match ?? new CertificateInventoryPolicyOverrideMatch();
            rule.Match = match;
            var action = rule.Action ?? new CertificateInventoryPolicyOverrideAction();
            rule.Action = action;

            var ruleName = rule.Name;
            if (ruleName == null) {
                rule.Name = null;
            } else {
                var trimmedRuleName = ruleName.Trim();
                rule.Name = trimmedRuleName.Length == 0 ? null : trimmedRuleName;
            }
            match.Hosts = NormalizeValues(match.Hosts);
            match.HostSuffixes = NormalizeValues(match.HostSuffixes);
            match.Services = NormalizeValues(match.Services);
            match.Ports = NormalizePorts(match.Ports, $"rules[{i}].match.ports");
            action.SuppressViolationCodes = NormalizeValues(action.SuppressViolationCodes);

            ValidateAction(action, $"rules[{i}].action");
        }
    }

    private static void ValidateAction(CertificateInventoryPolicyOverrideAction action, string source) {
        if (action == null) {
            return;
        }

        if (!string.IsNullOrWhiteSpace(action.BaselineProfile) &&
            !CertificateInventoryPolicyAnalyzer.TryResolveBaselineProfile(action.BaselineProfile, out _)) {
            throw new InvalidOperationException(
                $"Policy overrides {source}.baselineProfile '{action.BaselineProfile}' must be one of: {CertificateInventoryPolicyAnalyzer.BaselineProfileAcceptedValues}.");
        }
    }

    private static string[] NormalizeValues(IEnumerable<string>? values) {
        if (values == null) {
            return Array.Empty<string>();
        }

        return values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static int[] NormalizePorts(IEnumerable<int>? ports, string source) {
        if (ports == null) {
            return Array.Empty<int>();
        }

        var unique = new HashSet<int>();
        foreach (var port in ports) {
            if (port <= 0 || port > 65535) {
                throw new InvalidOperationException($"Policy overrides {source} contains invalid port '{port}'. Valid range is 1..65535.");
            }

            unique.Add(port);
        }

        return unique.OrderBy(port => port).ToArray();
    }
}

/// <summary>
/// Rule action that modifies effective baseline profile and/or suppresses violation codes.
/// </summary>
public sealed class CertificateInventoryPolicyOverrideAction {
    [JsonPropertyName("baselineProfile")]
    public string? BaselineProfile { get; set; }

    [JsonPropertyName("suppressViolationCodes")]
    public string[] SuppressViolationCodes { get; set; } = Array.Empty<string>();
}

/// <summary>
/// Matching rule applied to endpoint policy evaluation.
/// </summary>
public sealed class CertificateInventoryPolicyOverrideRule {
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("match")]
    public CertificateInventoryPolicyOverrideMatch Match { get; set; } = new();

    [JsonPropertyName("action")]
    public CertificateInventoryPolicyOverrideAction Action { get; set; } = new();

    internal bool IsMatch(string host, string service, int port) {
        var match = Match ?? new CertificateInventoryPolicyOverrideMatch();
        var hosts = match.Hosts ?? Array.Empty<string>();
        var hostSuffixes = match.HostSuffixes ?? Array.Empty<string>();
        var services = match.Services ?? Array.Empty<string>();
        var ports = match.Ports ?? Array.Empty<int>();

        if (hosts.Length > 0) {
            var normalizedHost = DomainHelper.NormalizeForComparison(host);
            var hostMatched = hosts.Any(candidate =>
                string.Equals(normalizedHost, DomainHelper.NormalizeForComparison(candidate), StringComparison.OrdinalIgnoreCase));
            if (!hostMatched) {
                return false;
            }
        }

        if (hostSuffixes.Length > 0) {
            var normalizedHost = DomainHelper.NormalizeForComparison(host);
            var suffixMatched = hostSuffixes.Any(suffix =>
                DomainHelper.IsDomainOrSubdomainOfNormalized(
                    normalizedHost,
                    DomainHelper.NormalizeForComparison(suffix)));
            if (!suffixMatched) {
                return false;
            }
        }

        if (services.Length > 0) {
            var serviceMatched = services.Any(candidate =>
                string.Equals(candidate, service, StringComparison.OrdinalIgnoreCase));
            if (!serviceMatched) {
                return false;
            }
        }

        if (ports.Length > 0 && !ports.Contains(port)) {
            return false;
        }

        return true;
    }
}

/// <summary>
/// Endpoint selector used by policy override rules.
/// </summary>
public sealed class CertificateInventoryPolicyOverrideMatch {
    [JsonPropertyName("hosts")]
    public string[] Hosts { get; set; } = Array.Empty<string>();

    [JsonPropertyName("hostSuffixes")]
    public string[] HostSuffixes { get; set; } = Array.Empty<string>();

    [JsonPropertyName("services")]
    public string[] Services { get; set; } = Array.Empty<string>();

    [JsonPropertyName("ports")]
    public int[] Ports { get; set; } = Array.Empty<int>();
}

internal sealed class CertificateInventoryPolicyResolvedOverride {
    public string EffectiveBaselineProfile { get; set; } = "Balanced";
    public List<string> SuppressedViolationCodes { get; set; } = new();
    public List<string> AppliedRuleNames { get; set; } = new();
}
