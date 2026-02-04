using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace DomainDetective;

/// <summary>SMTP rules loaded from a JSON file.</summary>
public sealed class EmailSmtpRuleSet {
    public Dictionary<string, EmailSmtpRulePolicy>? ByDomain { get; set; }
    public Dictionary<string, EmailSmtpRulePolicy>? ByMx { get; set; }
    public Dictionary<string, EmailSmtpRulePolicy>? ByMxSuffix { get; set; }
}

/// <summary>SMTP rule settings.</summary>
public sealed class EmailSmtpRulePolicy {
    public bool? DisableCatchAll { get; set; }
    public int? SmtpTimeoutSeconds { get; set; }
    public int? SmtpPortOverride { get; set; }
}

/// <summary>Resolved SMTP rule overrides.</summary>
public sealed class EmailSmtpRuleMatch {
    public bool? DisableCatchAll { get; set; }
    public int? SmtpTimeoutSeconds { get; set; }
    public int? SmtpPortOverride { get; set; }
}

public static class EmailSmtpRuleResolver {
    private const string BuiltinResource = "DomainDetective.email_smtp_rules.json";
    private static readonly object _cacheLock = new();
    private static readonly Dictionary<string, CachedRules> _rulesCache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Lazy<EmailSmtpRuleSet?> _builtinRules = new(LoadBuiltinRules);

    public static EmailSmtpRuleMatch? Resolve(string? domain, IEnumerable<string>? mxHosts, string? rulesPath, bool useBuiltin) {
        var rules = LoadRules(rulesPath, useBuiltin);
        if (rules == null) {
            return null;
        }

        var match = new EmailSmtpRuleMatch();
        bool matched = false;

        if (!string.IsNullOrWhiteSpace(domain) && rules.ByDomain != null) {
            var key = NormalizeKey(domain);
            if (rules.ByDomain.TryGetValue(key, out var policy)) {
                ApplyPolicy(match, policy);
                matched = true;
            }
        }

        if (mxHosts != null) {
            foreach (var host in mxHosts) {
                var normalized = NormalizeKey(host);
                if (normalized.Length == 0) {
                    continue;
                }

                if (rules.ByMx != null && rules.ByMx.TryGetValue(normalized, out var mxPolicy)) {
                    ApplyPolicy(match, mxPolicy);
                    matched = true;
                }

                if (rules.ByMxSuffix != null) {
                    foreach (var suffixRule in rules.ByMxSuffix) {
                        var suffix = NormalizeSuffix(suffixRule.Key);
                        if (suffix.Length == 0) {
                            continue;
                        }
                        if (normalized.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) {
                            ApplyPolicy(match, suffixRule.Value);
                            matched = true;
                        }
                    }
                }
            }
        }

        return matched ? match : null;
    }

    private static void ApplyPolicy(EmailSmtpRuleMatch match, EmailSmtpRulePolicy policy) {
        if (policy.DisableCatchAll.HasValue) {
            match.DisableCatchAll = policy.DisableCatchAll.Value;
        }
        if (policy.SmtpTimeoutSeconds.HasValue) {
            match.SmtpTimeoutSeconds = Math.Max(match.SmtpTimeoutSeconds ?? 0, policy.SmtpTimeoutSeconds.Value);
        }
        if (policy.SmtpPortOverride.HasValue) {
            match.SmtpPortOverride = policy.SmtpPortOverride;
        }
    }

    private static EmailSmtpRuleSet? LoadRules(string? path, bool useBuiltin) {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) {
            return useBuiltin ? _builtinRules.Value : null;
        }

        var fullPath = Path.GetFullPath(path);
        var lastWrite = File.GetLastWriteTimeUtc(fullPath);

        lock (_cacheLock) {
            if (_rulesCache.TryGetValue(fullPath, out var cached) && cached.LastWriteUtc == lastWrite) {
                return cached.Rules;
            }

            var json = File.ReadAllText(fullPath);
            var options = new JsonSerializerOptions {
                PropertyNameCaseInsensitive = true,
                ReadCommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true
            };
            var rules = JsonSerializer.Deserialize<EmailSmtpRuleSet>(json, options);
            if (rules?.ByDomain != null) {
                rules.ByDomain = NormalizeDictionary(rules.ByDomain);
            }
            if (rules?.ByMx != null) {
                rules.ByMx = NormalizeDictionary(rules.ByMx);
            }
            if (rules?.ByMxSuffix != null) {
                rules.ByMxSuffix = NormalizeDictionary(rules.ByMxSuffix, NormalizeSuffix);
            }

            _rulesCache[fullPath] = new CachedRules(lastWrite, rules);
            return rules;
        }
    }

    private static EmailSmtpRuleSet? LoadBuiltinRules() {
        var assembly = typeof(EmailSmtpRuleResolver).Assembly;
        using var stream = assembly.GetManifestResourceStream(BuiltinResource);
        if (stream == null) {
            return null;
        }
        using var reader = new StreamReader(stream);
        var json = reader.ReadToEnd();
        var options = new JsonSerializerOptions {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true
        };
        var rules = JsonSerializer.Deserialize<EmailSmtpRuleSet>(json, options);
        if (rules?.ByDomain != null) {
            rules.ByDomain = NormalizeDictionary(rules.ByDomain);
        }
        if (rules?.ByMx != null) {
            rules.ByMx = NormalizeDictionary(rules.ByMx);
        }
        if (rules?.ByMxSuffix != null) {
            rules.ByMxSuffix = NormalizeDictionary(rules.ByMxSuffix, NormalizeSuffix);
        }
        return rules;
    }

    private static Dictionary<string, EmailSmtpRulePolicy> NormalizeDictionary(Dictionary<string, EmailSmtpRulePolicy> source, Func<string, string>? normalizer = null) {
        var normalized = new Dictionary<string, EmailSmtpRulePolicy>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in source) {
            var key = normalizer != null ? normalizer(pair.Key) : NormalizeKey(pair.Key);
            if (key.Length == 0 || pair.Value == null) {
                continue;
            }
            normalized[key] = pair.Value;
        }
        return normalized;
    }

    private static string NormalizeKey(string value) {
        return (value ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
    }

    private static string NormalizeSuffix(string value) {
        var trimmed = NormalizeKey(value);
        if (trimmed.Length == 0) {
            return string.Empty;
        }
        return trimmed.StartsWith('.') ? trimmed : "." + trimmed;
    }

    private sealed class CachedRules {
        public CachedRules(DateTime lastWriteUtc, EmailSmtpRuleSet? rules) {
            LastWriteUtc = lastWriteUtc;
            Rules = rules;
        }

        public DateTime LastWriteUtc { get; }
        public EmailSmtpRuleSet? Rules { get; }
    }
}
