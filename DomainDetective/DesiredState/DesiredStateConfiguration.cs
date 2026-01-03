using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using DomainDetective.Definitions;
using DomainDetective.Helpers;

namespace DomainDetective.DesiredState;

/// <summary>
/// Represents an organization-specific desired state baseline for DomainDetective checks.
/// </summary>
public sealed class DesiredStateConfiguration {
    [JsonPropertyName("$schema")]
    public string? Schema { get; set; }

    [JsonPropertyName("version")]
    public int Version { get; set; } = 1;

    [JsonPropertyName("defaults")]
    public DesiredStateProfile Defaults { get; set; } = new DesiredStateProfile();

    [JsonPropertyName("overrides")]
    public List<DesiredStateOverride> Overrides { get; set; } = new List<DesiredStateOverride>();

    public static DesiredStateConfiguration Load(string path) {
        if (string.IsNullOrWhiteSpace(path)) {
            throw new ArgumentNullException(nameof(path));
        }
        var fullPath = Path.GetFullPath(path);
        var json = File.ReadAllText(fullPath);
        var config = JsonSerializer.Deserialize<DesiredStateConfiguration>(json, JsonOptions.Default);
        if (config == null) {
            throw new InvalidOperationException($"Failed to deserialize desired state configuration from '{fullPath}'.");
        }
        return config;
    }

    public bool RequiresMailClassification() {
        if (Overrides == null || Overrides.Count == 0) return false;
        foreach (var o in Overrides) {
            if (o?.Match?.Classifications != null && o.Match.Classifications.Length > 0) {
                return true;
            }
        }
        return false;
    }

    public DesiredStateProfile ResolveProfile(string domain, MailDomainClassificationCategory? classification = null) {
        if (string.IsNullOrWhiteSpace(domain)) {
            throw new ArgumentNullException(nameof(domain));
        }

        var effective = Defaults?.Clone() ?? new DesiredStateProfile();
        if (Overrides == null || Overrides.Count == 0) {
            effective.Normalize();
            return effective;
        }

        foreach (var o in Overrides) {
            if (o == null) continue;
            if (o.Matches(domain, classification)) {
                effective.Apply(o.Profile);
            }
        }
        effective.Normalize();
        return effective;
    }

    public static HealthCheckType[] GetRequiredChecks(DesiredStateProfile profile) {
        if (profile == null) return Array.Empty<HealthCheckType>();

        var set = new HashSet<HealthCheckType>();

        if (profile.Checks != null) {
            foreach (var c in profile.Checks) set.Add(c);
        }

        if (profile.Dmarc != null && profile.Dmarc.Enabled != false) set.Add(HealthCheckType.DMARC);
        if (profile.Spf != null && profile.Spf.Enabled != false) set.Add(HealthCheckType.SPF);

        return set.ToArray();
    }
}

public sealed class DesiredStateOverride {
    [JsonPropertyName("match")]
    public DesiredStateMatch Match { get; set; } = new DesiredStateMatch();

    [JsonPropertyName("profile")]
    public DesiredStateProfile Profile { get; set; } = new DesiredStateProfile();

    public bool Matches(string domain, MailDomainClassificationCategory? classification)
        => Match != null && Match.Matches(domain, classification);
}

public sealed class DesiredStateMatch {
    [JsonPropertyName("domainPatterns")]
    public string[]? DomainPatterns { get; set; }

    [JsonPropertyName("classifications")]
    public MailDomainClassificationCategory[]? Classifications { get; set; }

    public bool Matches(string domain, MailDomainClassificationCategory? classification) {
        if (string.IsNullOrWhiteSpace(domain)) return false;

        if (Classifications != null && Classifications.Length > 0) {
            if (!classification.HasValue) return false;
            if (!Classifications.Contains(classification.Value)) return false;
        }

        if (DomainPatterns == null || DomainPatterns.Length == 0) return true;

        foreach (var pattern in DomainPatterns) {
            if (string.IsNullOrWhiteSpace(pattern)) continue;
            if (WildcardMatcher.IsMatch(domain, pattern)) return true;
        }
        return false;
    }
}

public sealed class DesiredStateProfile {
    [JsonPropertyName("checks")]
    public HealthCheckType[]? Checks { get; set; }

    [JsonPropertyName("assessmentPolicy")]
    public DesiredStateAssessmentPolicy? AssessmentPolicy { get; set; }

    [JsonPropertyName("dmarc")]
    public DesiredStateDmarcPolicy? Dmarc { get; set; }

    [JsonPropertyName("spf")]
    public DesiredStateSpfPolicy? Spf { get; set; }

    public DesiredStateProfile Clone() {
        return new DesiredStateProfile {
            Checks = Checks?.ToArray(),
            AssessmentPolicy = AssessmentPolicy?.Clone(),
            Dmarc = Dmarc?.Clone(),
            Spf = Spf?.Clone()
        };
    }

    public void Apply(DesiredStateProfile? overlay) {
        if (overlay == null) return;

        if (overlay.Checks != null) {
            Checks = overlay.Checks.ToArray();
        }

        if (overlay.AssessmentPolicy != null) {
            AssessmentPolicy ??= new DesiredStateAssessmentPolicy();
            AssessmentPolicy.Apply(overlay.AssessmentPolicy);
        }

        if (overlay.Dmarc != null) {
            Dmarc ??= new DesiredStateDmarcPolicy();
            Dmarc.Apply(overlay.Dmarc);
        }

        if (overlay.Spf != null) {
            Spf ??= new DesiredStateSpfPolicy();
            Spf.Apply(overlay.Spf);
        }
    }

    public void Normalize() {
        Dmarc?.NormalizeDefaults();
        Spf?.NormalizeDefaults();
    }
}

public sealed class DesiredStateAssessmentPolicy {
    [JsonPropertyName("suppressCodes")]
    public string[]? SuppressCodes { get; set; }

    [JsonPropertyName("severityOverrides")]
    public Dictionary<string, AssessmentSeverity>? SeverityOverrides { get; set; }

    public DesiredStateAssessmentPolicy Clone() {
        return new DesiredStateAssessmentPolicy {
            SuppressCodes = SuppressCodes?.ToArray(),
            SeverityOverrides = SeverityOverrides != null
                ? new Dictionary<string, AssessmentSeverity>(SeverityOverrides, StringComparer.OrdinalIgnoreCase)
                : null
        };
    }

    public void Apply(DesiredStateAssessmentPolicy? overlay) {
        if (overlay == null) return;
        if (overlay.SuppressCodes != null) {
            SuppressCodes = overlay.SuppressCodes.ToArray();
        }
        if (overlay.SeverityOverrides != null) {
            SeverityOverrides = new Dictionary<string, AssessmentSeverity>(overlay.SeverityOverrides, StringComparer.OrdinalIgnoreCase);
        }
    }
}

public sealed class DesiredStateDmarcPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    /// <summary>Allowed DMARC policy values (p= tag), as lowercase strings (none/quarantine/reject).</summary>
    [JsonPropertyName("allowedPolicies")]
    public string[]? AllowedPolicies { get; set; }

    [JsonPropertyName("requireRua")]
    public bool? RequireRua { get; set; }

    /// <summary>Allowed domain suffixes for DMARC rua/ruf URIs (e.g., dmarc.vendor.example).</summary>
    [JsonPropertyName("allowedReportDomainSuffixes")]
    public string[]? AllowedReportDomainSuffixes { get; set; }

    /// <summary>When true, requires external reporting domains to be authorized via _report._dmarc.</summary>
    [JsonPropertyName("requireExternalReportAuthorization")]
    public bool? RequireExternalReportAuthorization { get; set; }

    public DesiredStateDmarcPolicy Clone() {
        return new DesiredStateDmarcPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            AllowedPolicies = AllowedPolicies?.ToArray(),
            RequireRua = RequireRua,
            AllowedReportDomainSuffixes = AllowedReportDomainSuffixes?.ToArray(),
            RequireExternalReportAuthorization = RequireExternalReportAuthorization
        };
    }

    public void Apply(DesiredStateDmarcPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.AllowedPolicies != null) AllowedPolicies = overlay.AllowedPolicies.ToArray();
        if (overlay.RequireRua.HasValue) RequireRua = overlay.RequireRua;
        if (overlay.AllowedReportDomainSuffixes != null) AllowedReportDomainSuffixes = overlay.AllowedReportDomainSuffixes.ToArray();
        if (overlay.RequireExternalReportAuthorization.HasValue) RequireExternalReportAuthorization = overlay.RequireExternalReportAuthorization;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireRecord ??= true;
        RequireRua ??= true;
        RequireExternalReportAuthorization ??= true;
    }
}

public sealed class DesiredStateSpfPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    /// <summary>Allowed all mechanisms, as SPF syntax strings (e.g., "-all", "~all").</summary>
    [JsonPropertyName("allowedAllMechanisms")]
    public string[]? AllowedAllMechanisms { get; set; }

    [JsonPropertyName("maxDnsLookups")]
    public int? MaxDnsLookups { get; set; }

    [JsonPropertyName("requireDenyAll")]
    public bool? RequireDenyAll { get; set; }

    public DesiredStateSpfPolicy Clone() {
        return new DesiredStateSpfPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            AllowedAllMechanisms = AllowedAllMechanisms?.ToArray(),
            MaxDnsLookups = MaxDnsLookups,
            RequireDenyAll = RequireDenyAll
        };
    }

    public void Apply(DesiredStateSpfPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.AllowedAllMechanisms != null) AllowedAllMechanisms = overlay.AllowedAllMechanisms.ToArray();
        if (overlay.MaxDnsLookups.HasValue) MaxDnsLookups = overlay.MaxDnsLookups;
        if (overlay.RequireDenyAll.HasValue) RequireDenyAll = overlay.RequireDenyAll;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireRecord ??= true;
        RequireDenyAll ??= false;
    }
}

internal static class WildcardMatcher {
    public static bool IsMatch(string input, string pattern) {
        if (input == null || pattern == null) return false;
        if (pattern == "*") return true;
        var regex = "^" + System.Text.RegularExpressions.Regex.Escape(pattern)
            .Replace("\\*", ".*")
            .Replace("\\?", ".") + "$";
        return System.Text.RegularExpressions.Regex.IsMatch(
            input,
            regex,
            System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);
    }
}
