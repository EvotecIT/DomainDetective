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
        if (profile.Dkim != null && profile.Dkim.Enabled != false) set.Add(HealthCheckType.DKIM);
        if (profile.Mtasts != null && profile.Mtasts.Enabled != false) set.Add(HealthCheckType.MTASTS);
        if (profile.TlsRpt != null && profile.TlsRpt.Enabled != false) set.Add(HealthCheckType.TLSRPT);
        if (profile.Bimi != null && profile.Bimi.Enabled != false) set.Add(HealthCheckType.BIMI);

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

    [JsonPropertyName("dkim")]
    public DesiredStateDkimPolicy? Dkim { get; set; }

    [JsonPropertyName("mtasts")]
    public DesiredStateMtastsPolicy? Mtasts { get; set; }

    [JsonPropertyName("tlsrpt")]
    public DesiredStateTlsRptPolicy? TlsRpt { get; set; }

    [JsonPropertyName("bimi")]
    public DesiredStateBimiPolicy? Bimi { get; set; }

    public DesiredStateProfile Clone() {
        return new DesiredStateProfile {
            Checks = Checks?.ToArray(),
            AssessmentPolicy = AssessmentPolicy?.Clone(),
            Dmarc = Dmarc?.Clone(),
            Spf = Spf?.Clone(),
            Dkim = Dkim?.Clone(),
            Mtasts = Mtasts?.Clone(),
            TlsRpt = TlsRpt?.Clone(),
            Bimi = Bimi?.Clone()
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

        if (overlay.Dkim != null) {
            Dkim ??= new DesiredStateDkimPolicy();
            Dkim.Apply(overlay.Dkim);
        }

        if (overlay.Mtasts != null) {
            Mtasts ??= new DesiredStateMtastsPolicy();
            Mtasts.Apply(overlay.Mtasts);
        }

        if (overlay.TlsRpt != null) {
            TlsRpt ??= new DesiredStateTlsRptPolicy();
            TlsRpt.Apply(overlay.TlsRpt);
        }

        if (overlay.Bimi != null) {
            Bimi ??= new DesiredStateBimiPolicy();
            Bimi.Apply(overlay.Bimi);
        }
    }

    public void Normalize() {
        Dmarc?.NormalizeDefaults();
        Spf?.NormalizeDefaults();
        Dkim?.NormalizeDefaults();
        Mtasts?.NormalizeDefaults();
        TlsRpt?.NormalizeDefaults();
        Bimi?.NormalizeDefaults();
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

public sealed class DesiredStateDkimPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>When true, requires at least one DKIM selector to be analyzed.</summary>
    [JsonPropertyName("requireAtLeastOneSelector")]
    public bool? RequireAtLeastOneSelector { get; set; }

    /// <summary>Selectors that must exist and publish DKIM records (organization-specific).</summary>
    [JsonPropertyName("requiredSelectors")]
    public string[]? RequiredSelectors { get; set; }

    /// <summary>Minimum accepted key length in bits for selectors (best-effort, RSA-focused).</summary>
    [JsonPropertyName("minKeyBits")]
    public int? MinKeyBits { get; set; }

    /// <summary>Allowed domain suffixes for selector CNAME targets (vendor-hosted DKIM).</summary>
    [JsonPropertyName("allowedCnameTargetSuffixes")]
    public string[]? AllowedCnameTargetSuffixes { get; set; }

    public DesiredStateDkimPolicy Clone() {
        return new DesiredStateDkimPolicy {
            Enabled = Enabled,
            RequireAtLeastOneSelector = RequireAtLeastOneSelector,
            RequiredSelectors = RequiredSelectors?.ToArray(),
            MinKeyBits = MinKeyBits,
            AllowedCnameTargetSuffixes = AllowedCnameTargetSuffixes?.ToArray()
        };
    }

    public void Apply(DesiredStateDkimPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireAtLeastOneSelector.HasValue) RequireAtLeastOneSelector = overlay.RequireAtLeastOneSelector;
        if (overlay.RequiredSelectors != null) RequiredSelectors = overlay.RequiredSelectors.ToArray();
        if (overlay.MinKeyBits.HasValue) MinKeyBits = overlay.MinKeyBits;
        if (overlay.AllowedCnameTargetSuffixes != null) AllowedCnameTargetSuffixes = overlay.AllowedCnameTargetSuffixes.ToArray();
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
    }
}

public sealed class DesiredStateMtastsPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    [JsonPropertyName("requireEnforce")]
    public bool? RequireEnforce { get; set; }

    /// <summary>Minimum accepted max_age value (seconds).</summary>
    [JsonPropertyName("minMaxAge")]
    public int? MinMaxAge { get; set; }

    [JsonPropertyName("requireMxAligned")]
    public bool? RequireMxAligned { get; set; }

    public DesiredStateMtastsPolicy Clone() {
        return new DesiredStateMtastsPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            RequireEnforce = RequireEnforce,
            MinMaxAge = MinMaxAge,
            RequireMxAligned = RequireMxAligned
        };
    }

    public void Apply(DesiredStateMtastsPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.RequireEnforce.HasValue) RequireEnforce = overlay.RequireEnforce;
        if (overlay.MinMaxAge.HasValue) MinMaxAge = overlay.MinMaxAge;
        if (overlay.RequireMxAligned.HasValue) RequireMxAligned = overlay.RequireMxAligned;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
    }
}

public sealed class DesiredStateTlsRptPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    [JsonPropertyName("requireRua")]
    public bool? RequireRua { get; set; }

    [JsonPropertyName("requireValidPolicy")]
    public bool? RequireValidPolicy { get; set; }

    /// <summary>Allowed domain suffixes for TLSRPT rua endpoints (mailto domains / HTTPS hosts).</summary>
    [JsonPropertyName("allowedReportDomainSuffixes")]
    public string[]? AllowedReportDomainSuffixes { get; set; }

    public DesiredStateTlsRptPolicy Clone() {
        return new DesiredStateTlsRptPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            RequireRua = RequireRua,
            RequireValidPolicy = RequireValidPolicy,
            AllowedReportDomainSuffixes = AllowedReportDomainSuffixes?.ToArray()
        };
    }

    public void Apply(DesiredStateTlsRptPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.RequireRua.HasValue) RequireRua = overlay.RequireRua;
        if (overlay.RequireValidPolicy.HasValue) RequireValidPolicy = overlay.RequireValidPolicy;
        if (overlay.AllowedReportDomainSuffixes != null) AllowedReportDomainSuffixes = overlay.AllowedReportDomainSuffixes.ToArray();
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
    }
}

public sealed class DesiredStateBimiPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    /// <summary>When true, requires the domain not to decline publishing a BIMI indicator (l= and/or a= must be present).</summary>
    [JsonPropertyName("requireIndicator")]
    public bool? RequireIndicator { get; set; }

    /// <summary>When true, requires a valid https://...svg(.svgz) location.</summary>
    [JsonPropertyName("requireValidLocation")]
    public bool? RequireValidLocation { get; set; }

    /// <summary>Allowed host suffixes for the indicator URL (vendor-hosted BIMI).</summary>
    [JsonPropertyName("allowedLocationHostSuffixes")]
    public string[]? AllowedLocationHostSuffixes { get; set; }

    /// <summary>When true, requires an authority (VMC) URL.</summary>
    [JsonPropertyName("requireAuthority")]
    public bool? RequireAuthority { get; set; }

    /// <summary>Allowed host suffixes for the authority URL (vendor-hosted VMC).</summary>
    [JsonPropertyName("allowedAuthorityHostSuffixes")]
    public string[]? AllowedAuthorityHostSuffixes { get; set; }

    /// <summary>When true, do not download the indicator SVG as part of the BIMI check.</summary>
    [JsonPropertyName("skipIndicatorDownload")]
    public bool? SkipIndicatorDownload { get; set; }

    public DesiredStateBimiPolicy Clone() {
        return new DesiredStateBimiPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            RequireIndicator = RequireIndicator,
            RequireValidLocation = RequireValidLocation,
            AllowedLocationHostSuffixes = AllowedLocationHostSuffixes?.ToArray(),
            RequireAuthority = RequireAuthority,
            AllowedAuthorityHostSuffixes = AllowedAuthorityHostSuffixes?.ToArray(),
            SkipIndicatorDownload = SkipIndicatorDownload
        };
    }

    public void Apply(DesiredStateBimiPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.RequireIndicator.HasValue) RequireIndicator = overlay.RequireIndicator;
        if (overlay.RequireValidLocation.HasValue) RequireValidLocation = overlay.RequireValidLocation;
        if (overlay.AllowedLocationHostSuffixes != null) AllowedLocationHostSuffixes = overlay.AllowedLocationHostSuffixes.ToArray();
        if (overlay.RequireAuthority.HasValue) RequireAuthority = overlay.RequireAuthority;
        if (overlay.AllowedAuthorityHostSuffixes != null) AllowedAuthorityHostSuffixes = overlay.AllowedAuthorityHostSuffixes.ToArray();
        if (overlay.SkipIndicatorDownload.HasValue) SkipIndicatorDownload = overlay.SkipIndicatorDownload;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireRecord ??= false;
        RequireIndicator ??= false;
        RequireValidLocation ??= false;
        RequireAuthority ??= false;
        SkipIndicatorDownload ??= true;
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
