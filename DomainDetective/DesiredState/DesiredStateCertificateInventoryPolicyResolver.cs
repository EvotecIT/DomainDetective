using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using DomainDetective.Definitions;

namespace DomainDetective.DesiredState;

/// <summary>
/// Resolves desired-state certificate inventory posture settings to executable policy inputs.
/// </summary>
public static class DesiredStateCertificateInventoryPolicyResolver {
    public static ResolvedDesiredStateCertificateInventoryPolicy Resolve(
        string domain,
        DesiredStateConfiguration configuration,
        MailDomainClassificationCategory? classification = null,
        string? configurationPath = null) {
        if (string.IsNullOrWhiteSpace(domain)) {
            throw new ArgumentException("Domain cannot be empty or whitespace.", nameof(domain));
        }

        if (configuration == null) {
            throw new ArgumentNullException(nameof(configuration));
        }

        var profile = configuration.ResolveProfile(domain, classification);
        profile.Normalize();
        var desired = profile.CertificateInventory;
        if (desired == null) {
            return new ResolvedDesiredStateCertificateInventoryPolicy {
                Subject = domain.Trim(),
                MailClassification = classification,
                Enabled = false,
                BaselineProfile = "Balanced",
                IncludeCompliant = false,
                MaxEndpoints = 300
            };
        }

        desired.NormalizeDefaults();

        CertificateInventoryPolicyOverrides? overrides = null;
        string? resolvedOverridesPath = ResolveOverridesPath(desired.PolicyOverridesPath, configurationPath);
        if (!string.IsNullOrWhiteSpace(resolvedOverridesPath)) {
            string overridesPath = resolvedOverridesPath!;
            overrides = CertificateInventoryPolicyOverrides.Load(overridesPath);
        }

        return new ResolvedDesiredStateCertificateInventoryPolicy {
            Subject = domain.Trim(),
            MailClassification = classification,
            Enabled = desired.Enabled != false,
            BaselineProfile = desired.BaselineProfile ?? "Balanced",
            IncludeCompliant = desired.IncludeCompliant == true,
            MaxEndpoints = Math.Max(0, desired.MaxEndpoints ?? 300),
            PolicyOverridesPath = desired.PolicyOverridesPath,
            ResolvedPolicyOverridesPath = resolvedOverridesPath,
            PolicyOverrides = overrides
        };
    }

    public static CertificateInventoryPolicySummary Evaluate(
        IEnumerable<CertificateInventorySnapshot>? snapshots,
        ResolvedDesiredStateCertificateInventoryPolicy resolved,
        DateTimeOffset? sinceUtc = null) {
        if (resolved == null) {
            throw new ArgumentNullException(nameof(resolved));
        }

        if (!resolved.Enabled) {
            return new CertificateInventoryPolicySummary {
                BaselineProfile = resolved.BaselineProfile
            };
        }

        IEnumerable<CertificateInventorySnapshot> source = snapshots ?? Array.Empty<CertificateInventorySnapshot>();
        if (sinceUtc.HasValue) {
            source = source.Where(snapshot => snapshot != null && snapshot.CapturedAtUtc >= sinceUtc.Value);
        }

        return CertificateInventoryPolicyAnalyzer.BuildPolicy(
            source,
            baselineProfile: resolved.BaselineProfile,
            includeCompliant: resolved.IncludeCompliant,
            maxEndpoints: resolved.MaxEndpoints,
            policyOverrides: resolved.PolicyOverrides);
    }

    private static string? ResolveOverridesPath(string? configuredPath, string? configurationPath) {
        if (string.IsNullOrWhiteSpace(configuredPath)) {
            return null;
        }

        string trimmed = configuredPath!.Trim();
        if (Path.IsPathRooted(trimmed)) {
            return Path.GetFullPath(trimmed);
        }

        string? baseDirectory = ResolveBaseDirectory(configurationPath);
        if (string.IsNullOrWhiteSpace(baseDirectory)) {
            return Path.GetFullPath(trimmed);
        }

        return Path.GetFullPath(Path.Combine(baseDirectory, trimmed));
    }

    private static string? ResolveBaseDirectory(string? configurationPath) {
        if (string.IsNullOrWhiteSpace(configurationPath)) {
            return null;
        }

        string normalizedConfigurationPath = configurationPath!;
        string fullPath = Path.GetFullPath(normalizedConfigurationPath);
        if (Directory.Exists(fullPath)) {
            return fullPath;
        }

        string? directory = Path.GetDirectoryName(fullPath);
        return string.IsNullOrWhiteSpace(directory) ? null : directory;
    }
}

/// <summary>
/// Fully resolved desired-state certificate inventory posture settings.
/// </summary>
public sealed class ResolvedDesiredStateCertificateInventoryPolicy {
    public string Subject { get; set; } = string.Empty;

    public MailDomainClassificationCategory? MailClassification { get; set; }

    public bool Enabled { get; set; }

    public string BaselineProfile { get; set; } = "Balanced";

    public bool IncludeCompliant { get; set; }

    public int MaxEndpoints { get; set; } = 300;

    public string? PolicyOverridesPath { get; set; }

    public string? ResolvedPolicyOverridesPath { get; set; }

    public CertificateInventoryPolicyOverrides? PolicyOverrides { get; set; }
}
