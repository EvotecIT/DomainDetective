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
    /// <summary>Executes the resolve operation.</summary>
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

    /// <summary>Executes the evaluate operation.</summary>
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
    /// <summary>Gets or sets the subject value.</summary>
    public string Subject { get; set; } = string.Empty;

    /// <summary>Gets or sets the mail classification value.</summary>
    public MailDomainClassificationCategory? MailClassification { get; set; }

    /// <summary>Gets or sets the enabled value.</summary>
    public bool Enabled { get; set; }

    /// <summary>Gets or sets the baseline profile value.</summary>
    public string BaselineProfile { get; set; } = "Balanced";

    /// <summary>Gets or sets the include compliant value.</summary>
    public bool IncludeCompliant { get; set; }

    /// <summary>Gets or sets the max endpoints value.</summary>
    public int MaxEndpoints { get; set; } = 300;

    /// <summary>Gets or sets the policy overrides path value.</summary>
    public string? PolicyOverridesPath { get; set; }

    /// <summary>Gets or sets the resolved policy overrides path value.</summary>
    public string? ResolvedPolicyOverridesPath { get; set; }

    /// <summary>Gets or sets the policy overrides value.</summary>
    public CertificateInventoryPolicyOverrides? PolicyOverrides { get; set; }
}
