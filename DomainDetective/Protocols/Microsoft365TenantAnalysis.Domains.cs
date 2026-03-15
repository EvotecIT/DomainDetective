using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

public sealed partial class Microsoft365TenantAnalysis {
    private static IReadOnlyList<Microsoft365TenantDomain> BuildTenantDomains(
        string primaryDomain,
        DkimAnalysis? dkim,
        Microsoft365DetectionConfidence tenantConfidence) {
        var domains = new List<Microsoft365TenantDomain>();
        var normalizedPrimary = NormalizeTenantDomain(primaryDomain);
        if (normalizedPrimary.Length > 0) {
            domains.Add(new Microsoft365TenantDomain {
                Domain = normalizedPrimary,
                Role = Microsoft365TenantDomainRole.Primary,
                Confidence = tenantConfidence == Microsoft365DetectionConfidence.Unknown ? Microsoft365DetectionConfidence.Weak : tenantConfidence,
                Evidence = new[] { "Analyzed domain" }
            });
        }

        if (dkim?.AnalysisResults != null && dkim.AnalysisResults.Count > 0) {
            foreach (var result in dkim.AnalysisResults.Values) {
                var namespaceDomain = TryExtractMicrosoftManagedNamespace(result);
                if (namespaceDomain.Length == 0) {
                    continue;
                }

                var evidence = new List<string>();
                if (!string.IsNullOrWhiteSpace(result.Name)) {
                    evidence.Add("DKIM target: " + result.Name);
                }
                if (!string.IsNullOrWhiteSpace(result.CnameTarget)) {
                    evidence.Add("DKIM CNAME: " + result.CnameTarget);
                }

                domains.Add(new Microsoft365TenantDomain {
                    Domain = namespaceDomain,
                    Role = Microsoft365TenantDomainRole.MicrosoftManagedNamespace,
                    Confidence = Microsoft365DetectionConfidence.Strong,
                    Evidence = evidence.Count > 0 ? evidence : new[] { "DKIM namespace inference" }
                });
            }
        }

        return domains
            .GroupBy(static item => $"{item.Role}|{item.Domain}", StringComparer.OrdinalIgnoreCase)
            .Select(static group => group.First())
            .OrderBy(static item => item.Role)
            .ThenBy(static item => item.Domain, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string TryExtractMicrosoftManagedNamespace(DkimRecordAnalysis? record) {
        if (record == null) {
            return string.Empty;
        }

        var candidates = new[] {
            record.Name,
            record.CnameTarget
        };

        for (var i = 0; i < candidates.Length; i++) {
            var candidate = NormalizeTenantDomain(candidates[i]);
            if (candidate.Length == 0) {
                continue;
            }

            var marker = "._domainkey.";
            var markerIndex = candidate.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (markerIndex < 0) {
                continue;
            }

            var namespaceDomain = candidate.Substring(markerIndex + marker.Length);
            if (namespaceDomain.EndsWith(".onmicrosoft.com", StringComparison.OrdinalIgnoreCase)) {
                return namespaceDomain;
            }
        }

        return string.Empty;
    }

    private static string NormalizeTenantDomain(string? value) {
        return (value ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
    }
}
