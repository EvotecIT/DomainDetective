using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

public sealed partial class Microsoft365TenantAnalysis {
    private static readonly string[] MicrosoftManagedNamespaceSuffixes = {
        ".onmicrosoft.com",
        ".onmicrosoft.us",
        ".partner.onmschina.cn"
    };

    private static IReadOnlyList<Microsoft365TenantDomain> BuildTenantDomains(
        string primaryDomain,
        IdpInfoAnalysis? idp,
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

        var identityDomain = NormalizeTenantDomain(idp?.DomainName);
        if (identityDomain.Length > 0) {
            if (domains.Count > 0 && string.Equals(identityDomain, normalizedPrimary, StringComparison.OrdinalIgnoreCase)) {
                domains[0] = new Microsoft365TenantDomain {
                    Domain = normalizedPrimary,
                    Role = Microsoft365TenantDomainRole.Primary,
                    Confidence = tenantConfidence == Microsoft365DetectionConfidence.Unknown ? Microsoft365DetectionConfidence.Weak : tenantConfidence,
                    Evidence = new[] { "Analyzed domain", "GetUserRealm domain: " + identityDomain }
                };
            } else {
                domains.Add(new Microsoft365TenantDomain {
                    Domain = identityDomain,
                    Role = Microsoft365TenantDomainRole.IdentityDomain,
                    Confidence = Microsoft365DetectionConfidence.Strong,
                    Evidence = new[] { "GetUserRealm domain: " + identityDomain }
                });
            }
        }

        if (dkim?.AnalysisResults != null && dkim.AnalysisResults.Count > 0) {
            foreach (var result in dkim.AnalysisResults.Values) {
                var customDomain = TryExtractDkimSigningDomain(result);
                if (customDomain.Length > 0) {
                    var customDomainEvidence = new List<string>();
                    if (!string.IsNullOrWhiteSpace(result.Name)) {
                        customDomainEvidence.Add("DKIM signing domain: " + result.Name);
                    }
                    if (!string.IsNullOrWhiteSpace(result.CnameTarget)) {
                        customDomainEvidence.Add("DKIM CNAME: " + result.CnameTarget);
                    }

                    domains.Add(new Microsoft365TenantDomain {
                        Domain = customDomain,
                        Role = Microsoft365TenantDomainRole.AcceptedCustomDomain,
                        Confidence = Microsoft365DetectionConfidence.Moderate,
                        Evidence = customDomainEvidence.Count > 0 ? customDomainEvidence : new[] { "DKIM signing-domain inference" }
                    });
                }

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
            .GroupBy(static item => item.Domain, StringComparer.OrdinalIgnoreCase)
            .Select(static group => MergeTenantDomain(group))
            .OrderBy(static item => GetTenantDomainRoleSortOrder(item.Role))
            .ThenBy(static item => item.Domain, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static Microsoft365TenantDomain MergeTenantDomain(IEnumerable<Microsoft365TenantDomain> domains) {
        var items = domains.ToList();
        var best = items
            .OrderBy(static item => GetTenantDomainRoleSortOrder(item.Role))
            .ThenByDescending(static item => item.Confidence)
            .First();

        return new Microsoft365TenantDomain {
            Domain = best.Domain,
            Role = best.Role,
            Confidence = items.Max(static item => item.Confidence),
            Evidence = items
                .SelectMany(static item => item.Evidence ?? Array.Empty<string>())
                .Where(static item => !string.IsNullOrWhiteSpace(item))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList()
        };
    }

    private static int GetTenantDomainRoleSortOrder(Microsoft365TenantDomainRole role) {
        switch (role) {
            case Microsoft365TenantDomainRole.Primary:
                return 0;
            case Microsoft365TenantDomainRole.IdentityDomain:
                return 1;
            case Microsoft365TenantDomainRole.AcceptedCustomDomain:
                return 2;
            case Microsoft365TenantDomainRole.MicrosoftManagedNamespace:
                return 3;
            case Microsoft365TenantDomainRole.Unknown:
            default:
                return int.MaxValue;
        }
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

            var namespaceStartIndex = markerIndex + marker.Length;
            if (namespaceStartIndex >= candidate.Length) {
                continue;
            }

            var namespaceDomain = candidate.Substring(namespaceStartIndex);
            for (var suffixIndex = 0; suffixIndex < MicrosoftManagedNamespaceSuffixes.Length; suffixIndex++) {
                if (namespaceDomain.EndsWith(MicrosoftManagedNamespaceSuffixes[suffixIndex], StringComparison.OrdinalIgnoreCase)) {
                    return namespaceDomain;
                }
            }
        }

        return string.Empty;
    }

    private static string TryExtractDkimSigningDomain(DkimRecordAnalysis? record) {
        if (record == null || string.IsNullOrWhiteSpace(record.Name)) {
            return string.Empty;
        }

        var candidate = NormalizeTenantDomain(record.Name);
        if (candidate.Length == 0) {
            return string.Empty;
        }

        var marker = "._domainkey.";
        var markerIndex = candidate.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (markerIndex < 0) {
            return string.Empty;
        }

        var domainStartIndex = markerIndex + marker.Length;
        if (domainStartIndex >= candidate.Length) {
            return string.Empty;
        }

        var domain = candidate.Substring(domainStartIndex);
        for (var suffixIndex = 0; suffixIndex < MicrosoftManagedNamespaceSuffixes.Length; suffixIndex++) {
            if (domain.EndsWith(MicrosoftManagedNamespaceSuffixes[suffixIndex], StringComparison.OrdinalIgnoreCase)) {
                return string.Empty;
            }
        }

        return domain;
    }

    private static string NormalizeTenantDomain(string? value) {
        return (value ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
    }

    private static string? InferTenantName(IReadOnlyList<Microsoft365TenantDomain>? domains) {
        if (domains == null || domains.Count == 0) {
            return null;
        }

        foreach (var domain in domains.Where(static item => item != null && item.Role == Microsoft365TenantDomainRole.MicrosoftManagedNamespace)) {
            var normalized = NormalizeTenantDomain(domain.Domain);
            for (var suffixIndex = 0; suffixIndex < MicrosoftManagedNamespaceSuffixes.Length; suffixIndex++) {
                var suffix = MicrosoftManagedNamespaceSuffixes[suffixIndex];
                if (!normalized.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) {
                    continue;
                }

                var tenantName = normalized.Substring(0, normalized.Length - suffix.Length);
                return string.IsNullOrWhiteSpace(tenantName) ? null : tenantName;
            }
        }

        return null;
    }

    private static string? FindTenantNamespaceDomain(IReadOnlyList<Microsoft365TenantDomain>? domains) {
        if (domains == null || domains.Count == 0) {
            return null;
        }

        foreach (var domain in domains) {
            if (domain != null && domain.Role == Microsoft365TenantDomainRole.MicrosoftManagedNamespace) {
                return domain.Domain;
            }
        }

        return null;
    }
}
