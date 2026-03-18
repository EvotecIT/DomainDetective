using System;
using System.Linq;
using System.Text.RegularExpressions;

namespace DomainDetective.Reports;

public static partial class SectionProjectors
{
    public static Microsoft365Section? BuildMicrosoft365(DomainDetective.Views.Microsoft365TenantInfo info)
    {
        if (info == null)
        {
            return null;
        }

        var sec = new Microsoft365Section
        {
            Status = string.IsNullOrWhiteSpace(info.Status) ? "-" : info.Status,
            IsMicrosoft365Tenant = info.IsMicrosoft365Tenant,
            DetectionConfidence = FormatMicrosoft365Confidence(info.DetectionConfidence)
        };

        sec.Summary.Add(("Status", sec.Status));
        sec.Summary.Add(("Tenant Detected", info.IsMicrosoft365Tenant ? "Yes" : "No"));
        sec.Summary.Add(("Confidence", sec.DetectionConfidence));
        sec.Summary.Add(("Tenant Name", string.IsNullOrWhiteSpace(info.TenantName) ? "Unknown" : info.TenantName!));
        sec.Summary.Add(("Tenant Namespace Domain", string.IsNullOrWhiteSpace(info.TenantNamespaceDomain) ? "-" : info.TenantNamespaceDomain!));
        sec.Summary.Add(("Company", string.IsNullOrWhiteSpace(info.CompanyName) ? "-" : info.CompanyName!));
        sec.Summary.Add(("Tenant ID", string.IsNullOrWhiteSpace(info.TenantId) ? "-" : info.TenantId!));
        sec.Summary.Add(("Domain Type", string.IsNullOrWhiteSpace(info.NameSpaceType) ? "-" : info.NameSpaceType!));
        sec.Summary.Add(("Identity Provider", FormatMicrosoft365IdentityProvider(info)));
        sec.Summary.Add(("Federation", FormatMicrosoft365Value(info.FederationMode)));
        sec.Summary.Add(("Cloud Instance", FormatMicrosoft365CloudInstance(info.CloudInstance)));
        sec.Summary.Add(("Region", FormatMicrosoft365Value(info.Region)));
        sec.Summary.Add(("Auth Path", FormatMicrosoft365Value(info.AuthenticationPath)));
        sec.Summary.Add(("User Enumeration", FormatMicrosoft365Value(info.UserEnumerationStatus)));
        sec.Summary.Add(("Smart Lockout", FormatMicrosoft365Value(info.SmartLockoutStatus)));
        sec.Summary.Add(("Throttling", FormatMicrosoft365ThrottlingStatus(info.ThrottlingStatus, info.AuthenticationSummary?.ThrottleStatus)));
        sec.Summary.Add(("Probe Responsive", info.AuthenticationSummary?.ProbeResponsive == true ? "Yes" : "No"));
        sec.Summary.Add(("Consumer Domain", info.ConsumerDomain ? "Yes" : "No"));
        sec.Summary.Add(("Accepted Domains", FormatMicrosoft365AcceptedDomains(info.TenantDomains)));
        sec.Summary.Add(("Domain Evidence", FormatMicrosoft365DomainEvidence(info.TenantDomains)));
        sec.Summary.Add(("Supported Grant Types", JoinValues(info.SupportedGrantTypes)));
        sec.Summary.Add(("Supported Response Types", JoinValues(info.SupportedResponseTypes)));
        sec.Summary.Add(("Services", info.Services?.Count(s => s.Status == DomainDetective.Microsoft365DetectionStatus.Detected).ToString() ?? "0"));
        sec.Summary.Add(("Tenant Domains", (info.TenantDomains?.Count ?? 0).ToString()));
        sec.Summary.Add(("Known Subdomains", (info.KnownSubdomains?.Count ?? 0).ToString()));
        sec.Summary.Add(("DNS Apps", (info.DetectedDnsApplications?.Count ?? 0).ToString()));
        sec.Summary.Add(("Evidence Items", (info.EvidenceLedger?.Count ?? 0).ToString()));

        foreach (var h in info.Highlights ?? Array.Empty<string>())
        {
            if (!string.IsNullOrWhiteSpace(h))
            {
                sec.Highlights.Add(h);
            }
        }

        foreach (var a in info.Assessments ?? Array.Empty<DomainDetective.Assessment>())
        {
            if (a != null && a.Severity != DomainDetective.AssessmentSeverity.Info)
            {
                sec.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
            }
        }

        foreach (var p in info.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
        {
            var title = p?.Title ?? p?.Code;
            if (!string.IsNullOrWhiteSpace(title))
            {
                sec.Positives.Add(title!);
            }
        }

        foreach (var r in info.References ?? Array.Empty<string>())
        {
            if (!string.IsNullOrWhiteSpace(r))
            {
                sec.References.Add(r);
            }
        }

        foreach (var service in info.Services ?? Array.Empty<DomainDetective.Microsoft365ServiceDetection>())
        {
            sec.Services.Add(new Microsoft365Section.ServiceRow
            {
                Service = FormatMicrosoft365Value(service.Kind),
                Status = FormatMicrosoft365Value(service.Status),
                Confidence = FormatMicrosoft365Confidence(service.Confidence),
                Evidence = JoinEvidence(service.Evidence)
            });
        }

        foreach (var domain in info.TenantDomains ?? Array.Empty<DomainDetective.Microsoft365TenantDomain>())
        {
            sec.Domains.Add(new Microsoft365Section.DomainRow
            {
                Domain = domain.Domain,
                Role = FormatMicrosoft365Value(domain.Role),
                Confidence = FormatMicrosoft365Confidence(domain.Confidence),
                Evidence = JoinEvidence(domain.Evidence)
            });
        }

        foreach (var subdomain in info.KnownSubdomains ?? Array.Empty<DomainDetective.KnownMicrosoft365Subdomain>())
        {
            sec.Subdomains.Add(new Microsoft365Section.SubdomainRow
            {
                Name = subdomain.Name,
                Role = FormatMicrosoft365Value(subdomain.Role),
                Resolution = FormatMicrosoft365Value(subdomain.ResolutionStatus)
            });
        }

        foreach (var app in info.DetectedDnsApplications ?? Array.Empty<DomainDetective.DetectedDnsApplication>())
        {
            sec.Applications.Add(new Microsoft365Section.ApplicationRow
            {
                Name = app.Name,
                Category = FormatMicrosoft365Value(app.Category),
                EvidenceKind = FormatMicrosoft365Value(app.EvidenceKind),
                Confidence = FormatMicrosoft365Confidence(app.Confidence),
                Evidence = string.IsNullOrWhiteSpace(app.Evidence) ? "-" : app.Evidence
            });
        }

        foreach (var evidence in info.EvidenceLedger ?? Array.Empty<DomainDetective.Microsoft365EvidenceItem>())
        {
            sec.Evidence.Add(new Microsoft365Section.EvidenceRow
            {
                Label = evidence.Label,
                Category = FormatMicrosoft365Value(evidence.Category),
                Confidence = FormatMicrosoft365Confidence(evidence.Confidence),
                Evidence = JoinEvidence(evidence.Evidence)
            });
        }

        return sec;
    }

    private static string FormatMicrosoft365IdentityProvider(DomainDetective.Views.Microsoft365TenantInfo info)
    {
        if (!string.IsNullOrWhiteSpace(info.IdentityProvider))
        {
            return info.IdentityProvider!;
        }

        return FormatMicrosoft365Value(info.IdentityProviderKind);
    }

    private static string JoinEvidence(System.Collections.Generic.IReadOnlyList<string>? items)
    {
        if (items == null || items.Count == 0)
        {
            return "-";
        }

        var values = items.Where(item => !string.IsNullOrWhiteSpace(item)).Take(4).ToList();
        if (values.Count == 0)
        {
            return "-";
        }

        return string.Join("; ", values);
    }

    private static string JoinValues(System.Collections.Generic.IReadOnlyList<string>? items)
    {
        if (items == null || items.Count == 0)
        {
            return "-";
        }

        var values = items.Where(item => !string.IsNullOrWhiteSpace(item)).Take(8).ToList();
        if (values.Count == 0)
        {
            return "-";
        }

        return string.Join(", ", values);
    }

    private static string FormatMicrosoft365AcceptedDomains(System.Collections.Generic.IReadOnlyList<DomainDetective.Microsoft365TenantDomain>? domains)
    {
        if (domains == null || domains.Count == 0)
        {
            return "-";
        }

        var values = domains
            .Where(static domain => domain.Role != DomainDetective.Microsoft365TenantDomainRole.MicrosoftManagedNamespace)
            .Select(static domain => domain.Domain)
            .Where(static domain => !string.IsNullOrWhiteSpace(domain))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(8)
            .ToList();
        if (values.Count == 0)
        {
            return "-";
        }

        return string.Join(", ", values);
    }

    private static string FormatMicrosoft365DomainEvidence(System.Collections.Generic.IReadOnlyList<DomainDetective.Microsoft365TenantDomain>? domains)
    {
        if (domains == null || domains.Count == 0)
        {
            return "-";
        }

        var values = domains
            .Where(static domain => domain.Role != DomainDetective.Microsoft365TenantDomainRole.Unknown)
            .GroupBy(static domain => domain.Role)
            .OrderBy(static group => GetMicrosoft365DomainRoleSortOrder(group.Key))
            .ThenByDescending(static group => group.Max(item => item.Confidence))
            .ThenBy(static group => group.Key.ToString(), StringComparer.OrdinalIgnoreCase)
            .Take(6)
            .Select(group => $"{FormatMicrosoft365DomainRoleEvidence(group.Key)} {group.Count()} ({FormatMicrosoft365Confidence(group.Max(static item => item.Confidence))})")
            .ToList();

        if (values.Count == 0)
        {
            return "-";
        }

        return string.Join(", ", values);
    }

    private static int GetMicrosoft365DomainRoleSortOrder(DomainDetective.Microsoft365TenantDomainRole role)
    {
        switch (role)
        {
            case DomainDetective.Microsoft365TenantDomainRole.Primary:
                return 0;
            case DomainDetective.Microsoft365TenantDomainRole.IdentityDomain:
                return 1;
            case DomainDetective.Microsoft365TenantDomainRole.AcceptedCustomDomain:
                return 2;
            case DomainDetective.Microsoft365TenantDomainRole.MicrosoftManagedNamespace:
                return 3;
            case DomainDetective.Microsoft365TenantDomainRole.Unknown:
            default:
                return int.MaxValue;
        }
    }

    private static string FormatMicrosoft365DomainRoleEvidence(DomainDetective.Microsoft365TenantDomainRole role)
    {
        switch (role)
        {
            case DomainDetective.Microsoft365TenantDomainRole.Primary:
                return "Primary";
            case DomainDetective.Microsoft365TenantDomainRole.IdentityDomain:
                return "Identity-derived";
            case DomainDetective.Microsoft365TenantDomainRole.AcceptedCustomDomain:
                return "DKIM-derived";
            case DomainDetective.Microsoft365TenantDomainRole.MicrosoftManagedNamespace:
                return "Namespace-derived";
            case DomainDetective.Microsoft365TenantDomainRole.Unknown:
            default:
                return "Unknown";
        }
    }

    private static string FormatMicrosoft365ThrottlingStatus(DomainDetective.Microsoft365AuthThrottlingStatus throttlingStatus, int? throttleStatus)
    {
        switch (throttlingStatus)
        {
            case DomainDetective.Microsoft365AuthThrottlingStatus.NoThrottling:
                return "No Throttling";
            case DomainDetective.Microsoft365AuthThrottlingStatus.ThrottlingObserved:
                return throttleStatus.HasValue ? "Observed (" + throttleStatus.Value + ")" : "Observed";
            default:
                return "Unknown";
        }
    }

    private static string FormatMicrosoft365CloudInstance(DomainDetective.TenantCloudInstanceKind cloudInstance)
    {
        return cloudInstance switch
        {
            DomainDetective.TenantCloudInstanceKind.Global => "Global/Commercial",
            DomainDetective.TenantCloudInstanceKind.GCC => "GCC",
            DomainDetective.TenantCloudInstanceKind.GCCHigh => "GCC High",
            DomainDetective.TenantCloudInstanceKind.DoD => "DoD",
            DomainDetective.TenantCloudInstanceKind.China => "China",
            DomainDetective.TenantCloudInstanceKind.Germany => "Germany",
            _ => "Unknown"
        };
    }

    private static string FormatMicrosoft365Confidence(DomainDetective.Microsoft365DetectionConfidence confidence)
    {
        return confidence switch
        {
            DomainDetective.Microsoft365DetectionConfidence.Strong => "Strong",
            DomainDetective.Microsoft365DetectionConfidence.Moderate => "Moderate",
            DomainDetective.Microsoft365DetectionConfidence.Weak => "Weak",
            _ => "Unknown"
        };
    }

    private static string FormatMicrosoft365Value<T>(T value)
    {
        if (value == null)
        {
            return "-";
        }

        var text = value.ToString();
        if (string.IsNullOrWhiteSpace(text))
        {
            return "-";
        }

        if (string.Equals(text, "Unknown", StringComparison.OrdinalIgnoreCase))
        {
            return "Unknown";
        }

        return Regex.Replace(text, "([a-z0-9])([A-Z])", "$1 $2");
    }
}
