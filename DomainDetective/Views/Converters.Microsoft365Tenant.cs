using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static Microsoft365TenantInfo Convert(Microsoft365TenantAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);

        var refs = new[]
        {
            new StandardReference { Title = "OpenID Connect Discovery", Reference = "OIDC Discovery", Url = "https://openid.net/specs/openid-connect-discovery-1_0.html" },
            new StandardReference { Title = "Microsoft identity platform", Reference = "Microsoft identity platform", Url = "https://learn.microsoft.com/en-us/entra/identity-platform/" }
        };

        var detectedServices = analysis.Services?
            .Where(static service => service.Status == Microsoft365DetectionStatus.Detected)
            .Select(static service => service.Kind.ToString())
            .ToArray() ?? Array.Empty<string>();
        var authPath = FormatAuthenticationPath(analysis.AuthenticationSummary?.AuthenticationPath ?? Microsoft365AuthPathKind.Unknown);
        var authSummary = DescribeAuthenticationSummary(analysis.AuthenticationSummary);
        var workloadSummary = analysis.WorkloadSummary ?? new Microsoft365WorkloadConfidenceSummary();
        var dnsApplicationSummary = analysis.DnsApplicationSummary ?? new Microsoft365DnsApplicationSummary();
        var evidenceSummary = analysis.EvidenceSummary ?? new Microsoft365EvidenceSummary();
        var highlights = BuildHighlights(analysis, authPath, detectedServices, workloadSummary, dnsApplicationSummary, evidenceSummary);
        var dnsCategorySummary = DescribeDnsApplicationCategories(dnsApplicationSummary, 1);
        var evidenceCategorySummary = DescribeEvidenceCategories(evidenceSummary, 1);
        var domainEvidenceSummary = DescribeDomainEvidence(analysis.TenantDomains, 3);
        var summary = $"{(analysis.IsMicrosoft365Tenant ? "M365" : "No M365")} tenant; confidence {analysis.DetectionConfidence}; auth-path {authPath}; auth {authSummary}; workloads S{workloadSummary.StrongCount}/M{workloadSummary.ModerateCount}/W{workloadSummary.WeakCount}; app-cats {dnsApplicationSummary.CategoryCount}{(string.IsNullOrWhiteSpace(dnsCategorySummary) ? string.Empty : $" (top {dnsCategorySummary})")}; evidence-groups {evidenceSummary.CategoryCount}{(string.IsNullOrWhiteSpace(evidenceCategorySummary) ? string.Empty : $" (top {evidenceCategorySummary})")}; domain-evidence {(analysis.TenantDomains?.Count ?? 0)}{(string.IsNullOrWhiteSpace(domainEvidenceSummary) ? string.Empty : $" (top {domainEvidenceSummary})")}; services {detectedServices.Length}; apps {analysis.DetectedDnsApplications?.Count ?? 0}; evidence {analysis.EvidenceLedger?.Count ?? 0}; subdomains {analysis.KnownSubdomains?.Count ?? 0}";

        return new Microsoft365TenantInfo
        {
            Check = HealthCheckType.MICROSOFT365,
            Area = AreaForKind(HealthCheckType.MICROSOFT365),
            Subject = analysis.Subject,
            QuerySucceeded = analysis.QuerySucceeded,
            FailureReason = analysis.FailureReason,
            IsMicrosoft365Tenant = analysis.IsMicrosoft365Tenant,
            DetectionConfidence = analysis.DetectionConfidence,
            TenantId = analysis.TenantId,
            TenantName = analysis.TenantName,
            CompanyName = analysis.CompanyName,
            TenantNamespaceDomain = analysis.TenantNamespaceDomain,
            NameSpaceType = analysis.NameSpaceType,
            IdentityProviderKind = analysis.IdentityProviderKind,
            IdentityProvider = analysis.IdentityProvider,
            FederationMode = analysis.FederationMode,
            CloudInstance = analysis.CloudInstance,
            Region = analysis.Region,
            ConsumerDomain = analysis.ConsumerDomain,
            UserEnumerationStatus = analysis.UserEnumerationStatus,
            SmartLockoutStatus = analysis.SmartLockoutStatus,
            ThrottlingStatus = analysis.ThrottlingStatus,
            AuthenticationProbeSucceeded = analysis.AuthenticationProbeSucceeded,
            AuthenticationProbeAddress = analysis.AuthenticationProbeAddress,
            AuthenticationProbe = analysis.AuthenticationProbe,
            AuthenticationSummary = analysis.AuthenticationSummary ?? new Microsoft365AuthenticationSummary(),
            AuthenticationPath = analysis.AuthenticationSummary?.AuthenticationPath ?? Microsoft365AuthPathKind.Unknown,
            SupportedGrantTypes = analysis.SupportedGrantTypes ?? Array.Empty<string>(),
            SupportedResponseTypes = analysis.SupportedResponseTypes ?? Array.Empty<string>(),
            Services = analysis.Services ?? Array.Empty<Microsoft365ServiceDetection>(),
            WorkloadSummary = workloadSummary,
            DnsApplicationSummary = dnsApplicationSummary,
            EvidenceSummary = evidenceSummary,
            TenantDomains = analysis.TenantDomains ?? Array.Empty<Microsoft365TenantDomain>(),
            KnownSubdomains = analysis.KnownSubdomains ?? Array.Empty<KnownMicrosoft365Subdomain>(),
            DetectedDnsApplications = analysis.DetectedDnsApplications ?? Array.Empty<DetectedDnsApplication>(),
            EvidenceLedger = analysis.EvidenceLedger ?? Array.Empty<Microsoft365EvidenceItem>(),
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = summary,
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(refs, recs),
            Highlights = highlights,
            Raw = analysis
        };
    }

    private static string DescribeAuthenticationSummary(Microsoft365AuthenticationSummary? summary)
    {
        if (summary == null || !summary.ProbeResponsive)
        {
            return "not-probed";
        }

        var domainType = summary.DomainType.HasValue ? summary.DomainType.Value.ToString() : "-";
        var preferredCredential = summary.PreferredCredential.HasValue ? summary.PreferredCredential.Value.ToString() : "-";
        return $"{summary.UserEnumerationStatus} / {summary.SmartLockoutStatus} / {FormatAuthenticationThrottlingStatus(summary.ThrottlingStatus)} ({FormatAuthenticationDomainPosture(summary.DomainPosture)}, {FormatAuthenticationCredentialFlow(summary.CredentialFlow)}; DomainType {domainType}; PrefCredential {preferredCredential})";
    }

    private static string FormatAuthenticationPath(Microsoft365AuthPathKind path)
    {
        switch (path)
        {
            case Microsoft365AuthPathKind.ManagedNative:
                return "managed-native";
            case Microsoft365AuthPathKind.ManagedRedirect:
                return "managed-redirect";
            case Microsoft365AuthPathKind.FederatedRedirect:
                return "federated-redirect";
            case Microsoft365AuthPathKind.Federated:
                return "federated";
            case Microsoft365AuthPathKind.ConsumerIdentity:
                return "consumer-identity";
            case Microsoft365AuthPathKind.Redirect:
                return "redirect";
            case Microsoft365AuthPathKind.NativeCredential:
                return "native-credential";
            case Microsoft365AuthPathKind.Unknown:
            default:
                return "unknown";
        }
    }

    private static IReadOnlyList<string> BuildHighlights(Microsoft365TenantAnalysis analysis, string authPath, IReadOnlyList<string> detectedServices, Microsoft365WorkloadConfidenceSummary workloadSummary, Microsoft365DnsApplicationSummary dnsApplicationSummary, Microsoft365EvidenceSummary evidenceSummary)
    {
        var highlights = new List<string>();

        if (analysis.AuthenticationSummary?.ProbeResponsive == true)
        {
            highlights.Add("Auth path: " + authPath);
        }

        if (workloadSummary.StrongCount > 0)
        {
            highlights.Add("Strong workloads: " + string.Join(", ", workloadSummary.StrongServices));
        }
        else if (workloadSummary.ModerateCount > 0)
        {
            highlights.Add("Moderate workloads: " + string.Join(", ", workloadSummary.ModerateServices.Take(4)));
        }

        var dnsCategorySummary = DescribeDnsApplicationCategories(dnsApplicationSummary, 3);
        if (!string.IsNullOrWhiteSpace(dnsCategorySummary))
        {
            highlights.Add("App footprint: " + dnsCategorySummary);
        }

        var evidenceCategorySummary = DescribeEvidenceCategories(evidenceSummary, 3);
        if (!string.IsNullOrWhiteSpace(evidenceCategorySummary))
        {
            highlights.Add("Evidence groups: " + evidenceCategorySummary);
        }

        if (analysis.UserEnumerationStatus == Microsoft365AuthExposureStatus.Exposed)
        {
            highlights.Add("User enumeration: exposed");
        }

        if (!string.IsNullOrWhiteSpace(analysis.IdentityProvider))
        {
            highlights.Add("Identity provider: " + analysis.IdentityProvider);
        }
        else if (analysis.IdentityProviderKind != TenantIdentityProviderKind.Unknown)
        {
            highlights.Add("Identity provider: " + analysis.IdentityProviderKind);
        }

        if (!string.IsNullOrWhiteSpace(analysis.TenantId))
        {
            highlights.Add("Tenant ID: " + analysis.TenantId);
        }

        if (!string.IsNullOrWhiteSpace(analysis.CompanyName))
        {
            highlights.Add("Company: " + analysis.CompanyName);
        }

        if (!string.IsNullOrWhiteSpace(analysis.TenantName))
        {
            highlights.Add("Tenant namespace: " + analysis.TenantName);
        }

        if (!string.IsNullOrWhiteSpace(analysis.TenantNamespaceDomain))
        {
            highlights.Add("Tenant namespace domain: " + analysis.TenantNamespaceDomain);
        }

        var domainEvidenceSummary = DescribeDomainEvidence(analysis.TenantDomains, 3);
        if (!string.IsNullOrWhiteSpace(domainEvidenceSummary))
        {
            highlights.Add("Domain evidence: " + domainEvidenceSummary);
        }

        if (detectedServices.Count > 0)
        {
            highlights.Add("Detected services: " + string.Join(", ", detectedServices.Take(4)));
        }

        return highlights;
    }

    private static string DescribeDnsApplicationCategories(Microsoft365DnsApplicationSummary summary, int take)
    {
        if (summary == null || summary.Categories.Count == 0 || take <= 0)
        {
            return string.Empty;
        }

        return string.Join(
            ", ",
            summary.Categories
                .Take(take)
                .Select(item => $"{FormatDetectedDnsAppCategory(item.Category)} {item.Count} ({FormatDetectionConfidence(item.HighestConfidence)})"));
    }

    private static string DescribeEvidenceCategories(Microsoft365EvidenceSummary summary, int take)
    {
        if (summary == null || summary.Categories.Count == 0 || take <= 0)
        {
            return string.Empty;
        }

        return string.Join(
            ", ",
            summary.Categories
                .Take(take)
                .Select(item => $"{FormatEvidenceCategory(item.Category)} {item.Count} ({FormatDetectionConfidence(item.HighestConfidence)})"));
    }

    private static string DescribeDomainEvidence(IReadOnlyList<Microsoft365TenantDomain>? domains, int take)
    {
        if (domains == null || domains.Count == 0 || take <= 0)
        {
            return string.Empty;
        }

        return string.Join(
            ", ",
            domains
                .Where(static domain => domain.Role != Microsoft365TenantDomainRole.Unknown)
                .GroupBy(static domain => domain.Role)
                .OrderBy(static group => GetDomainEvidenceSortOrder(group.Key))
                .ThenByDescending(static group => group.Max(item => item.Confidence))
                .ThenBy(static group => group.Key.ToString(), StringComparer.OrdinalIgnoreCase)
                .Take(take)
                .Select(group => $"{FormatDomainEvidenceRole(group.Key)} {group.Count()} ({FormatDetectionConfidence(group.Max(static item => item.Confidence))})"));
    }

    private static int GetDomainEvidenceSortOrder(Microsoft365TenantDomainRole role)
    {
        switch (role)
        {
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

    private static string FormatDomainEvidenceRole(Microsoft365TenantDomainRole role)
    {
        switch (role)
        {
            case Microsoft365TenantDomainRole.Primary:
                return "Primary";
            case Microsoft365TenantDomainRole.IdentityDomain:
                return "Identity-derived";
            case Microsoft365TenantDomainRole.AcceptedCustomDomain:
                return "DKIM-derived";
            case Microsoft365TenantDomainRole.MicrosoftManagedNamespace:
                return "Namespace-derived";
            case Microsoft365TenantDomainRole.Unknown:
            default:
                return "Unknown";
        }
    }

    private static string FormatDetectedDnsAppCategory(DetectedDnsAppCategory category)
    {
        switch (category)
        {
            case DetectedDnsAppCategory.Productivity:
                return "Productivity";
            case DetectedDnsAppCategory.CRM:
                return "CRM";
            case DetectedDnsAppCategory.EmailMarketing:
                return "Email marketing";
            case DetectedDnsAppCategory.EmailSecurity:
                return "Email security";
            case DetectedDnsAppCategory.EmailSignatures:
                return "Email signatures";
            case DetectedDnsAppCategory.DmarcReporting:
                return "DMARC reporting";
            case DetectedDnsAppCategory.Security:
                return "Security";
            case DetectedDnsAppCategory.Analytics:
                return "Analytics";
            case DetectedDnsAppCategory.Verification:
                return "Verification";
            case DetectedDnsAppCategory.DnsHosting:
                return "DNS hosting";
            case DetectedDnsAppCategory.CDN:
                return "CDN";
            case DetectedDnsAppCategory.Identity:
                return "Identity";
            case DetectedDnsAppCategory.Other:
                return "Other";
            case DetectedDnsAppCategory.Unknown:
            default:
                return "Unknown";
        }
    }

    private static string FormatEvidenceCategory(Microsoft365EvidenceCategory category)
    {
        switch (category)
        {
            case Microsoft365EvidenceCategory.Identity:
                return "Identity";
            case Microsoft365EvidenceCategory.Mail:
                return "Mail";
            case Microsoft365EvidenceCategory.Service:
                return "Services";
            case Microsoft365EvidenceCategory.DnsApplication:
                return "Apps";
            case Microsoft365EvidenceCategory.Authentication:
                return "Authentication";
            case Microsoft365EvidenceCategory.Domain:
                return "Domains";
            case Microsoft365EvidenceCategory.Unknown:
            default:
                return "Unknown";
        }
    }

    private static string FormatDetectionConfidence(Microsoft365DetectionConfidence confidence)
    {
        switch (confidence)
        {
            case Microsoft365DetectionConfidence.Strong:
                return "strong";
            case Microsoft365DetectionConfidence.Moderate:
                return "moderate";
            case Microsoft365DetectionConfidence.Weak:
                return "weak";
            case Microsoft365DetectionConfidence.Unknown:
            default:
                return "unknown";
        }
    }

    private static string FormatAuthenticationDomainPosture(Microsoft365AuthDomainPostureKind posture)
    {
        switch (posture)
        {
            case Microsoft365AuthDomainPostureKind.ManagedTenant:
                return "managed";
            case Microsoft365AuthDomainPostureKind.FederatedTenant:
                return "federated";
            case Microsoft365AuthDomainPostureKind.ConsumerTenant:
                return "consumer";
            case Microsoft365AuthDomainPostureKind.Unknown:
            default:
                return "unknown-posture";
        }
    }

    private static string FormatAuthenticationCredentialFlow(Microsoft365AuthCredentialFlowKind flow)
    {
        switch (flow)
        {
            case Microsoft365AuthCredentialFlowKind.NativeCredential:
                return "native-credential";
            case Microsoft365AuthCredentialFlowKind.Redirect:
                return "redirect";
            case Microsoft365AuthCredentialFlowKind.Unknown:
            default:
                return "unknown-flow";
        }
    }

    private static string FormatAuthenticationThrottlingStatus(Microsoft365AuthThrottlingStatus throttlingStatus)
    {
        switch (throttlingStatus)
        {
            case Microsoft365AuthThrottlingStatus.NoThrottling:
                return "no-throttling";
            case Microsoft365AuthThrottlingStatus.ThrottlingObserved:
                return "throttling-observed";
            case Microsoft365AuthThrottlingStatus.Unknown:
            default:
                return "unknown-throttling";
        }
    }
}

/// <summary>Provides microsoft365 tenant info functionality.</summary>
public sealed class Microsoft365TenantInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the query succeeded value.</summary>
    public bool QuerySucceeded { get; set; }
    /// <summary>Gets or sets the failure reason value.</summary>
    public string? FailureReason { get; set; }
    /// <summary>Gets or sets the is microsoft365 tenant value.</summary>
    public bool IsMicrosoft365Tenant { get; set; }
    /// <summary>Gets or sets the detection confidence value.</summary>
    public Microsoft365DetectionConfidence DetectionConfidence { get; set; }
    /// <summary>Gets or sets the tenant id value.</summary>
    public string? TenantId { get; set; }
    /// <summary>Gets or sets the tenant name value.</summary>
    public string? TenantName { get; set; }
    /// <summary>Gets or sets the company name value.</summary>
    public string? CompanyName { get; set; }
    /// <summary>Gets or sets the tenant namespace domain value.</summary>
    public string? TenantNamespaceDomain { get; set; }
    /// <summary>Gets or sets the name space type value.</summary>
    public string? NameSpaceType { get; set; }
    /// <summary>Gets or sets the identity provider kind value.</summary>
    public TenantIdentityProviderKind IdentityProviderKind { get; set; }
    /// <summary>Gets or sets the identity provider value.</summary>
    public string? IdentityProvider { get; set; }
    /// <summary>Gets or sets the federation mode value.</summary>
    public Microsoft365FederationMode FederationMode { get; set; }
    /// <summary>Gets or sets the cloud instance value.</summary>
    public TenantCloudInstanceKind CloudInstance { get; set; }
    /// <summary>Gets or sets the region value.</summary>
    public TenantRegionKind Region { get; set; }
    /// <summary>Gets or sets the consumer domain value.</summary>
    public bool ConsumerDomain { get; set; }
    /// <summary>Gets or sets the user enumeration status value.</summary>
    public Microsoft365AuthExposureStatus UserEnumerationStatus { get; set; }
    /// <summary>Gets or sets the smart lockout status value.</summary>
    public Microsoft365AuthExposureStatus SmartLockoutStatus { get; set; }
    /// <summary>Gets or sets the throttling status value.</summary>
    public Microsoft365AuthThrottlingStatus ThrottlingStatus { get; set; }
    /// <summary>Gets or sets the authentication probe succeeded value.</summary>
    public bool AuthenticationProbeSucceeded { get; set; }
    /// <summary>Gets or sets the authentication probe address value.</summary>
    public string? AuthenticationProbeAddress { get; set; }
    /// <summary>Gets or sets the authentication probe value.</summary>
    public MicrosoftCredentialTypeProbe? AuthenticationProbe { get; set; }
    /// <summary>Gets or sets the authentication summary value.</summary>
    public Microsoft365AuthenticationSummary AuthenticationSummary { get; set; } = new();
    /// <summary>Gets or sets the authentication path value.</summary>
    public Microsoft365AuthPathKind AuthenticationPath { get; set; }
    /// <summary>Gets or sets the supported grant types value.</summary>
    public IReadOnlyList<string> SupportedGrantTypes { get; set; } = Array.Empty<string>();
    /// <summary>Gets or sets the supported response types value.</summary>
    public IReadOnlyList<string> SupportedResponseTypes { get; set; } = Array.Empty<string>();
    /// <summary>Gets or sets the services value.</summary>
    public IReadOnlyList<Microsoft365ServiceDetection> Services { get; set; } = Array.Empty<Microsoft365ServiceDetection>();
    /// <summary>Gets or sets the workload summary value.</summary>
    public Microsoft365WorkloadConfidenceSummary WorkloadSummary { get; set; } = new();
    /// <summary>Gets or sets the dns application summary value.</summary>
    public Microsoft365DnsApplicationSummary DnsApplicationSummary { get; set; } = new();
    /// <summary>Gets or sets the evidence summary value.</summary>
    public Microsoft365EvidenceSummary EvidenceSummary { get; set; } = new();
    /// <summary>Gets or sets the tenant domains value.</summary>
    public IReadOnlyList<Microsoft365TenantDomain> TenantDomains { get; set; } = Array.Empty<Microsoft365TenantDomain>();
    /// <summary>Gets or sets the known subdomains value.</summary>
    public IReadOnlyList<KnownMicrosoft365Subdomain> KnownSubdomains { get; set; } = Array.Empty<KnownMicrosoft365Subdomain>();
    /// <summary>Gets or sets the detected dns applications value.</summary>
    public IReadOnlyList<DetectedDnsApplication> DetectedDnsApplications { get; set; } = Array.Empty<DetectedDnsApplication>();
    /// <summary>Gets or sets the evidence ledger value.</summary>
    public IReadOnlyList<Microsoft365EvidenceItem> EvidenceLedger { get; set; } = Array.Empty<Microsoft365EvidenceItem>();
    /// <summary>Gets or sets the assessments value.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = Array.Empty<Assessment>();
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = string.Empty;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = string.Empty;
    /// <summary>Gets or sets the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the positives value.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the references value.</summary>
    public IReadOnlyList<string> References { get; set; } = Array.Empty<string>();
    /// <summary>Gets or sets the highlights value.</summary>
    public IReadOnlyList<string> Highlights { get; set; } = Array.Empty<string>();
    /// <summary>Gets or sets the raw value.</summary>
    [JsonIgnore]
    public Microsoft365TenantAnalysis Raw { get; set; } = null!;
}
