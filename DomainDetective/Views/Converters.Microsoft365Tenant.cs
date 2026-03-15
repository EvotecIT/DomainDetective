using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
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
        var authSummary = DescribeAuthenticationSummary(analysis.AuthenticationSummary);
        var summary = $"{(analysis.IsMicrosoft365Tenant ? "M365" : "No M365")} tenant; confidence {analysis.DetectionConfidence}; auth {authSummary}; services {detectedServices.Length}; domains {analysis.TenantDomains?.Count ?? 0}; apps {analysis.DetectedDnsApplications?.Count ?? 0}; evidence {analysis.EvidenceLedger?.Count ?? 0}; subdomains {analysis.KnownSubdomains?.Count ?? 0}";

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
            NameSpaceType = analysis.NameSpaceType,
            IdentityProviderKind = analysis.IdentityProviderKind,
            IdentityProvider = analysis.IdentityProvider,
            FederationMode = analysis.FederationMode,
            CloudInstance = analysis.CloudInstance,
            Region = analysis.Region,
            ConsumerDomain = analysis.ConsumerDomain,
            UserEnumerationStatus = analysis.UserEnumerationStatus,
            SmartLockoutStatus = analysis.SmartLockoutStatus,
            AuthenticationProbeSucceeded = analysis.AuthenticationProbeSucceeded,
            AuthenticationProbeAddress = analysis.AuthenticationProbeAddress,
            AuthenticationProbe = analysis.AuthenticationProbe,
            AuthenticationSummary = analysis.AuthenticationSummary,
            SupportedGrantTypes = analysis.SupportedGrantTypes ?? Array.Empty<string>(),
            SupportedResponseTypes = analysis.SupportedResponseTypes ?? Array.Empty<string>(),
            Services = analysis.Services ?? Array.Empty<Microsoft365ServiceDetection>(),
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
        return $"{summary.UserEnumerationStatus} / {summary.SmartLockoutStatus} ({FormatAuthenticationDomainPosture(summary.DomainPosture)}, {FormatAuthenticationCredentialFlow(summary.CredentialFlow)}; DomainType {domainType}; PrefCredential {preferredCredential})";
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
}

public sealed class Microsoft365TenantInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public bool QuerySucceeded { get; set; }
    public string? FailureReason { get; set; }
    public bool IsMicrosoft365Tenant { get; set; }
    public Microsoft365DetectionConfidence DetectionConfidence { get; set; }
    public string? TenantId { get; set; }
    public string? NameSpaceType { get; set; }
    public TenantIdentityProviderKind IdentityProviderKind { get; set; }
    public string? IdentityProvider { get; set; }
    public Microsoft365FederationMode FederationMode { get; set; }
    public TenantCloudInstanceKind CloudInstance { get; set; }
    public TenantRegionKind Region { get; set; }
    public bool ConsumerDomain { get; set; }
    public Microsoft365AuthExposureStatus UserEnumerationStatus { get; set; }
    public Microsoft365AuthExposureStatus SmartLockoutStatus { get; set; }
    public bool AuthenticationProbeSucceeded { get; set; }
    public string? AuthenticationProbeAddress { get; set; }
    public MicrosoftCredentialTypeProbe? AuthenticationProbe { get; set; }
    public Microsoft365AuthenticationSummary AuthenticationSummary { get; set; } = null!;
    public IReadOnlyList<string> SupportedGrantTypes { get; set; } = null!;
    public IReadOnlyList<string> SupportedResponseTypes { get; set; } = null!;
    public IReadOnlyList<Microsoft365ServiceDetection> Services { get; set; } = null!;
    public IReadOnlyList<Microsoft365TenantDomain> TenantDomains { get; set; } = null!;
    public IReadOnlyList<KnownMicrosoft365Subdomain> KnownSubdomains { get; set; } = null!;
    public IReadOnlyList<DetectedDnsApplication> DetectedDnsApplications { get; set; } = null!;
    public IReadOnlyList<Microsoft365EvidenceItem> EvidenceLedger { get; set; } = null!;
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public Microsoft365TenantAnalysis Raw { get; set; } = null!;
}
