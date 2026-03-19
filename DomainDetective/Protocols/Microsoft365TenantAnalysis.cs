using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Helpers;

namespace DomainDetective;

/// <summary>
/// Aggregates Microsoft 365 tenant identity, service, subdomain, and DNS application hints.
/// </summary>
public sealed partial class Microsoft365TenantAnalysis : IHasAssessments {
    private const int EvidenceLedgerMaxItems = 12;
    private const string AuthenticationProbePrefix = "dd-authprobe-";

    public string? Subject { get; private set; }
    public bool QuerySucceeded { get; private set; }
    public string? FailureReason { get; private set; }
    public bool IsMicrosoft365Tenant { get; private set; }
    public Microsoft365DetectionConfidence DetectionConfidence { get; private set; }
    public string? TenantId { get; private set; }
    public string? TenantName { get; private set; }
    public string? CompanyName { get; private set; }
    public string? TenantNamespaceDomain { get; private set; }
    public string? NameSpaceType { get; private set; }
    public TenantIdentityProviderKind IdentityProviderKind { get; private set; }
    public string? IdentityProvider { get; private set; }
    public Microsoft365FederationMode FederationMode { get; private set; }
    public TenantCloudInstanceKind CloudInstance { get; private set; }
    public TenantRegionKind Region { get; private set; }
    public bool ConsumerDomain { get; private set; }
    public Microsoft365AuthExposureStatus UserEnumerationStatus { get; private set; }
    public Microsoft365AuthExposureStatus SmartLockoutStatus { get; private set; }
    public Microsoft365AuthThrottlingStatus ThrottlingStatus { get; private set; }
    public bool AuthenticationProbeSucceeded { get; private set; }
    public string? AuthenticationProbeAddress { get; private set; }
    public MicrosoftCredentialTypeProbe? AuthenticationProbe { get; private set; }
    public Microsoft365AuthenticationSummary AuthenticationSummary { get; private set; } = new();
    public IReadOnlyList<string> SupportedGrantTypes { get; private set; } = Array.Empty<string>();
    public IReadOnlyList<string> SupportedResponseTypes { get; private set; } = Array.Empty<string>();
    public IReadOnlyList<Microsoft365ServiceDetection> Services { get; private set; } = Array.Empty<Microsoft365ServiceDetection>();
    public Microsoft365WorkloadConfidenceSummary WorkloadSummary { get; private set; } = new();
    public Microsoft365DnsApplicationSummary DnsApplicationSummary { get; private set; } = new();
    public Microsoft365EvidenceSummary EvidenceSummary { get; private set; } = new();
    public IReadOnlyList<Microsoft365TenantDomain> TenantDomains { get; private set; } = Array.Empty<Microsoft365TenantDomain>();
    public IReadOnlyList<KnownMicrosoft365Subdomain> KnownSubdomains { get; private set; } = Array.Empty<KnownMicrosoft365Subdomain>();
    public IReadOnlyList<DetectedDnsApplication> DetectedDnsApplications { get; private set; } = Array.Empty<DetectedDnsApplication>();
    public IReadOnlyList<Microsoft365EvidenceItem> EvidenceLedger { get; private set; } = Array.Empty<Microsoft365EvidenceItem>();
    public List<Assessment> Assessments { get; } = new();

    /// <summary>
    /// Aggregates Microsoft 365 signals from previously collected analyses.
    /// </summary>
    public void Analyze(
        string domain,
        IdpInfoAnalysis? idp,
        DnsInventoryAnalysis? dnsInventory,
        DkimAnalysis? dkim,
        SubdomainsAnalysis? subdomains,
        AutodiscoverAnalysis? autodiscover,
        InternalLogger? logger = null) {
        if (string.IsNullOrWhiteSpace(domain)) {
            throw new ArgumentNullException(nameof(domain));
        }

        Reset();
        Subject = DomainHelper.ValidateIdn(domain);

        bool hasAnySource = false;
        if (idp != null && string.Equals(idp.Domain, Subject, StringComparison.OrdinalIgnoreCase)) {
            hasAnySource = true;
            MergeIdentity(idp);
        }
        if (dnsInventory != null && string.Equals(dnsInventory.Subject, Subject, StringComparison.OrdinalIgnoreCase)) {
            hasAnySource = true;
        }
        if (subdomains != null && string.Equals(subdomains.Subject, Subject, StringComparison.OrdinalIgnoreCase)) {
            hasAnySource = true;
        }
        if (autodiscover != null && string.Equals(autodiscover.Subject, Subject, StringComparison.OrdinalIgnoreCase)) {
            hasAnySource = true;
        }
        if (dkim != null && string.Equals(dkim.Subject, Subject, StringComparison.OrdinalIgnoreCase)) {
            hasAnySource = true;
        }

        if (!hasAnySource) {
            QuerySucceeded = false;
            FailureReason = "No prerequisite Microsoft 365 source analyses were available for this domain.";
            Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "Microsoft 365",
                Code = Microsoft365Codes.NoSources,
                Target = Subject,
                Message = FailureReason
            });
            return;
        }

        KnownSubdomains = BuildKnownSubdomains(subdomains, Subject);
        DetectedDnsApplications = BuildDetectedApplications(dnsInventory, KnownSubdomains);
        Services = BuildServiceDetections(idp, dnsInventory, autodiscover, KnownSubdomains, DetectedDnsApplications);
        WorkloadSummary = BuildWorkloadSummary(Services);
        DnsApplicationSummary = BuildDnsApplicationSummary(DetectedDnsApplications);
        IsMicrosoft365Tenant = DetermineMicrosoft365Presence(idp, dnsInventory, autodiscover, KnownSubdomains, DetectedDnsApplications, Services);
        DetectionConfidence = BuildTenantDetectionConfidence(idp, dnsInventory, autodiscover, KnownSubdomains, Services, DetectedDnsApplications);
        TenantDomains = BuildTenantDomains(Subject, idp, dkim, DetectionConfidence);
        TenantName = InferTenantName(TenantDomains);
        TenantNamespaceDomain = FindTenantNamespaceDomain(TenantDomains);
        EvidenceLedger = BuildEvidenceLedger(idp, dnsInventory, autodiscover, Services, DetectedDnsApplications, TenantDomains);
        EvidenceSummary = BuildEvidenceSummary(EvidenceLedger);

        QuerySucceeded = true;

        if (IdentityProviderKind == TenantIdentityProviderKind.MicrosoftEntraId) {
            Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Info,
                Category = "Microsoft 365",
                Code = Microsoft365Codes.EntraDetected,
                Target = Subject,
                Message = $"Microsoft Entra ID detected{(string.IsNullOrWhiteSpace(TenantId) ? "." : $" (tenant {TenantId}).")}"
            });
        }

        var detectedServices = Services
            .Where(static service => service.Status == Microsoft365DetectionStatus.Detected)
            .Select(static service => service.Kind.ToString())
            .ToList();
        if (detectedServices.Count > 0) {
            Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Info,
                Category = "Microsoft 365",
                Code = Microsoft365Codes.ServicesDetected,
                Target = Subject,
                Message = $"Microsoft 365 service hints detected: {string.Join(", ", detectedServices)}."
            });
        }

        var dnsApps = DetectedDnsApplications
            .Where(static app =>
                app.Category == DetectedDnsAppCategory.Verification ||
                app.Category == DetectedDnsAppCategory.Productivity ||
                app.Category == DetectedDnsAppCategory.Identity ||
                app.Category == DetectedDnsAppCategory.CDN)
            .Take(6)
            .Select(static app => $"{app.Name} ({app.EvidenceKind})")
            .ToList();
        if (dnsApps.Count > 0) {
            Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Info,
                Category = "Microsoft 365",
                Code = Microsoft365Codes.DnsAppsDetected,
                Target = Subject,
                Message = $"DNS application evidence detected: {string.Join(", ", dnsApps)}."
            });
        }

        if (!IsMicrosoft365Tenant) {
            Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Info,
                Category = "Microsoft 365",
                Code = Microsoft365Codes.NotDetected,
                Target = Subject,
                Message = "No strong Microsoft 365 tenant signal was detected from the currently collected analyses."
            });
        }

        logger?.WriteVerbose(
            "Microsoft 365 aggregate for {0}: Tenant={1}, Services={2}, Apps={3}, M365={4}",
            Subject,
            string.IsNullOrWhiteSpace(TenantId) ? "-" : TenantId,
            Services.Count(service => service.Status == Microsoft365DetectionStatus.Detected),
            DetectedDnsApplications.Count,
            IsMicrosoft365Tenant);
    }

    private void MergeIdentity(IdpInfoAnalysis idp) {
        TenantId = idp.TenantId;
        CompanyName = idp.FederationBrandName;
        NameSpaceType = idp.NameSpaceType;
        IdentityProvider = !string.IsNullOrWhiteSpace(idp.IdentityProviderHost)
            ? idp.IdentityProviderHost
            : idp.FederatedAuthUrl;
        IdentityProviderKind = MapIdentityProviderKind(idp);
        FederationMode = MapFederationMode(idp.NameSpaceType);
        CloudInstance = MapCloudInstance(idp.CloudInstanceName);
        Region = MapRegion(idp.TenantRegionScope);
        ConsumerDomain = string.Equals(idp.TenantRegionScope, "consumer", StringComparison.OrdinalIgnoreCase);
        SupportedGrantTypes = Deduplicate(idp.GrantTypesSupported);
        SupportedResponseTypes = Deduplicate(idp.ResponseTypesSupported);
    }

    private void Reset() {
        Subject = null;
        QuerySucceeded = false;
        FailureReason = null;
        IsMicrosoft365Tenant = false;
        DetectionConfidence = Microsoft365DetectionConfidence.Unknown;
        TenantId = null;
        TenantName = null;
        CompanyName = null;
        TenantNamespaceDomain = null;
        NameSpaceType = null;
        IdentityProviderKind = TenantIdentityProviderKind.Unknown;
        IdentityProvider = null;
        FederationMode = Microsoft365FederationMode.Unknown;
        CloudInstance = TenantCloudInstanceKind.Unknown;
        Region = TenantRegionKind.Unknown;
        ConsumerDomain = false;
        UserEnumerationStatus = Microsoft365AuthExposureStatus.Unknown;
        SmartLockoutStatus = Microsoft365AuthExposureStatus.Unknown;
        ThrottlingStatus = Microsoft365AuthThrottlingStatus.Unknown;
        AuthenticationProbeSucceeded = false;
        AuthenticationProbeAddress = null;
        AuthenticationProbe = null;
        AuthenticationSummary = new Microsoft365AuthenticationSummary();
        SupportedGrantTypes = Array.Empty<string>();
        SupportedResponseTypes = Array.Empty<string>();
        Services = Array.Empty<Microsoft365ServiceDetection>();
        WorkloadSummary = new Microsoft365WorkloadConfidenceSummary();
        DnsApplicationSummary = new Microsoft365DnsApplicationSummary();
        EvidenceSummary = new Microsoft365EvidenceSummary();
        TenantDomains = Array.Empty<Microsoft365TenantDomain>();
        KnownSubdomains = Array.Empty<KnownMicrosoft365Subdomain>();
        DetectedDnsApplications = Array.Empty<DetectedDnsApplication>();
        EvidenceLedger = Array.Empty<Microsoft365EvidenceItem>();
        Assessments.Clear();
    }
}

internal static class Microsoft365Codes {
    public const string NoSources = "m365-no-sources";
    public const string EntraDetected = "m365-entra-detected";
    public const string ServicesDetected = "m365-services-detected";
    public const string DnsAppsDetected = "m365-dns-apps-detected";
    public const string AuthProbeDetected = "m365-auth-probe-detected";
    public const string AuthUserEnumerationExposed = "m365-auth-user-enumeration-exposed";
    public const string AuthManagedPostureDetected = "m365-auth-managed-posture-detected";
    public const string AuthFederatedPostureDetected = "m365-auth-federated-posture-detected";
    public const string AuthConsumerPostureDetected = "m365-auth-consumer-posture-detected";
    public const string AuthRedirectFlowDetected = "m365-auth-redirect-flow-detected";
    public const string AuthNativeCredentialFlowDetected = "m365-auth-native-credential-flow-detected";
    public const string AuthFederatedRedirectPathDetected = "m365-auth-federated-redirect-path-detected";
    public const string AuthManagedRedirectPathDetected = "m365-auth-managed-redirect-path-detected";
    public const string AuthManagedNativePathDetected = "m365-auth-managed-native-path-detected";
    public const string NotDetected = "m365-not-detected";
}
