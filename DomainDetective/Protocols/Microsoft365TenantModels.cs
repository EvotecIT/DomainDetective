using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>
/// Typed detection status used by Microsoft 365 aggregate findings.
/// </summary>
public enum Microsoft365DetectionStatus {
    Unknown = 0,
    NotDetected = 1,
    Detected = 2
}

/// <summary>
/// Confidence level for Microsoft 365 public-signal detections.
/// </summary>
public enum Microsoft365DetectionConfidence {
    Unknown = 0,
    Weak = 1,
    Moderate = 2,
    Strong = 3
}

/// <summary>
/// High-level category for compact Microsoft 365 evidence ledger entries.
/// </summary>
public enum Microsoft365EvidenceCategory {
    Unknown = 0,
    Identity = 1,
    Mail = 2,
    Service = 3,
    DnsApplication = 4,
    Authentication = 5,
    Domain = 6
}

/// <summary>
/// Role for a typed Microsoft 365 tenant-related domain.
/// </summary>
public enum Microsoft365TenantDomainRole {
    Unknown = 0,
    Primary = 1,
    MicrosoftManagedNamespace = 2
}

/// <summary>
/// Authentication exposure posture for Microsoft identity probes.
/// </summary>
public enum Microsoft365AuthExposureStatus {
    Unknown = 0,
    NotExposed = 1,
    Exposed = 2
}

/// <summary>
/// Best-effort normalized tenant posture inferred from Microsoft auth probe context.
/// </summary>
public enum Microsoft365AuthDomainPostureKind {
    Unknown = 0,
    ManagedTenant = 1,
    FederatedTenant = 2,
    ConsumerTenant = 3
}

/// <summary>
/// Best-effort normalized credential flow inferred from Microsoft auth probe context.
/// </summary>
public enum Microsoft365AuthCredentialFlowKind {
    Unknown = 0,
    NativeCredential = 1,
    Redirect = 2
}

/// <summary>
/// Best-effort combined Microsoft authentication path derived from posture and flow.
/// </summary>
public enum Microsoft365AuthPathKind {
    Unknown = 0,
    ManagedNative = 1,
    ManagedRedirect = 2,
    FederatedRedirect = 3,
    Federated = 4,
    ConsumerIdentity = 5,
    Redirect = 6,
    NativeCredential = 7
}

/// <summary>
/// Compact typed summary of the public Microsoft authentication probe posture.
/// </summary>
public sealed class Microsoft365AuthenticationSummary {
    public bool ProbeResponsive { get; init; }
    public Microsoft365AuthExposureStatus UserEnumerationStatus { get; init; }
    /// <summary>
    /// Conservative best-effort smart lockout posture.
    /// Public Microsoft auth probes do not currently expose enough signal to infer this reliably,
    /// so this remains <see cref="Microsoft365AuthExposureStatus.Unknown"/> unless a future probe adds a safe signal.
    /// </summary>
    public Microsoft365AuthExposureStatus SmartLockoutStatus { get; init; }
    public int? IfExistsResult { get; init; }
    public int? ThrottleStatus { get; init; }
    public int? DomainType { get; init; }
    public int? PreferredCredential { get; init; }
    public string? FederationRedirectUrl { get; init; }
    public Microsoft365AuthDomainPostureKind DomainPosture { get; init; }
    public Microsoft365AuthCredentialFlowKind CredentialFlow { get; init; }
    public Microsoft365AuthPathKind AuthenticationPath { get; init; }
    public Microsoft365DetectionConfidence Confidence { get; init; }
    public IReadOnlyList<string> Evidence { get; init; } = Array.Empty<string>();
}

/// <summary>
/// High-level identity provider kind for a Microsoft 365 tenant.
/// </summary>
public enum TenantIdentityProviderKind {
    Unknown = 0,
    MicrosoftEntraId = 1,
    FederatedIdentityProvider = 2
}

/// <summary>
/// Federation posture returned by Microsoft public identity endpoints.
/// </summary>
public enum Microsoft365FederationMode {
    Unknown = 0,
    CloudManaged = 1,
    Federated = 2
}

/// <summary>
/// Microsoft cloud instance inferred from OIDC discovery.
/// </summary>
public enum TenantCloudInstanceKind {
    Unknown = 0,
    Global = 1,
    GCC = 2,
    GCCHigh = 3,
    DoD = 4,
    China = 5,
    Germany = 6
}

/// <summary>
/// Best-effort tenant region derived from OIDC tenant region hints.
/// </summary>
public enum TenantRegionKind {
    Unknown = 0,
    Worldwide = 1,
    NorthAmerica = 2,
    Europe = 3,
    AsiaPacific = 4
}

/// <summary>
/// Microsoft 365 workload or service family inferred from public signals.
/// </summary>
public enum Microsoft365ServiceKind {
    ExchangeOnline = 0,
    SharePointOnline = 1,
    OneDrive = 2,
    Teams = 3,
    IntuneEndpoint = 4,
    Defender = 5,
    EntraId = 6,
    PowerApps = 7,
    PowerAutomate = 8,
    PowerBi = 9
}

/// <summary>
/// Known Microsoft-related subdomain roles inferred from naming patterns.
/// </summary>
public enum KnownSubdomainRole {
    Unknown = 0,
    Autodiscover = 1,
    EnterpriseRegistration = 2,
    EnterpriseEnrollment = 3,
    LyncDiscover = 4,
    Sip = 5,
    MsoId = 6,
    SharePoint = 7,
    OneDrive = 8,
    Teams = 9,
    Portal = 10,
    FederationService = 11,
    Login = 12,
    Vpn = 13,
    Mail = 14,
    Webmail = 15,
    Owa = 16,
    Gateway = 17,
    Api = 18,
    Cdn = 19,
    StaticAssets = 20,
    DkimSelector = 21,
    Apps = 22,
    PowerBi = 23,
    Flow = 24,
    Automate = 25
}

/// <summary>
/// Typed category for DNS-discovered third-party application evidence.
/// </summary>
public enum DetectedDnsAppCategory {
    Unknown = 0,
    Productivity = 1,
    CRM = 2,
    EmailMarketing = 3,
    EmailSecurity = 4,
    EmailSignatures = 5,
    DmarcReporting = 6,
    Security = 7,
    Analytics = 8,
    Verification = 9,
    DnsHosting = 10,
    CDN = 11,
    Identity = 12,
    Other = 13
}

/// <summary>
/// Evidence source used for a detected DNS application.
/// </summary>
public enum DetectedDnsAppEvidenceKind {
    Unknown = 0,
    TxtRecord = 1,
    MxRecord = 2,
    NsRecord = 3,
    CnameRecord = 4,
    Subdomain = 5
}

/// <summary>
/// Single typed Microsoft 365 service detection.
/// </summary>
public sealed class Microsoft365ServiceDetection {
    public Microsoft365ServiceKind Kind { get; init; }
    public Microsoft365DetectionStatus Status { get; init; }
    public Microsoft365DetectionConfidence Confidence { get; init; }
    public IReadOnlyList<string> Evidence { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Compact rollup of detected Microsoft 365 workloads by confidence tier.
/// </summary>
public sealed class Microsoft365WorkloadConfidenceSummary {
    public int DetectedCount { get; init; }
    public int StrongCount { get; init; }
    public int ModerateCount { get; init; }
    public int WeakCount { get; init; }
    public IReadOnlyList<Microsoft365ServiceKind> StrongServices { get; init; } = Array.Empty<Microsoft365ServiceKind>();
    public IReadOnlyList<Microsoft365ServiceKind> ModerateServices { get; init; } = Array.Empty<Microsoft365ServiceKind>();
    public IReadOnlyList<Microsoft365ServiceKind> WeakServices { get; init; } = Array.Empty<Microsoft365ServiceKind>();
}

/// <summary>
/// Compact rollup entry for detected DNS applications within a single category.
/// </summary>
public sealed class Microsoft365DnsApplicationCategorySummary {
    public DetectedDnsAppCategory Category { get; init; }
    public int Count { get; init; }
    public Microsoft365DetectionConfidence HighestConfidence { get; init; }
    public IReadOnlyList<string> ApplicationNames { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Compact rollup of detected DNS applications by category.
/// </summary>
public sealed class Microsoft365DnsApplicationSummary {
    public int TotalCount { get; init; }
    public int CategoryCount { get; init; }
    public DetectedDnsAppCategory DominantCategory { get; init; }
    public int DominantCategoryCount { get; init; }
    public IReadOnlyList<Microsoft365DnsApplicationCategorySummary> Categories { get; init; } = Array.Empty<Microsoft365DnsApplicationCategorySummary>();
}

/// <summary>
/// Known Microsoft-related subdomain with typed role classification.
/// </summary>
public sealed class KnownMicrosoft365Subdomain {
    public string Name { get; init; } = string.Empty;
    public KnownSubdomainRole Role { get; init; }
    public SubdomainResolutionStatus ResolutionStatus { get; init; }
    public IReadOnlyList<string> Evidence { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Typed third-party application detection inferred from DNS data.
/// </summary>
public sealed class DetectedDnsApplication {
    public string Id { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public DetectedDnsAppCategory Category { get; init; }
    public DetectedDnsAppEvidenceKind EvidenceKind { get; init; }
    public Microsoft365DetectionConfidence Confidence { get; init; }
    public string Evidence { get; init; } = string.Empty;
    public string? Source { get; init; }
}

/// <summary>
/// Compact evidence entry explaining why a Microsoft 365 tenant was inferred.
/// </summary>
public sealed class Microsoft365EvidenceItem {
    public string Id { get; init; } = string.Empty;
    public string Label { get; init; } = string.Empty;
    public Microsoft365EvidenceCategory Category { get; init; }
    public Microsoft365DetectionConfidence Confidence { get; init; }
    public IReadOnlyList<string> Evidence { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Compact rollup entry for evidence within a single category.
/// </summary>
public sealed class Microsoft365EvidenceCategorySummary {
    public Microsoft365EvidenceCategory Category { get; init; }
    public int Count { get; init; }
    public Microsoft365DetectionConfidence HighestConfidence { get; init; }
    public IReadOnlyList<string> Labels { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Compact rollup of evidence ledger items by category.
/// </summary>
public sealed class Microsoft365EvidenceSummary {
    public int TotalCount { get; init; }
    public int CategoryCount { get; init; }
    public Microsoft365EvidenceCategory DominantCategory { get; init; }
    public int DominantCategoryCount { get; init; }
    public IReadOnlyList<Microsoft365EvidenceCategorySummary> Categories { get; init; } = Array.Empty<Microsoft365EvidenceCategorySummary>();
}

/// <summary>
/// Typed domain related to the inferred Microsoft 365 tenant.
/// </summary>
public sealed class Microsoft365TenantDomain {
    public string Domain { get; init; } = string.Empty;
    public Microsoft365TenantDomainRole Role { get; init; }
    public Microsoft365DetectionConfidence Confidence { get; init; }
    public IReadOnlyList<string> Evidence { get; init; } = Array.Empty<string>();
}
