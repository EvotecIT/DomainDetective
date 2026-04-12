using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>
/// Typed detection status used by Microsoft 365 aggregate findings.
/// </summary>
public enum Microsoft365DetectionStatus {
    /// <summary>Defines values for microsoft365 detection confidence.</summary>
    Unknown = 0,
    /// <summary>Defines values for microsoft365 detection confidence.</summary>
    NotDetected = 1,
    /// <summary>Defines values for microsoft365 detection confidence.</summary>
    Detected = 2
}

/// <summary>
/// Confidence level for Microsoft 365 public-signal detections.
/// </summary>
public enum Microsoft365DetectionConfidence {
    /// <summary>Defines values for microsoft365 evidence category.</summary>
    Unknown = 0,
    /// <summary>Defines values for microsoft365 evidence category.</summary>
    Weak = 1,
    /// <summary>Defines values for microsoft365 evidence category.</summary>
    Moderate = 2,
    /// <summary>Defines values for microsoft365 evidence category.</summary>
    Strong = 3
}

/// <summary>
/// High-level category for compact Microsoft 365 evidence ledger entries.
/// </summary>
public enum Microsoft365EvidenceCategory {
    /// <summary>Defines values for microsoft365 tenant domain role.</summary>
    Unknown = 0,
    /// <summary>Defines values for microsoft365 tenant domain role.</summary>
    Identity = 1,
    /// <summary>Defines values for microsoft365 tenant domain role.</summary>
    Mail = 2,
    /// <summary>Defines values for microsoft365 tenant domain role.</summary>
    Service = 3,
    /// <summary>Defines values for microsoft365 tenant domain role.</summary>
    DnsApplication = 4,
    /// <summary>Defines values for microsoft365 tenant domain role.</summary>
    Authentication = 5,
    /// <summary>Defines values for microsoft365 tenant domain role.</summary>
    Domain = 6
}

/// <summary>
/// Role for a typed Microsoft 365 tenant-related domain.
/// </summary>
public enum Microsoft365TenantDomainRole {
    /// <summary>Defines values for microsoft365 auth exposure status.</summary>
    Unknown = 0,
    /// <summary>Defines values for microsoft365 auth exposure status.</summary>
    Primary = 1,
    /// <summary>Defines values for microsoft365 auth exposure status.</summary>
    MicrosoftManagedNamespace = 2,
    /// <summary>Defines values for microsoft365 auth exposure status.</summary>
    IdentityDomain = 3,
    /// <summary>Defines values for microsoft365 auth exposure status.</summary>
    AcceptedCustomDomain = 4
}

/// <summary>
/// Authentication exposure posture for Microsoft identity probes.
/// </summary>
public enum Microsoft365AuthExposureStatus {
    /// <summary>Defines values for microsoft365 auth throttling status.</summary>
    Unknown = 0,
    /// <summary>Defines values for microsoft365 auth throttling status.</summary>
    NotExposed = 1,
    /// <summary>Defines values for microsoft365 auth throttling status.</summary>
    Exposed = 2
}

/// <summary>
/// Best-effort throttling posture inferred from the public Microsoft auth probe.
/// </summary>
public enum Microsoft365AuthThrottlingStatus {
    /// <summary>Defines values for microsoft365 auth domain posture kind.</summary>
    Unknown = 0,
    /// <summary>Defines values for microsoft365 auth domain posture kind.</summary>
    NoThrottling = 1,
    /// <summary>Defines values for microsoft365 auth domain posture kind.</summary>
    ThrottlingObserved = 2
}

/// <summary>
/// Best-effort normalized tenant posture inferred from Microsoft auth probe context.
/// </summary>
public enum Microsoft365AuthDomainPostureKind {
    /// <summary>Defines values for microsoft365 auth credential flow kind.</summary>
    Unknown = 0,
    /// <summary>Defines values for microsoft365 auth credential flow kind.</summary>
    ManagedTenant = 1,
    /// <summary>Defines values for microsoft365 auth credential flow kind.</summary>
    FederatedTenant = 2,
    /// <summary>Defines values for microsoft365 auth credential flow kind.</summary>
    ConsumerTenant = 3
}

/// <summary>
/// Best-effort normalized credential flow inferred from Microsoft auth probe context.
/// </summary>
public enum Microsoft365AuthCredentialFlowKind {
    /// <summary>Defines values for microsoft365 auth path kind.</summary>
    Unknown = 0,
    /// <summary>Defines values for microsoft365 auth path kind.</summary>
    NativeCredential = 1,
    /// <summary>Defines values for microsoft365 auth path kind.</summary>
    Redirect = 2
}

/// <summary>
/// Best-effort combined Microsoft authentication path derived from posture and flow.
/// </summary>
public enum Microsoft365AuthPathKind {
    /// <summary>Provides microsoft365 authentication summary functionality.</summary>
    Unknown = 0,
    /// <summary>Provides microsoft365 authentication summary functionality.</summary>
    ManagedNative = 1,
    /// <summary>Provides microsoft365 authentication summary functionality.</summary>
    ManagedRedirect = 2,
    /// <summary>Provides microsoft365 authentication summary functionality.</summary>
    FederatedRedirect = 3,
    /// <summary>Provides microsoft365 authentication summary functionality.</summary>
    Federated = 4,
    /// <summary>Provides microsoft365 authentication summary functionality.</summary>
    ConsumerIdentity = 5,
    /// <summary>Provides microsoft365 authentication summary functionality.</summary>
    Redirect = 6,
    /// <summary>Provides microsoft365 authentication summary functionality.</summary>
    NativeCredential = 7
}

/// <summary>
/// Compact typed summary of the public Microsoft authentication probe posture.
/// </summary>
public sealed class Microsoft365AuthenticationSummary {
    /// <summary>Gets or sets the probe responsive value.</summary>
    public bool ProbeResponsive { get; init; }
    /// <summary>Gets or sets the user enumeration status value.</summary>
    public Microsoft365AuthExposureStatus UserEnumerationStatus { get; init; }
    /// <summary>
    /// Conservative best-effort smart lockout posture.
    /// Public Microsoft auth probes do not currently expose enough signal to infer this reliably,
    /// so this remains <see cref="Microsoft365AuthExposureStatus.Unknown"/> unless a future probe adds a safe signal.
    /// </summary>
    public Microsoft365AuthExposureStatus SmartLockoutStatus { get; init; }
    /// <summary>Gets or sets the throttling status value.</summary>
    public Microsoft365AuthThrottlingStatus ThrottlingStatus { get; init; }
    /// <summary>Gets or sets the if exists result value.</summary>
    public int? IfExistsResult { get; init; }
    /// <summary>Gets or sets the throttle status value.</summary>
    public int? ThrottleStatus { get; init; }
    /// <summary>Gets or sets the domain type value.</summary>
    public int? DomainType { get; init; }
    /// <summary>Gets or sets the preferred credential value.</summary>
    public int? PreferredCredential { get; init; }
    /// <summary>Gets or sets the federation redirect url value.</summary>
    public string? FederationRedirectUrl { get; init; }
    /// <summary>Gets or sets the domain posture value.</summary>
    public Microsoft365AuthDomainPostureKind DomainPosture { get; init; }
    /// <summary>Gets or sets the credential flow value.</summary>
    public Microsoft365AuthCredentialFlowKind CredentialFlow { get; init; }
    /// <summary>Gets or sets the authentication path value.</summary>
    public Microsoft365AuthPathKind AuthenticationPath { get; init; }
    /// <summary>Gets or sets the confidence value.</summary>
    public Microsoft365DetectionConfidence Confidence { get; init; }
    /// <summary>Gets or sets the evidence value.</summary>
    public IReadOnlyList<string> Evidence { get; init; } = Array.Empty<string>();
}

/// <summary>
/// High-level identity provider kind for a Microsoft 365 tenant.
/// </summary>
public enum TenantIdentityProviderKind {
    /// <summary>Defines values for microsoft365 federation mode.</summary>
    Unknown = 0,
    /// <summary>Defines values for microsoft365 federation mode.</summary>
    MicrosoftEntraId = 1,
    /// <summary>Defines values for microsoft365 federation mode.</summary>
    FederatedIdentityProvider = 2
}

/// <summary>
/// Federation posture returned by Microsoft public identity endpoints.
/// </summary>
public enum Microsoft365FederationMode {
    /// <summary>Defines values for tenant cloud instance kind.</summary>
    Unknown = 0,
    /// <summary>Defines values for tenant cloud instance kind.</summary>
    CloudManaged = 1,
    /// <summary>Defines values for tenant cloud instance kind.</summary>
    Federated = 2
}

/// <summary>
/// Microsoft cloud instance inferred from OIDC discovery.
/// </summary>
public enum TenantCloudInstanceKind {
    /// <summary>Defines values for tenant region kind.</summary>
    Unknown = 0,
    /// <summary>Defines values for tenant region kind.</summary>
    Global = 1,
    /// <summary>Defines values for tenant region kind.</summary>
    GCC = 2,
    /// <summary>Defines values for tenant region kind.</summary>
    GCCHigh = 3,
    /// <summary>Defines values for tenant region kind.</summary>
    DoD = 4,
    /// <summary>Defines values for tenant region kind.</summary>
    China = 5,
    /// <summary>Defines values for tenant region kind.</summary>
    Germany = 6
}

/// <summary>
/// Best-effort tenant region derived from OIDC tenant region hints.
/// </summary>
public enum TenantRegionKind {
    /// <summary>Defines values for microsoft365 service kind.</summary>
    Unknown = 0,
    /// <summary>Defines values for microsoft365 service kind.</summary>
    Worldwide = 1,
    /// <summary>Defines values for microsoft365 service kind.</summary>
    NorthAmerica = 2,
    /// <summary>Defines values for microsoft365 service kind.</summary>
    Europe = 3,
    /// <summary>Defines values for microsoft365 service kind.</summary>
    AsiaPacific = 4
}

/// <summary>
/// Microsoft 365 workload or service family inferred from public signals.
/// </summary>
public enum Microsoft365ServiceKind {
    /// <summary>Defines values for microsoft365 service evidence source kind.</summary>
    ExchangeOnline = 0,
    /// <summary>Defines values for microsoft365 service evidence source kind.</summary>
    SharePointOnline = 1,
    /// <summary>Defines values for microsoft365 service evidence source kind.</summary>
    OneDrive = 2,
    /// <summary>Defines values for microsoft365 service evidence source kind.</summary>
    Teams = 3,
    /// <summary>Defines values for microsoft365 service evidence source kind.</summary>
    IntuneEndpoint = 4,
    /// <summary>Defines values for microsoft365 service evidence source kind.</summary>
    Defender = 5,
    /// <summary>Defines values for microsoft365 service evidence source kind.</summary>
    EntraId = 6,
    /// <summary>Defines values for microsoft365 service evidence source kind.</summary>
    PowerApps = 7,
    /// <summary>Defines values for microsoft365 service evidence source kind.</summary>
    PowerAutomate = 8,
    /// <summary>Defines values for microsoft365 service evidence source kind.</summary>
    PowerBi = 9
}

/// <summary>
/// Primary public evidence source used for a Microsoft 365 workload detection.
/// </summary>
public enum Microsoft365ServiceEvidenceSourceKind {
    /// <summary>Defines values for known subdomain role.</summary>
    Unknown = 0,
    /// <summary>Defines values for known subdomain role.</summary>
    IdentityProbe = 1,
    /// <summary>Defines values for known subdomain role.</summary>
    MailProtocol = 2,
    /// <summary>Defines values for known subdomain role.</summary>
    KnownSubdomain = 3,
    /// <summary>Defines values for known subdomain role.</summary>
    DnsApplication = 4
}

/// <summary>
/// Known Microsoft-related subdomain roles inferred from naming patterns.
/// </summary>
public enum KnownSubdomainRole {
    /// <summary>Defines values for detected dns app category.</summary>
    Unknown = 0,
    /// <summary>Defines values for detected dns app category.</summary>
    Autodiscover = 1,
    /// <summary>Defines values for detected dns app category.</summary>
    EnterpriseRegistration = 2,
    /// <summary>Defines values for detected dns app category.</summary>
    EnterpriseEnrollment = 3,
    /// <summary>Defines values for detected dns app category.</summary>
    LyncDiscover = 4,
    /// <summary>Defines values for detected dns app category.</summary>
    Sip = 5,
    /// <summary>Defines values for detected dns app category.</summary>
    MsoId = 6,
    /// <summary>Defines values for detected dns app category.</summary>
    SharePoint = 7,
    /// <summary>Defines values for detected dns app category.</summary>
    OneDrive = 8,
    /// <summary>Defines values for detected dns app category.</summary>
    Teams = 9,
    /// <summary>Defines values for detected dns app category.</summary>
    Portal = 10,
    /// <summary>Defines values for detected dns app category.</summary>
    FederationService = 11,
    /// <summary>Defines values for detected dns app category.</summary>
    Login = 12,
    /// <summary>Defines values for detected dns app category.</summary>
    Vpn = 13,
    /// <summary>Defines values for detected dns app category.</summary>
    Mail = 14,
    /// <summary>Defines values for detected dns app category.</summary>
    Webmail = 15,
    /// <summary>Defines values for detected dns app category.</summary>
    Owa = 16,
    /// <summary>Defines values for detected dns app category.</summary>
    Gateway = 17,
    /// <summary>Defines values for detected dns app category.</summary>
    Api = 18,
    /// <summary>Defines values for detected dns app category.</summary>
    Cdn = 19,
    /// <summary>Defines values for detected dns app category.</summary>
    StaticAssets = 20,
    /// <summary>Defines values for detected dns app category.</summary>
    DkimSelector = 21,
    /// <summary>Defines values for detected dns app category.</summary>
    Apps = 22,
    /// <summary>Defines values for detected dns app category.</summary>
    PowerBi = 23,
    /// <summary>Defines values for detected dns app category.</summary>
    Flow = 24,
    /// <summary>Defines values for detected dns app category.</summary>
    Automate = 25,
    /// <summary>Defines values for detected dns app category.</summary>
    DefenderPortal = 26,
    /// <summary>Defines values for detected dns app category.</summary>
    AdminPortal = 27,
    /// <summary>Defines values for detected dns app category.</summary>
    MyApps = 28,
    /// <summary>Defines values for detected dns app category.</summary>
    PasswordReset = 29,
    /// <summary>Defines values for detected dns app category.</summary>
    CompliancePortal = 30
}

/// <summary>
/// Typed category for DNS-discovered third-party application evidence.
/// </summary>
public enum DetectedDnsAppCategory {
    /// <summary>Defines values for detected dns app evidence kind.</summary>
    Unknown = 0,
    /// <summary>Defines values for detected dns app evidence kind.</summary>
    Productivity = 1,
    /// <summary>Defines values for detected dns app evidence kind.</summary>
    CRM = 2,
    /// <summary>Defines values for detected dns app evidence kind.</summary>
    EmailMarketing = 3,
    /// <summary>Defines values for detected dns app evidence kind.</summary>
    EmailSecurity = 4,
    /// <summary>Defines values for detected dns app evidence kind.</summary>
    EmailSignatures = 5,
    /// <summary>Defines values for detected dns app evidence kind.</summary>
    DmarcReporting = 6,
    /// <summary>Defines values for detected dns app evidence kind.</summary>
    Security = 7,
    /// <summary>Defines values for detected dns app evidence kind.</summary>
    Analytics = 8,
    /// <summary>Defines values for detected dns app evidence kind.</summary>
    Verification = 9,
    /// <summary>Defines values for detected dns app evidence kind.</summary>
    DnsHosting = 10,
    /// <summary>Defines values for detected dns app evidence kind.</summary>
    CDN = 11,
    /// <summary>Defines values for detected dns app evidence kind.</summary>
    Identity = 12,
    /// <summary>Defines values for detected dns app evidence kind.</summary>
    Other = 13
}

/// <summary>
/// Evidence source used for a detected DNS application.
/// </summary>
public enum DetectedDnsAppEvidenceKind {
    /// <summary>Provides microsoft365 service detection functionality.</summary>
    Unknown = 0,
    /// <summary>Provides microsoft365 service detection functionality.</summary>
    TxtRecord = 1,
    /// <summary>Provides microsoft365 service detection functionality.</summary>
    MxRecord = 2,
    /// <summary>Provides microsoft365 service detection functionality.</summary>
    NsRecord = 3,
    /// <summary>Provides microsoft365 service detection functionality.</summary>
    CnameRecord = 4,
    /// <summary>Provides microsoft365 service detection functionality.</summary>
    Subdomain = 5
}

/// <summary>
/// Single typed Microsoft 365 service detection.
/// </summary>
public sealed class Microsoft365ServiceDetection {
    /// <summary>Gets or sets the kind value.</summary>
    public Microsoft365ServiceKind Kind { get; init; }
    /// <summary>Gets or sets the status value.</summary>
    public Microsoft365DetectionStatus Status { get; init; }
    /// <summary>Gets or sets the confidence value.</summary>
    public Microsoft365DetectionConfidence Confidence { get; init; }
    /// <summary>Gets or sets the evidence source value.</summary>
    public Microsoft365ServiceEvidenceSourceKind EvidenceSource { get; init; }
    /// <summary>Gets or sets the tenant context boosted value.</summary>
    public bool TenantContextBoosted { get; init; }
    /// <summary>Gets or sets the evidence value.</summary>
    public IReadOnlyList<string> Evidence { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Compact rollup of detected Microsoft 365 workloads by confidence tier.
/// </summary>
public sealed class Microsoft365WorkloadConfidenceSummary {
    /// <summary>Gets or sets the detected count value.</summary>
    public int DetectedCount { get; init; }
    /// <summary>Gets or sets the strong count value.</summary>
    public int StrongCount { get; init; }
    /// <summary>Gets or sets the moderate count value.</summary>
    public int ModerateCount { get; init; }
    /// <summary>Gets or sets the weak count value.</summary>
    public int WeakCount { get; init; }
    /// <summary>Gets or sets the strong services value.</summary>
    public IReadOnlyList<Microsoft365ServiceKind> StrongServices { get; init; } = Array.Empty<Microsoft365ServiceKind>();
    /// <summary>Gets or sets the moderate services value.</summary>
    public IReadOnlyList<Microsoft365ServiceKind> ModerateServices { get; init; } = Array.Empty<Microsoft365ServiceKind>();
    /// <summary>Gets or sets the weak services value.</summary>
    public IReadOnlyList<Microsoft365ServiceKind> WeakServices { get; init; } = Array.Empty<Microsoft365ServiceKind>();
}

/// <summary>
/// Compact rollup entry for detected DNS applications within a single category.
/// </summary>
public sealed class Microsoft365DnsApplicationCategorySummary {
    /// <summary>Gets or sets the category value.</summary>
    public DetectedDnsAppCategory Category { get; init; }
    /// <summary>Gets or sets the count value.</summary>
    public int Count { get; init; }
    /// <summary>Gets or sets the highest confidence value.</summary>
    public Microsoft365DetectionConfidence HighestConfidence { get; init; }
    /// <summary>Gets or sets the application names value.</summary>
    public IReadOnlyList<string> ApplicationNames { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Compact rollup of detected DNS applications by category.
/// </summary>
public sealed class Microsoft365DnsApplicationSummary {
    /// <summary>Gets or sets the total count value.</summary>
    public int TotalCount { get; init; }
    /// <summary>Gets or sets the category count value.</summary>
    public int CategoryCount { get; init; }
    /// <summary>Gets or sets the dominant category value.</summary>
    public DetectedDnsAppCategory DominantCategory { get; init; }
    /// <summary>Gets or sets the dominant category count value.</summary>
    public int DominantCategoryCount { get; init; }
    /// <summary>Gets or sets the categories value.</summary>
    public IReadOnlyList<Microsoft365DnsApplicationCategorySummary> Categories { get; init; } = Array.Empty<Microsoft365DnsApplicationCategorySummary>();
}

/// <summary>
/// Known Microsoft-related subdomain with typed role classification.
/// </summary>
public sealed class KnownMicrosoft365Subdomain {
    /// <summary>Gets or sets the name value.</summary>
    public string Name { get; init; } = string.Empty;
    /// <summary>Gets or sets the role value.</summary>
    public KnownSubdomainRole Role { get; init; }
    /// <summary>Gets or sets the resolution status value.</summary>
    public SubdomainResolutionStatus ResolutionStatus { get; init; }
    /// <summary>Gets or sets the evidence value.</summary>
    public IReadOnlyList<string> Evidence { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Typed third-party application detection inferred from DNS data.
/// </summary>
public sealed class DetectedDnsApplication {
    /// <summary>Gets or sets the id value.</summary>
    public string Id { get; init; } = string.Empty;
    /// <summary>Gets or sets the name value.</summary>
    public string Name { get; init; } = string.Empty;
    /// <summary>Gets or sets the category value.</summary>
    public DetectedDnsAppCategory Category { get; init; }
    /// <summary>Gets or sets the evidence kind value.</summary>
    public DetectedDnsAppEvidenceKind EvidenceKind { get; init; }
    /// <summary>Gets or sets the confidence value.</summary>
    public Microsoft365DetectionConfidence Confidence { get; init; }
    /// <summary>Gets or sets the evidence value.</summary>
    public string Evidence { get; init; } = string.Empty;
    /// <summary>Gets or sets the source value.</summary>
    public string? Source { get; init; }
}

/// <summary>
/// Compact evidence entry explaining why a Microsoft 365 tenant was inferred.
/// </summary>
public sealed class Microsoft365EvidenceItem {
    /// <summary>Gets or sets the id value.</summary>
    public string Id { get; init; } = string.Empty;
    /// <summary>Gets or sets the label value.</summary>
    public string Label { get; init; } = string.Empty;
    /// <summary>Gets or sets the category value.</summary>
    public Microsoft365EvidenceCategory Category { get; init; }
    /// <summary>Gets or sets the confidence value.</summary>
    public Microsoft365DetectionConfidence Confidence { get; init; }
    /// <summary>Gets or sets the evidence value.</summary>
    public IReadOnlyList<string> Evidence { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Compact rollup entry for evidence within a single category.
/// </summary>
public sealed class Microsoft365EvidenceCategorySummary {
    /// <summary>Gets or sets the category value.</summary>
    public Microsoft365EvidenceCategory Category { get; init; }
    /// <summary>Gets or sets the count value.</summary>
    public int Count { get; init; }
    /// <summary>Gets or sets the highest confidence value.</summary>
    public Microsoft365DetectionConfidence HighestConfidence { get; init; }
    /// <summary>Gets or sets the labels value.</summary>
    public IReadOnlyList<string> Labels { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Compact rollup of evidence ledger items by category.
/// </summary>
public sealed class Microsoft365EvidenceSummary {
    /// <summary>Gets or sets the total count value.</summary>
    public int TotalCount { get; init; }
    /// <summary>Gets or sets the category count value.</summary>
    public int CategoryCount { get; init; }
    /// <summary>Gets or sets the dominant category value.</summary>
    public Microsoft365EvidenceCategory DominantCategory { get; init; }
    /// <summary>Gets or sets the dominant category count value.</summary>
    public int DominantCategoryCount { get; init; }
    /// <summary>Gets or sets the categories value.</summary>
    public IReadOnlyList<Microsoft365EvidenceCategorySummary> Categories { get; init; } = Array.Empty<Microsoft365EvidenceCategorySummary>();
}

/// <summary>
/// Typed domain related to the inferred Microsoft 365 tenant.
/// </summary>
public sealed class Microsoft365TenantDomain {
    /// <summary>Gets or sets the domain value.</summary>
    public string Domain { get; init; } = string.Empty;
    /// <summary>Gets or sets the role value.</summary>
    public Microsoft365TenantDomainRole Role { get; init; }
    /// <summary>Gets or sets the confidence value.</summary>
    public Microsoft365DetectionConfidence Confidence { get; init; }
    /// <summary>Gets or sets the evidence value.</summary>
    public IReadOnlyList<string> Evidence { get; init; } = Array.Empty<string>();
}
