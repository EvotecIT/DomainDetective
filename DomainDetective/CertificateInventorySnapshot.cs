using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace DomainDetective {
    /// <summary>
    /// Represents one persisted certificate inventory snapshot.
    /// </summary>
    public sealed class CertificateInventorySnapshot {
        public DateTimeOffset CapturedAtUtc { get; set; }
        public int Port { get; set; }
        public List<CertificateInventoryEntry> Entries { get; set; } = new();
        public List<NativeCtLogDiagnosticEntry> NativeCtLogDiagnostics { get; set; } = new();
        public List<string> NativeCtLogDiagnosticsRaw { get; set; } = new();
        public List<PassiveCtDiagnosticEntry> PassiveCtDiagnostics { get; set; } = new();
        public List<TargetDecisionDiagnosticEntry> TargetDecisionDiagnostics { get; set; } = new();
        public List<TargetDecisionSummaryEntry> TargetDecisionSummary { get; set; } = new();
    }

    /// <summary>
    /// Structured native CT ingestion diagnostic captured alongside inventory snapshots.
    /// </summary>
    public sealed class NativeCtLogDiagnosticEntry {
        public string Scope { get; set; } = string.Empty;
        public bool SharedIngestion { get; set; }
        public bool IsRetired { get; set; }
        public string State { get; set; } = "Unknown";
        public string LogUrl { get; set; } = string.Empty;
        public long? TreeSize { get; set; }
        public long? LastProcessedIndex { get; set; }
        public long? LagBefore { get; set; }
        public long? LagAfter { get; set; }
        public DateTimeOffset? CircuitOpenUntilUtc { get; set; }
        public string? Failure { get; set; }
    }

    /// <summary>
    /// Structured passive/public CT provider diagnostic captured alongside inventory snapshots.
    /// </summary>
    public sealed class PassiveCtDiagnosticEntry {
        public string Scope { get; set; } = string.Empty;
        public string QueryKind { get; set; } = string.Empty;
        public string SourceName { get; set; } = string.Empty;
        public string RequestUrl { get; set; } = string.Empty;
        public string State { get; set; } = "Unknown";
        public bool RetrySuggested { get; set; }
        public DateTimeOffset? CooldownUntilUtc { get; set; }
        public int? RetryAfterSeconds { get; set; }
        public string? Failure { get; set; }
    }

    /// <summary>
    /// Structured target-selection diagnostic captured alongside inventory snapshots.
    /// </summary>
    public sealed class TargetDecisionDiagnosticEntry {
        public string Stage { get; set; } = string.Empty;
        public string Action { get; set; } = string.Empty;
        public string Reason { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public string RecommendedAction { get; set; } = string.Empty;
        public string Target { get; set; } = string.Empty;
        public string? Service { get; set; }
        public int? PriorityScore { get; set; }
        public string? Message { get; set; }
        public IReadOnlyList<string> TargetOrigins { get; set; } = Array.Empty<string>();
    }

    /// <summary>
    /// Grouped summary bucket for target-selection diagnostics.
    /// </summary>
    public sealed class TargetDecisionSummaryEntry {
        public string Stage { get; set; } = string.Empty;
        public string Action { get; set; } = string.Empty;
        public string Reason { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public string RecommendedAction { get; set; } = string.Empty;
        public int Count { get; set; }
        public IReadOnlyList<string> ExampleTargets { get; set; } = Array.Empty<string>();
        public IReadOnlyList<string> ExampleServices { get; set; } = Array.Empty<string>();
        public IReadOnlyList<string> TargetOrigins { get; set; } = Array.Empty<string>();
    }

    /// <summary>
    /// Represents one host entry inside a certificate inventory snapshot.
    /// </summary>
    public sealed class CertificateInventoryEntry {
        public string Host { get; set; } = string.Empty;
        public string? ResolvedHost { get; set; }
        public string Url { get; set; } = string.Empty;
        public string Scheme { get; set; } = "https";
        public int Port { get; set; } = 443;
        public string Service { get; set; } = "HTTPS";
        public string? CertificateSubject { get; set; }
        public string? CertificateIssuer { get; set; }
        public string? CertificateThumbprint { get; set; }
        public string? CertificateSerialNumber { get; set; }
        public string? CertificateIssuerCommonName { get; set; }
        public string? CertificateIssuerOrganization { get; set; }
        public string? CertificateIssuerNormalized { get; set; }
        public string? CertificateAuthorityFamily { get; set; }
        public string? CertificateRootSubject { get; set; }
        public string? CertificateRootIssuer { get; set; }
        public string? CertificateRootIssuerCommonName { get; set; }
        public string? CertificateRootIssuerOrganization { get; set; }
        public string? CertificateRootIssuerNormalized { get; set; }
        public string? CertificateRootAuthorityFamily { get; set; }
        public string? CertificateRootThumbprint { get; set; }
        public int CertificateChainLength { get; set; }
        public int CertificateIntermediateCount { get; set; }
        public bool IsKnownCertificateAuthority { get; set; }
        public bool IsKnownRootCertificateAuthority { get; set; }
        public DateTimeOffset? NotBeforeUtc { get; set; }
        public DateTimeOffset? NotAfterUtc { get; set; }
        public bool Valid { get; set; }
        public bool Expired { get; set; }
        public bool ChainComplete { get; set; }
        public bool IsReachable { get; set; }
        /// <summary>Best-effort reason captured when the live probe failed to complete successfully.</summary>
        public string? FailureReason { get; set; }
        /// <summary>Normalized failure kind captured for stable reuse and analytics.</summary>
        public CertificateFailureKind FailureKind { get; set; }
        public bool IsSelfSigned { get; set; }
        public bool HostnameMatch { get; set; }
        public bool PresentInCtLogs { get; set; }
        /// <summary>CT/discovery sources queried when evaluating certificate presence.</summary>
        public IReadOnlyList<string> CtDiscoverySources { get; set; } = Array.Empty<string>();
        /// <summary>CT template-format/configuration errors observed during CT discovery.</summary>
        public IReadOnlyList<string> CtTemplateFormatErrors { get; set; } = Array.Empty<string>();
        /// <summary>Earliest CT timestamp observed for this host/subdomain.</summary>
        public DateTimeOffset? CtFirstSeenUtc { get; set; }
        /// <summary>Latest CT timestamp observed for this host/subdomain.</summary>
        public DateTimeOffset? CtLastSeenUtc { get; set; }
        /// <summary>Latest CT entry timestamp tied to the latest observed certificate metadata.</summary>
        public DateTimeOffset? CtLatestCertificateEntryTimestampUtc { get; set; }
        /// <summary>Latest certificate subject observed in CT logs for this host/subdomain.</summary>
        public string? CtLatestCertificateSubject { get; set; }
        /// <summary>Latest certificate issuer observed in CT logs for this host/subdomain.</summary>
        public string? CtLatestCertificateIssuer { get; set; }
        /// <summary>Latest certificate serial number observed in CT logs for this host/subdomain.</summary>
        public string? CtLatestCertificateSerialNumber { get; set; }
        /// <summary>Latest certificate not-before timestamp observed in CT logs for this host/subdomain.</summary>
        public DateTimeOffset? CtLatestCertificateNotBeforeUtc { get; set; }
        /// <summary>Latest certificate not-after timestamp observed in CT logs for this host/subdomain.</summary>
        public DateTimeOffset? CtLatestCertificateNotAfterUtc { get; set; }
        /// <summary>Number of CT observations contributing to this host/subdomain aggregate.</summary>
        public int CtObservationCount { get; set; }
        /// <summary>Days to expiry as observed at snapshot capture time.</summary>
        public int DaysToExpire { get; set; }
        public int DaysValid { get; set; }
        public string Protocol { get; set; } = string.Empty;
        public string KeyAlgorithm { get; set; } = string.Empty;
        public int KeySize { get; set; }
        public bool WeakKey { get; set; }
        public bool Sha1Signature { get; set; }
        public bool RsaPssSignature { get; set; }
        public bool HasEnhancedKeyUsageExtension { get; set; }
        public bool HasAnyExtendedKeyUsageOid { get; set; }

        [Obsolete("Use HasAnyExtendedKeyUsageOid.")]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool HasAnyExtendedKeyUsage {
            get { return HasAnyExtendedKeyUsageOid; }
            set { HasAnyExtendedKeyUsageOid = value; }
        }

        public bool AllowsServerAuthentication { get; set; }
        public bool AllowsClientAuthentication { get; set; }
        public bool AllowsSecureEmail { get; set; }
        public string AuthenticationProfile { get; set; } = CertificateAuthenticationProfileClassifier.NoEkuExtension;
        public string? CertificateChainSource { get; set; }
        public List<string> CertificateChainSources { get; set; } = new();
        /// <summary>Origin tags explaining why this endpoint was targeted in the current capture run.</summary>
        public IReadOnlyList<string> TargetOrigins { get; set; } = Array.Empty<string>();
        /// <summary>How this endpoint entered the current capture result (live probe or recent snapshot reuse).</summary>
        public string CaptureDisposition { get; set; } = string.Empty;
        public List<string> ExtendedKeyUsageOids { get; set; } = new();
        public List<string> SubjectAlternativeNames { get; set; } = new();
        public List<string> CertificateChainSubjects { get; set; } = new();
        public List<string> CertificateChainIssuers { get; set; } = new();
        public List<string> CertificateChainThumbprints { get; set; } = new();
    }
}
