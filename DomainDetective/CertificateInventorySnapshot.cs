using System;
using System.Collections.Generic;
using System.ComponentModel;
using DomainDetective.Providers.Endpoint;

namespace DomainDetective {
    /// <summary>
    /// Represents one persisted certificate inventory snapshot.
    /// </summary>
    public sealed class CertificateInventorySnapshot {
        /// <summary>Gets or sets the captured at utc value.</summary>
        public DateTimeOffset CapturedAtUtc { get; set; }
        /// <summary>Gets or sets the port value.</summary>
        public int Port { get; set; }
        /// <summary>Gets or sets the entries value.</summary>
        public List<CertificateInventoryEntry> Entries { get; set; } = new();
        /// <summary>Gets or sets the native ct log diagnostics value.</summary>
        public List<NativeCtLogDiagnosticEntry> NativeCtLogDiagnostics { get; set; } = new();
        /// <summary>Gets or sets the native ct log diagnostics raw value.</summary>
        public List<string> NativeCtLogDiagnosticsRaw { get; set; } = new();
        /// <summary>Gets or sets the passive ct diagnostics value.</summary>
        public List<PassiveCtDiagnosticEntry> PassiveCtDiagnostics { get; set; } = new();
        /// <summary>Gets or sets the target decision diagnostics value.</summary>
        public List<TargetDecisionDiagnosticEntry> TargetDecisionDiagnostics { get; set; } = new();
        /// <summary>Gets or sets the target decision summary value.</summary>
        public List<TargetDecisionSummaryEntry> TargetDecisionSummary { get; set; } = new();
    }

    /// <summary>
    /// Structured native CT ingestion diagnostic captured alongside inventory snapshots.
    /// </summary>
    public sealed class NativeCtLogDiagnosticEntry {
        /// <summary>Gets or sets the scope value.</summary>
        public string Scope { get; set; } = string.Empty;
        /// <summary>Gets or sets the shared ingestion value.</summary>
        public bool SharedIngestion { get; set; }
        /// <summary>Gets or sets the is retired value.</summary>
        public bool IsRetired { get; set; }
        /// <summary>Gets or sets the state value.</summary>
        public string State { get; set; } = "Unknown";
        /// <summary>Gets or sets the log url value.</summary>
        public string LogUrl { get; set; } = string.Empty;
        /// <summary>Gets or sets the tree size value.</summary>
        public long? TreeSize { get; set; }
        /// <summary>Gets or sets the last processed index value.</summary>
        public long? LastProcessedIndex { get; set; }
        /// <summary>Gets or sets the lag before value.</summary>
        public long? LagBefore { get; set; }
        /// <summary>Gets or sets the lag after value.</summary>
        public long? LagAfter { get; set; }
        /// <summary>Gets or sets the circuit open until utc value.</summary>
        public DateTimeOffset? CircuitOpenUntilUtc { get; set; }
        /// <summary>Gets or sets the failure value.</summary>
        public string? Failure { get; set; }
    }

    /// <summary>
    /// Structured passive/public CT provider diagnostic captured alongside inventory snapshots.
    /// </summary>
    public sealed class PassiveCtDiagnosticEntry {
        /// <summary>Gets or sets the scope value.</summary>
        public string Scope { get; set; } = string.Empty;
        /// <summary>Gets or sets the query kind value.</summary>
        public string QueryKind { get; set; } = string.Empty;
        /// <summary>Gets or sets the source name value.</summary>
        public string SourceName { get; set; } = string.Empty;
        /// <summary>Gets or sets the request url value.</summary>
        public string RequestUrl { get; set; } = string.Empty;
        /// <summary>Gets or sets the state value.</summary>
        public string State { get; set; } = "Unknown";
        /// <summary>Gets or sets the retry suggested value.</summary>
        public bool RetrySuggested { get; set; }
        /// <summary>Gets or sets the cooldown until utc value.</summary>
        public DateTimeOffset? CooldownUntilUtc { get; set; }
        /// <summary>Gets or sets the retry after seconds value.</summary>
        public int? RetryAfterSeconds { get; set; }
        /// <summary>Gets or sets the failure value.</summary>
        public string? Failure { get; set; }
    }

    /// <summary>
    /// Structured target-selection diagnostic captured alongside inventory snapshots.
    /// </summary>
    public sealed class TargetDecisionDiagnosticEntry {
        /// <summary>Gets or sets the stage value.</summary>
        public string Stage { get; set; } = string.Empty;
        /// <summary>Gets or sets the action value.</summary>
        public string Action { get; set; } = string.Empty;
        /// <summary>Gets or sets the reason value.</summary>
        public string Reason { get; set; } = string.Empty;
        /// <summary>Gets or sets the severity value.</summary>
        public string Severity { get; set; } = string.Empty;
        /// <summary>Gets or sets the recommended action value.</summary>
        public string RecommendedAction { get; set; } = string.Empty;
        /// <summary>Gets or sets the target value.</summary>
        public string Target { get; set; } = string.Empty;
        /// <summary>Gets or sets the service value.</summary>
        public string? Service { get; set; }
        /// <summary>Gets or sets the priority score value.</summary>
        public int? PriorityScore { get; set; }
        /// <summary>Gets or sets the message value.</summary>
        public string? Message { get; set; }
        /// <summary>Gets or sets the target origins value.</summary>
        public IReadOnlyList<string> TargetOrigins { get; set; } = Array.Empty<string>();
    }

    /// <summary>
    /// Grouped summary bucket for target-selection diagnostics.
    /// </summary>
    public sealed class TargetDecisionSummaryEntry {
        /// <summary>Gets or sets the stage value.</summary>
        public string Stage { get; set; } = string.Empty;
        /// <summary>Gets or sets the action value.</summary>
        public string Action { get; set; } = string.Empty;
        /// <summary>Gets or sets the reason value.</summary>
        public string Reason { get; set; } = string.Empty;
        /// <summary>Gets or sets the severity value.</summary>
        public string Severity { get; set; } = string.Empty;
        /// <summary>Gets or sets the recommended action value.</summary>
        public string RecommendedAction { get; set; } = string.Empty;
        /// <summary>Gets or sets the count value.</summary>
        public int Count { get; set; }
        /// <summary>Gets or sets the example targets value.</summary>
        public IReadOnlyList<string> ExampleTargets { get; set; } = Array.Empty<string>();
        /// <summary>Gets or sets the example services value.</summary>
        public IReadOnlyList<string> ExampleServices { get; set; } = Array.Empty<string>();
        /// <summary>Gets or sets the target origins value.</summary>
        public IReadOnlyList<string> TargetOrigins { get; set; } = Array.Empty<string>();
    }

    /// <summary>
    /// Represents one host entry inside a certificate inventory snapshot.
    /// </summary>
    public sealed class CertificateInventoryEntry {
        /// <summary>Gets or sets the host value.</summary>
        public string Host { get; set; } = string.Empty;
        /// <summary>Gets or sets the resolved host value.</summary>
        public string? ResolvedHost { get; set; }
        /// <summary>Gets or sets the url value.</summary>
        public string Url { get; set; } = string.Empty;
        /// <summary>Gets or sets the scheme value.</summary>
        public string Scheme { get; set; } = "https";
        /// <summary>Gets or sets the port value.</summary>
        public int Port { get; set; } = 443;
        /// <summary>Gets or sets the service value.</summary>
        public string Service { get; set; } = "HTTPS";
        /// <summary>Time at which this endpoint observation was made.</summary>
        public DateTimeOffset? ObservedAtUtc { get; set; }
        /// <summary>Caller-supplied identifier for the network location that performed the probe.</summary>
        public string ProbeVantage { get; set; } = string.Empty;
        /// <summary>DNS resolver configuration used to collect endpoint evidence.</summary>
        public string DnsResolver { get; set; } = string.Empty;
        /// <summary>Time at which DNS evidence was collected for this endpoint.</summary>
        public DateTimeOffset? DnsObservedAtUtc { get; set; }
        /// <summary>Actual remote address reached by the protocol probe, when observable.</summary>
        public string? RemoteAddress { get; set; }
        /// <summary>Address family of <see cref="RemoteAddress"/>.</summary>
        public string? RemoteAddressFamily { get; set; }
        /// <summary>Addresses resolved for the effective endpoint hostname.</summary>
        public IReadOnlyList<string> ResolvedAddresses { get; set; } = Array.Empty<string>();
        /// <summary>CNAME targets followed from the logical hostname, in traversal order.</summary>
        public IReadOnlyList<string> CnameChain { get; set; } = Array.Empty<string>();
        /// <summary>HTTP redirect target hosts observed while probing the endpoint.</summary>
        public IReadOnlyList<string> RedirectTargets { get; set; } = Array.Empty<string>();
        /// <summary>Non-fatal DNS evidence collection errors.</summary>
        public IReadOnlyList<string> DnsObservationErrors { get; set; } = Array.Empty<string>();
        /// <summary>Explainable provider or managed-service attribution for the observed endpoint.</summary>
        public EndpointAttributionResult? Attribution { get; set; }
        /// <summary>Gets or sets the certificate subject value.</summary>
        public string? CertificateSubject { get; set; }
        /// <summary>Gets or sets the certificate issuer value.</summary>
        public string? CertificateIssuer { get; set; }
        /// <summary>Gets or sets the certificate thumbprint value.</summary>
        public string? CertificateThumbprint { get; set; }
        /// <summary>Gets or sets the certificate serial number value.</summary>
        public string? CertificateSerialNumber { get; set; }
        /// <summary>Gets or sets the certificate issuer common name value.</summary>
        public string? CertificateIssuerCommonName { get; set; }
        /// <summary>Gets or sets the certificate issuer organization value.</summary>
        public string? CertificateIssuerOrganization { get; set; }
        /// <summary>Gets or sets the certificate issuer normalized value.</summary>
        public string? CertificateIssuerNormalized { get; set; }
        /// <summary>Gets or sets the certificate authority family value.</summary>
        public string? CertificateAuthorityFamily { get; set; }
        /// <summary>Gets or sets the certificate root subject value.</summary>
        public string? CertificateRootSubject { get; set; }
        /// <summary>Gets or sets the certificate root issuer value.</summary>
        public string? CertificateRootIssuer { get; set; }
        /// <summary>Gets or sets the certificate root issuer common name value.</summary>
        public string? CertificateRootIssuerCommonName { get; set; }
        /// <summary>Gets or sets the certificate root issuer organization value.</summary>
        public string? CertificateRootIssuerOrganization { get; set; }
        /// <summary>Gets or sets the certificate root issuer normalized value.</summary>
        public string? CertificateRootIssuerNormalized { get; set; }
        /// <summary>Gets or sets the certificate root authority family value.</summary>
        public string? CertificateRootAuthorityFamily { get; set; }
        /// <summary>Gets or sets the certificate root thumbprint value.</summary>
        public string? CertificateRootThumbprint { get; set; }
        /// <summary>Gets or sets the certificate chain length value.</summary>
        public int CertificateChainLength { get; set; }
        /// <summary>Gets or sets the certificate intermediate count value.</summary>
        public int CertificateIntermediateCount { get; set; }
        /// <summary>Gets or sets the is known certificate authority value.</summary>
        public bool IsKnownCertificateAuthority { get; set; }
        /// <summary>Gets or sets the is known root certificate authority value.</summary>
        public bool IsKnownRootCertificateAuthority { get; set; }
        /// <summary>Gets or sets the not before utc value.</summary>
        public DateTimeOffset? NotBeforeUtc { get; set; }
        /// <summary>Gets or sets the not after utc value.</summary>
        public DateTimeOffset? NotAfterUtc { get; set; }
        /// <summary>Gets or sets the valid value.</summary>
        public bool Valid { get; set; }
        /// <summary>Gets or sets the expired value.</summary>
        public bool Expired { get; set; }
        /// <summary>Gets or sets the chain complete value.</summary>
        public bool ChainComplete { get; set; }
        /// <summary>Gets or sets the is reachable value.</summary>
        public bool IsReachable { get; set; }
        /// <summary>Best-effort reason captured when the live probe failed to complete successfully.</summary>
        public string? FailureReason { get; set; }
        /// <summary>Normalized failure kind captured for stable reuse and analytics.</summary>
        public CertificateFailureKind FailureKind { get; set; }
        /// <summary>Gets or sets the is self signed value.</summary>
        public bool IsSelfSigned { get; set; }
        /// <summary>Gets or sets the hostname match value.</summary>
        public bool HostnameMatch { get; set; }
        /// <summary>Gets or sets the present in ct logs value.</summary>
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
        /// <summary>Latest certificate thumbprint observed in CT logs for this host/subdomain.</summary>
        public string? CtLatestCertificateThumbprint { get; set; }
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
        /// <summary>Gets or sets the days valid value.</summary>
        public int DaysValid { get; set; }
        /// <summary>Gets or sets the protocol value.</summary>
        public string Protocol { get; set; } = string.Empty;
        /// <summary>Gets or sets the key algorithm value.</summary>
        public string KeyAlgorithm { get; set; } = string.Empty;
        /// <summary>Gets or sets the key size value.</summary>
        public int KeySize { get; set; }
        /// <summary>Gets or sets the weak key value.</summary>
        public bool WeakKey { get; set; }
        /// <summary>Gets or sets the sha1 signature value.</summary>
        public bool Sha1Signature { get; set; }
        /// <summary>Gets or sets the rsa pss signature value.</summary>
        public bool RsaPssSignature { get; set; }
        /// <summary>Gets or sets the has enhanced key usage extension value.</summary>
        public bool HasEnhancedKeyUsageExtension { get; set; }
        /// <summary>Gets or sets the has any extended key usage oid value.</summary>
        public bool HasAnyExtendedKeyUsageOid { get; set; }

        /// <summary>Represents the has any extended key usage value.</summary>
        [Obsolete("Use HasAnyExtendedKeyUsageOid.")]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool HasAnyExtendedKeyUsage {
            get { return HasAnyExtendedKeyUsageOid; }
            set { HasAnyExtendedKeyUsageOid = value; }
        }

        /// <summary>Gets or sets the allows server authentication value.</summary>
        public bool AllowsServerAuthentication { get; set; }
        /// <summary>Gets or sets the allows client authentication value.</summary>
        public bool AllowsClientAuthentication { get; set; }
        /// <summary>Gets or sets the allows secure email value.</summary>
        public bool AllowsSecureEmail { get; set; }
        /// <summary>Gets or sets the authentication profile value.</summary>
        public string AuthenticationProfile { get; set; } = CertificateAuthenticationProfileClassifier.NoEkuExtension;
        /// <summary>Gets or sets the certificate chain source value.</summary>
        public string? CertificateChainSource { get; set; }
        /// <summary>Gets or sets the certificate chain sources value.</summary>
        public List<string> CertificateChainSources { get; set; } = new();
        /// <summary>Origin tags explaining why this endpoint was targeted in the current capture run.</summary>
        public IReadOnlyList<string> TargetOrigins { get; set; } = Array.Empty<string>();
        /// <summary>How this endpoint entered the current capture result (live probe or recent snapshot reuse).</summary>
        public string CaptureDisposition { get; set; } = string.Empty;
        /// <summary>Gets or sets the extended key usage oids value.</summary>
        public List<string> ExtendedKeyUsageOids { get; set; } = new();
        /// <summary>Gets or sets the subject alternative names value.</summary>
        public List<string> SubjectAlternativeNames { get; set; } = new();
        /// <summary>Gets or sets the certificate chain subjects value.</summary>
        public List<string> CertificateChainSubjects { get; set; } = new();
        /// <summary>Gets or sets the certificate chain issuers value.</summary>
        public List<string> CertificateChainIssuers { get; set; } = new();
        /// <summary>Gets or sets the certificate chain thumbprints value.</summary>
        public List<string> CertificateChainThumbprints { get; set; } = new();
    }
}
