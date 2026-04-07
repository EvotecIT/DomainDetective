using DnsClientX;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;

namespace DomainDetective;

/// <summary>
/// Options controlling certificate inventory capture from domain lists and discovered endpoints.
/// </summary>
public sealed class CertificateInventoryCaptureOptions {
    /// <summary>Certificate monitor cache directory (inventory snapshots are saved under the inventory subfolder).</summary>
    public string CacheDirectory { get; set; } = CertificateInventoryCmdletPathDefaults.DefaultCacheDirectory;

    /// <summary>DNS endpoint used for MX discovery.</summary>
    public DnsEndpoint DnsEndpoint { get; set; } = DnsEndpoint.System;

    /// <summary>When true, probes apex domains over HTTPS.</summary>
    public bool IncludeApexHttps { get; set; } = true;

    /// <summary>When true, probes www.&lt;domain&gt; over HTTPS.</summary>
    public bool IncludeWwwHttps { get; set; } = true;

    /// <summary>When true, discovers CT-observed subdomains and probes them over HTTPS.</summary>
    public bool IncludeCtDiscoveredSubdomains { get; set; }

    /// <summary>When true, CT-discovered subdomains are DNS-verified before inclusion.</summary>
    public bool VerifyCtDiscoveredSubdomains { get; set; }

    /// <summary>
    /// When true, CT-discovered subdomains are promoted into HTTPS probe targets for the current capture.
    /// Disable this for discovery-only lanes that should persist names now and let a later capture decide
    /// which discovered hosts are worth probing.
    /// </summary>
    public bool PromoteCtDiscoveredSubdomainsToHttpsProbes { get; set; } = true;

    /// <summary>Maximum CT rows processed per domain while discovering CT subdomains (0 means no explicit cap override).</summary>
    public int MaxCtRowsPerDomain { get; set; } = 10_000;

    /// <summary>Maximum CT-discovered subdomains retained per domain (0 means no explicit cap override).</summary>
    public int MaxCtSubdomainsPerDomain { get; set; } = 2_000;

    /// <summary>
    /// Optional domain list used only for CT subdomain discovery and CT metadata hydration.
    /// When empty, the full normalized input domain list is used.
    /// </summary>
    public List<string> CtDiscoveryDomains { get; } = new();

    /// <summary>
    /// Optional hosts that should skip passive CT metadata rescue because the caller already has
    /// durable CT-backed evidence for them or recently observed empty-result metadata attempts.
    /// </summary>
    public List<string> ExactHostSeedCtMetadataSuppressedHosts { get; } = new();

    /// <summary>
    /// Optional normalized hosts that should still perform CT fingerprint lookups even when the
    /// broader HTTPS metadata profile is running in lightweight mode.
    /// </summary>
    public List<string> CtMetadataTargetHosts { get; } = new();

    /// <summary>
    /// Optional normalized hosts that should remain eligible for exact passive CT metadata rescue.
    /// When empty, the broader <see cref="CtMetadataTargetHosts"/> list is reused.
    /// </summary>
    public List<string> ExactPassiveCtMetadataTargetHosts { get; } = new();

    /// <summary>When true, uses native RFC6962 CT log polling for subdomain discovery.</summary>
    public bool EnableNativeCtLogSubdomainSource { get; set; }

    /// <summary>When true (default), reuses one native CT ingestion pass across all domains in a capture run.</summary>
    public bool EnableNativeCtSharedIngestion { get; set; } = true;

    /// <summary>Maximum total CT rows processed by one shared native ingestion pass (0 means uncapped).</summary>
    public int NativeCtSharedMaxRowsTotal { get; set; } = 2_000_000;

    /// <summary>Maximum total CT-discovered subdomains retained by one shared native ingestion pass (0 means uncapped).</summary>
    public int NativeCtSharedMaxSubdomainsTotal { get; set; } = 500_000;

    /// <summary>When true, uses only native CT log polling for subdomain discovery (skips crt.sh/Cert Spotter).</summary>
    public bool NativeCtLogOnly { get; set; }

    /// <summary>
    /// When true, passive/public CT APIs (for example crt.sh or Cert Spotter) may be used
    /// as fallback for CT subdomain discovery.
    /// </summary>
    public bool EnablePassiveCtFallback { get; set; }

    /// <summary>
    /// When true, passive/public CT APIs (for example crt.sh or Cert Spotter) may be used
    /// to hydrate or rescue missing CT certificate metadata for both exact-host seeds and
    /// CT-discovered subdomains, without enabling passive CT discovery fallback more broadly.
    /// </summary>
    public bool EnablePassiveCtMetadataFallback { get; set; }

    /// <summary>
    /// When true, exact-host CT metadata rescue may query the public crt.sh PostgreSQL replica
    /// directly before falling back to passive/public CT web APIs. This is intended for
    /// thumbprint- and metadata-rescue lanes that need stronger exact-host CT coverage than the
    /// rate-limited web endpoints provide.
    /// </summary>
    public bool EnableCrtShPostgreSqlMetadataFallback { get; set; }

    /// <summary>
    /// Optional connection string used for direct crt.sh PostgreSQL metadata rescue.
    /// When empty and <see cref="EnableCrtShPostgreSqlMetadataFallback"/> is enabled, the capture
    /// uses the public guest endpoint (`crt.sh:5432/certwatch`) with TLS enabled.
    /// </summary>
    public string? CrtShPostgreSqlConnectionString { get; set; }

    /// <summary>
    /// Command timeout in seconds for direct crt.sh PostgreSQL metadata rescue.
    /// </summary>
    public int CrtShPostgreSqlCommandTimeoutSeconds { get; set; } = 15;

    /// <summary>Per-request timeout for passive/public CT HTTP calls.</summary>
    public TimeSpan PassiveCtRequestTimeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>Maximum retry count for transient passive/public CT HTTP failures.</summary>
    public int PassiveCtRetryCount { get; set; } = 2;

    /// <summary>Base delay between passive/public CT retry attempts.</summary>
    public TimeSpan PassiveCtRetryBaseDelay { get; set; } = TimeSpan.FromMilliseconds(750);

    /// <summary>Maximum delay between passive/public CT retry attempts.</summary>
    public TimeSpan PassiveCtRetryMaxDelay { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>Cooldown applied to passive/public CT sources after transient failures or rate limits.</summary>
    public TimeSpan PassiveCtSourceCooldown { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Minimum spacing between public crt.sh requests when passive/public CT fallback is active.
    /// This helps exact-host rescue and fallback discovery stay within respectful shared-source pacing.
    /// </summary>
    public TimeSpan PassiveCtCrtShMinimumSpacing { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Minimum spacing between Cert Spotter requests when passive/public CT fallback is active.
    /// This is anti-burst pacing only; the main safety rail is the run-local request budget below.
    /// </summary>
    public TimeSpan PassiveCtCertSpotterMinimumSpacing { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Maximum number of public crt.sh exact-host metadata requests issued during a single passive CT run.
    /// Zero means uncapped.
    /// </summary>
    public int PassiveCtCrtShMaximumRequestsPerRun { get; set; } = 8;

    /// <summary>
    /// Maximum number of Cert Spotter exact-host metadata requests issued during a single passive CT run.
    /// Zero means uncapped. The default stays conservative for unauthenticated public-plan access.
    /// </summary>
    public int PassiveCtCertSpotterMaximumRequestsPerRun { get; set; } = 1;

    /// <summary>
    /// Maximum number of concurrent passive/public CT network queries issued at once.
    /// This is intentionally separate from <see cref="DiscoveryParallelism"/> so DNS/native CT work
    /// can remain wide while rate-limited passive CT providers are queried more gently.
    /// </summary>
    public int PassiveCtParallelism { get; set; } = 4;

    /// <summary>Native CT log list URL used to resolve trusted CT logs.</summary>
    public string NativeCtLogListUrl { get; set; } = "https://www.gstatic.com/ct/log_list/v3/log_list.json";

    /// <summary>Optional explicit CT log URLs for native subdomain discovery.</summary>
    public List<string> NativeCtLogUrls { get; } = new();

    /// <summary>Optional native CT log URL prefixes that should be preferred ahead of other eligible logs.</summary>
    public List<string> NativeCtPreferredLogUrlPrefixes { get; } = new();

    /// <summary>Optional native CT log URL prefixes that should be excluded from discovery.</summary>
    public List<string> NativeCtExcludedLogUrlPrefixes { get; } = new();

    /// <summary>Maximum CT logs processed per domain during native subdomain discovery (0 means all).</summary>
    public int NativeCtMaxLogs { get; set; } = 12;

    /// <summary>Maximum CT entries processed per log during native subdomain discovery (0 means uncapped).</summary>
    public int NativeCtMaxEntriesPerLog { get; set; } = 2_000;

    /// <summary>Maximum get-entries batch size for native CT polling.</summary>
    public int NativeCtEntryBatchSize { get; set; } = 256;

    /// <summary>Initial per-log backfill when native CT cursor is missing (0 starts at current tree head).</summary>
    public int NativeCtInitialBackfillEntriesPerLog { get; set; } = 2_000;

    /// <summary>Optional native CT cursor state file path. Defaults to inventory/ct-native-cursor.json in CacheDirectory.</summary>
    public string? NativeCtCursorStatePath { get; set; }

    /// <summary>When true, includes pending CT logs from log list in native subdomain discovery.</summary>
    public bool NativeCtIncludePendingLogs { get; set; }

    /// <summary>When true, includes retired CT logs in native subdomain discovery to recover older certificate history.</summary>
    public bool NativeCtIncludeRetiredLogs { get; set; } = true;

    /// <summary>Optional delay between native CT HTTP requests.</summary>
    public TimeSpan NativeCtRequestDelay { get; set; } = TimeSpan.Zero;

    /// <summary>Per-request timeout for native CT HTTP calls.</summary>
    public TimeSpan NativeCtRequestTimeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>Maximum retry count for transient native CT HTTP failures.</summary>
    public int NativeCtRetryCount { get; set; } = 3;

    /// <summary>Base delay between native CT retry attempts.</summary>
    public TimeSpan NativeCtRetryBaseDelay { get; set; } = TimeSpan.FromMilliseconds(500);

    /// <summary>Maximum delay between native CT retry attempts.</summary>
    public TimeSpan NativeCtRetryMaxDelay { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>Consecutive native CT failures required before opening circuit breaker for a log.</summary>
    public int NativeCtCircuitBreakerFailureThreshold { get; set; } = 3;

    /// <summary>Base native CT circuit-breaker duration per log after repeated failures.</summary>
    public TimeSpan NativeCtCircuitBreakerDuration { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>When true, native CT polling automatically expands caps when cursor lag is large.</summary>
    public bool NativeCtEnableCatchUpMode { get; set; } = true;

    /// <summary>Cursor lag threshold at/above which native CT catch-up mode is activated.</summary>
    public int NativeCtCatchUpLagThreshold { get; set; } = 50_000;

    /// <summary>Maximum CT entries processed per log while native CT catch-up mode is active.</summary>
    public int NativeCtCatchUpMaxEntriesPerLog { get; set; } = 20_000;

    /// <summary>Maximum get-entries batch size used while native CT catch-up mode is active.</summary>
    public int NativeCtCatchUpBatchSize { get; set; } = 1_024;

    /// <summary>
    /// When true, performs CT metadata backfill for CT-discovered subdomains that are missing
    /// certificate metadata (subject/issuer/serial/notBefore/notAfter). When
    /// <see cref="EnablePassiveCtMetadataFallback"/> is enabled, passive/public CT APIs may be
    /// used for CT metadata hydration even if <see cref="EnablePassiveCtFallback"/> remains disabled.
    /// </summary>
    public bool BackfillMissingCtCertificateMetadata { get; set; } = true;

    /// <summary>When true, discovers MX hosts from DNS.</summary>
    public bool IncludeMxHosts { get; set; } = true;

    /// <summary>When true, also probes discovered MX hosts over HTTPS.</summary>
    public bool IncludeMxHttps { get; set; }

    /// <summary>When true, probes discovered MX hosts for SMTP STARTTLS on <see cref="SmtpPort"/>.</summary>
    public bool IncludeSmtpStartTls { get; set; } = true;

    /// <summary>When true, probes discovered MX hosts for SMTP STARTTLS on <see cref="SubmissionPort"/>.</summary>
    public bool IncludeSubmissionStartTls { get; set; } = true;

    /// <summary>When true, probes discovered MX hosts for IMAP TLS on <see cref="ImapPort"/>.</summary>
    public bool IncludeImapTls { get; set; }

    /// <summary>When true, probes discovered MX hosts for POP3 TLS on <see cref="Pop3Port"/>.</summary>
    public bool IncludePop3Tls { get; set; }

    /// <summary>Default HTTPS port for host-only targets.</summary>
    public int HttpsPort { get; set; } = 443;

    /// <summary>SMTP STARTTLS port.</summary>
    public int SmtpPort { get; set; } = 25;

    /// <summary>SMTP submission STARTTLS port.</summary>
    public int SubmissionPort { get; set; } = 587;

    /// <summary>IMAP TLS port.</summary>
    public int ImapPort { get; set; } = 993;

    /// <summary>POP3 TLS port.</summary>
    public int Pop3Port { get; set; } = 995;

    /// <summary>Maximum MX hosts retained per domain (0 means unlimited).</summary>
    public int MaxMxHostsPerDomain { get; set; } = 50;

    /// <summary>Maximum number of concurrent probe operations.</summary>
    public int MaxParallelism { get; set; } = 16;

    /// <summary>Maximum number of concurrent domain discovery operations.</summary>
    public int DiscoveryParallelism { get; set; } = 20;

    /// <summary>Timeout applied to mail TLS probes.</summary>
    public TimeSpan MailTimeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>Timeout applied to HTTPS certificate probes.</summary>
    public TimeSpan HttpsTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>When true, HTTPS probes also collect extended revocation, protocol, stapling, grade, and CT metadata.</summary>
    public bool CaptureExtendedHttpsMetadata { get; set; } = true;

    /// <summary>
    /// When true, HTTPS probes may use a certificate-only TLS handshake instead of a full HTTP request.
    /// This is intended for high-throughput monitoring lanes that only need certificate evidence.
    /// </summary>
    public bool PreferTlsHandshakeOnlyProbe { get; set; }

    /// <summary>Maximum total probe targets (HTTPS + mail) kept after discovery; 0 means unlimited.</summary>
    public int MaxTargets { get; set; }

    /// <summary>Maximum number of probe starts per second; 0 means unlimited.</summary>
    public int MaxProbeStartsPerSecond { get; set; }

    /// <summary>When true, reuses recent persisted snapshot endpoint results to avoid re-probing unchanged endpoints.</summary>
    public bool ReuseRecentSnapshotEntries { get; set; }

    /// <summary>Maximum age of persisted snapshots considered for endpoint reuse.</summary>
    public TimeSpan RecentSnapshotTtl { get; set; } = TimeSpan.FromHours(24);

    /// <summary>
    /// When true, reuses recent persisted snapshot entries for stable failure outcomes
    /// so hot verification lanes do not immediately re-probe the same dead or timeout-heavy
    /// endpoint on every pass.
    /// </summary>
    public bool ReuseRecentFailureSnapshotEntries { get; set; }

    /// <summary>Maximum age of persisted failure snapshots considered for stable-failure reuse.</summary>
    public TimeSpan RecentFailureSnapshotTtl { get; set; } = TimeSpan.FromHours(1);

    /// <summary>Do not reuse cached endpoint results when certificate expires within this many days.</summary>
    public int ReprobeExpiringWithinDays { get; set; } = 14;

    /// <summary>When true, skips revocation checks for HTTPS certificate analysis.</summary>
    public bool SkipRevocation { get; set; }

    /// <summary>Baseline CT enrichment profile for HTTPS probes.</summary>
    public CertificateCtEnrichmentProfile CtProfile { get; set; } = CertificateCtEnrichmentProfile.Default;

    /// <summary>
    /// When true, keeps the default crt.sh API template for certificate-fingerprint CT enrichment.
    /// The template is only used when <see cref="EnablePassiveCtFallback"/> is also enabled.
    /// </summary>
    public bool IncludeDefaultCtTemplate { get; set; } = true;

    /// <summary>Additional CT API templates to query. Templates should include a {0} fingerprint placeholder.</summary>
    public List<string> CtApiTemplates { get; } = new();

    /// <summary>When true, enables Censys CT source integration.</summary>
    public bool EnableCensysCtSource { get; set; }

    /// <summary>Censys API identifier.</summary>
    public string? CensysApiId { get; set; }

    /// <summary>Censys API secret.</summary>
    public string? CensysApiSecret { get; set; }

    /// <summary>Censys CT API URL template. Should contain a {0} fingerprint placeholder.</summary>
    public string? CensysCtApiUrlTemplate { get; set; }

    /// <summary>When true, enables Shodan CT source integration.</summary>
    public bool EnableShodanCtSource { get; set; }

    /// <summary>Shodan API key.</summary>
    public string? ShodanApiKey { get; set; }

    /// <summary>Shodan CT API URL template. Should contain {0} fingerprint and {1} API key placeholders.</summary>
    public string? ShodanCtApiUrlTemplate { get; set; }

    /// <summary>When true, persists a snapshot to inventory storage.</summary>
    public bool PersistSnapshot { get; set; } = true;

    /// <summary>
    /// Configures the capture for CT discovery only.
    /// This keeps the run focused on discovering names and CT-backed metadata without
    /// widening into HTTPS, MX, or mail probing in the same pass.
    /// </summary>
    public CertificateInventoryCaptureOptions ApplyCtDiscoveryOnlyProfile() {
        IncludeApexHttps = false;
        IncludeWwwHttps = false;
        IncludeCtDiscoveredSubdomains = true;
        VerifyCtDiscoveredSubdomains = false;
        PromoteCtDiscoveredSubdomainsToHttpsProbes = false;
        IncludeMxHosts = false;
        IncludeMxHttps = false;
        IncludeSmtpStartTls = false;
        IncludeSubmissionStartTls = false;
        IncludeImapTls = false;
        IncludePop3Tls = false;
        return this;
    }

    /// <summary>
    /// Configures the capture for exact-host CT evidence refresh.
    /// This keeps the run focused on apex or explicit host probes plus CT metadata hydration,
    /// without reopening broader CT discovery or MX/mail expansion.
    /// </summary>
    public CertificateInventoryCaptureOptions ApplyCtEvidenceRefreshProfile() {
        IncludeApexHttps = true;
        IncludeWwwHttps = false;
        IncludeCtDiscoveredSubdomains = false;
        VerifyCtDiscoveredSubdomains = false;
        PromoteCtDiscoveredSubdomainsToHttpsProbes = false;
        IncludeMxHosts = false;
        IncludeMxHttps = false;
        IncludeSmtpStartTls = false;
        IncludeSubmissionStartTls = false;
        IncludeImapTls = false;
        IncludePop3Tls = false;
        return this;
    }

    /// <summary>
    /// Additional endpoints to probe.
    /// Supported forms:
    /// - https://host[:port], http://host[:port]
    /// - smtp://host[:port], submission://host[:port], imap://host[:port], pop3://host[:port], imaps://host[:port], pop3s://host[:port]
    /// - host or host:port (treated as HTTPS).
    /// </summary>
    public List<string> AdditionalEndpoints { get; } = new();
}

/// <summary>
/// Result returned after a certificate inventory capture run.
/// </summary>
public sealed class CertificateInventoryCaptureResult {
    /// <summary>Timestamp of snapshot capture (UTC).</summary>
    public DateTimeOffset CapturedAtUtc { get; set; }

    /// <summary>Snapshot file path when persistence is enabled and succeeds.</summary>
    public string SnapshotPath { get; set; } = string.Empty;

    /// <summary>Input domains considered for discovery.</summary>
    public int DomainCount { get; set; }

    /// <summary>Discovered MX host count.</summary>
    public int MxHostCount { get; set; }

    /// <summary>HTTPS endpoint probe count.</summary>
    public int HttpsEndpointCount { get; set; }

    /// <summary>Mail endpoint probe count.</summary>
    public int MailEndpointCount { get; set; }

    /// <summary>Total snapshot entry count.</summary>
    public int EntryCount { get; set; }

    /// <summary>Total endpoints reused from recent snapshots.</summary>
    public int ReusedRecentEntryCount { get; set; }

    /// <summary>HTTPS endpoints reused from recent snapshots.</summary>
    public int ReusedRecentHttpsCount { get; set; }

    /// <summary>Mail endpoints reused from recent snapshots.</summary>
    public int ReusedRecentMailCount { get; set; }

    /// <summary>Total endpoints reused specifically because of stable recent failures.</summary>
    public int ReusedRecentFailureEntryCount { get; set; }

    /// <summary>HTTPS endpoints reused specifically because of stable recent failures.</summary>
    public int ReusedRecentFailureHttpsCount { get; set; }

    /// <summary>Mail endpoints reused specifically because of stable recent failures.</summary>
    public int ReusedRecentFailureMailCount { get; set; }

    /// <summary>HTTPS endpoints that required live probing in this run.</summary>
    public int ProbedHttpsCount { get; set; }

    /// <summary>Mail endpoints that required live probing in this run.</summary>
    public int ProbedMailCount { get; set; }

    /// <summary>CT-discovered subdomain count included for HTTPS probing.</summary>
    public int CtDiscoveredSubdomainCount { get; set; }

    /// <summary>CT-discovered subdomains promoted into HTTPS targets.</summary>
    public int CtPromotedHttpsCount { get; set; }

    /// <summary>CT-discovered subdomains retained for metadata/reporting but not promoted into HTTPS targets.</summary>
    public int CtSkippedHttpsPromotionCount { get; set; }

    /// <summary>CT-discovered subdomains skipped for HTTPS because DNS resolution was not confirmed or failed.</summary>
    public int CtSkippedUnresolvedHttpsPromotionCount { get; set; }

    /// <summary>CT-discovered subdomains skipped for HTTPS because they matched low-confidence historical-only variants.</summary>
    public int CtSkippedLowConfidenceHttpsPromotionCount { get; set; }

    /// <summary>CT-discovered subdomains that qualified for HTTPS but collapsed into an already-added target.</summary>
    public int CtSkippedDuplicateHttpsPromotionCount { get; set; }

    /// <summary>MX hosts promoted into HTTPS targets.</summary>
    public int MxPromotedHttpsCount { get; set; }

    /// <summary>Mail targets added from discovered MX hosts.</summary>
    public int MxPromotedMailCount { get; set; }

    /// <summary>MX lookup artifacts rejected during host normalization.</summary>
    public int MxInvalidArtifactCount { get; set; }

    /// <summary>Duplicate MX hosts collapsed during normalization.</summary>
    public int MxDuplicateHostCount { get; set; }

    /// <summary>MX hosts that qualified for HTTPS but collapsed into an already-added target.</summary>
    public int MxSkippedDuplicateHttpsPromotionCount { get; set; }

    /// <summary>HTTPS target count before applying MaxTargets capping.</summary>
    public int HttpsTargetCountBeforeLimit { get; set; }

    /// <summary>Mail target count before applying MaxTargets capping.</summary>
    public int MailTargetCountBeforeLimit { get; set; }

    /// <summary>HTTPS targets dropped by MaxTargets capping.</summary>
    public int HttpsTargetCountDroppedByLimit { get; set; }

    /// <summary>Mail targets dropped by MaxTargets capping.</summary>
    public int MailTargetCountDroppedByLimit { get; set; }

    /// <summary>Counts of final entries by target-origin tag. Entries with multiple origins contribute to each matching tag.</summary>
    public IReadOnlyDictionary<string, int> TargetOriginCounts { get; set; } =
        new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Counts of final entries by capture disposition.</summary>
    public IReadOnlyDictionary<string, int> CaptureDispositionCounts { get; set; } =
        new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Unique endpoint count (host+port).</summary>
    public int UniqueEndpointCount { get; set; }

    /// <summary>Entries with valid certificates.</summary>
    public int ValidCount { get; set; }

    /// <summary>Entries with expired certificates.</summary>
    public int ExpiredCount { get; set; }

    /// <summary>Entries where no certificate was retrieved.</summary>
    public int FailedCount { get; set; }

    /// <summary>Domains included in the run.</summary>
    public IReadOnlyList<string> Domains { get; set; } = Array.Empty<string>();

    /// <summary>Discovered MX hosts.</summary>
    public IReadOnlyList<string> MxHosts { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Owning source domains for each discovered MX host.
    /// This preserves which input domains resolved to third-party/provider MX hosts so downstream
    /// consumers can retain accurate current-state ownership for external mail endpoints.
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>> MxSourceDomainsByHost { get; set; } =
        new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);

    /// <summary>HTTPS endpoints probed in this run.</summary>
    public IReadOnlyList<string> HttpsEndpoints { get; set; } = Array.Empty<string>();

    /// <summary>CT-discovered subdomains included for HTTPS probing.</summary>
    public IReadOnlyList<string> CtDiscoveredSubdomains { get; set; } = Array.Empty<string>();

    /// <summary>CT-discovered subdomain records with CT first/last seen and latest observed certificate metadata.</summary>
    public IReadOnlyList<SubdomainDiscoveryEntry> CtDiscoveredSubdomainEntries { get; set; } = Array.Empty<SubdomainDiscoveryEntry>();

    /// <summary>Mail endpoints probed in this run.</summary>
    public IReadOnlyList<string> MailEndpoints { get; set; } = Array.Empty<string>();

    /// <summary>Non-fatal warnings captured during discovery/probing.</summary>
    public IReadOnlyList<string> Warnings { get; set; } = Array.Empty<string>();

    /// <summary>Native CT per-log diagnostics observed during CT subdomain discovery.</summary>
    public IReadOnlyList<string> NativeCtLogDiagnostics { get; set; } = Array.Empty<string>();

    /// <summary>Structured native CT per-log diagnostics observed during CT subdomain discovery.</summary>
    public IReadOnlyList<NativeCtLogDiagnosticEntry> NativeCtLogDiagnosticEntries { get; set; } = Array.Empty<NativeCtLogDiagnosticEntry>();

    /// <summary>Structured passive/public CT diagnostics observed during CT discovery and metadata backfill.</summary>
    public IReadOnlyList<PassiveCtDiagnosticEntry> PassiveCtDiagnosticEntries { get; set; } = Array.Empty<PassiveCtDiagnosticEntry>();

    /// <summary>Structured target-selection diagnostics for rejected and pruned targets.</summary>
    public IReadOnlyList<TargetDecisionDiagnosticEntry> TargetDecisionDiagnostics { get; set; } = Array.Empty<TargetDecisionDiagnosticEntry>();

    /// <summary>Grouped summary buckets for target-selection diagnostics.</summary>
    public IReadOnlyList<TargetDecisionSummaryEntry> TargetDecisionSummary { get; set; } = Array.Empty<TargetDecisionSummaryEntry>();

    /// <summary>Captured snapshot object.</summary>
    public CertificateInventorySnapshot Snapshot { get; set; } = new();
}

/// <summary>
/// Captures certificate inventory snapshots from explicit domains and discovered service endpoints.
/// </summary>
public sealed partial class CertificateInventoryCapture {
    private static readonly Lazy<PublicSuffixList> EmbeddedPublicSuffixList = new(LoadPublicSuffixList);

    /// <summary>
    /// Restores persisted passive CT source cooldowns into the shared in-memory query state.
    /// Use this after loading diagnostics from a previous capture so a restarted process does not
    /// immediately hit sources that were recently rate-limited.
    /// </summary>
    /// <param name="diagnostics">Passive CT diagnostics containing source cooldown information.</param>
    public static void RestorePassiveCtSharedCooldownState(IEnumerable<PassiveCtDiagnosticEntry>? diagnostics) {
        PassiveCtSourceClient.RestoreSharedCooldownState(diagnostics);
    }

    private sealed class CertificateInventorySeed {
        public string Name { get; init; } = string.Empty;
        public string RegistrableDomain { get; init; } = string.Empty;
        public bool IsExactHostSeed { get; init; }
    }

    private sealed class MailEndpointTarget {
        public string Host { get; set; } = string.Empty;
        public int Port { get; set; }
        public MailTlsAnalysis.MailProtocol Protocol { get; set; }
        public string Service { get; set; } = string.Empty;
        public string Scheme { get; set; } = string.Empty;
        public string ChainSource { get; set; } = string.Empty;
        public List<string> TargetOrigins { get; set; } = new();
    }

    private sealed class ProbeStartRateLimiter {
        private readonly int _intervalMilliseconds;
        private readonly object _sync = new();
        private long _nextStartTimeUtcMilliseconds;

        public ProbeStartRateLimiter(int maxStartsPerSecond) {
            if (maxStartsPerSecond > 0) {
                _intervalMilliseconds = (int)Math.Ceiling(1000d / maxStartsPerSecond);
                if (_intervalMilliseconds < 1) {
                    _intervalMilliseconds = 1;
                }
            }
        }

        public async Task WaitAsync(CancellationToken cancellationToken) {
            if (_intervalMilliseconds <= 0) {
                return;
            }

            var delay = 0;
            lock (_sync) {
                var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                if (_nextStartTimeUtcMilliseconds <= now) {
                    _nextStartTimeUtcMilliseconds = now + _intervalMilliseconds;
                } else {
                    delay = (int)Math.Min(int.MaxValue, _nextStartTimeUtcMilliseconds - now);
                    _nextStartTimeUtcMilliseconds += _intervalMilliseconds;
                }
            }

            if (delay > 0) {
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    internal Func<string, DnsConfiguration, int, CancellationToken, Task<IReadOnlyList<string>>>? MxLookupOverride { get; set; }
    internal Func<IReadOnlyList<string>, CertificateInventoryCaptureOptions, InternalLogger?, CancellationToken, Task<IReadOnlyList<CertificateMonitor.Entry>>>? HttpsProbeOverride { get; set; }
    internal Func<IReadOnlyList<string>, CertificateInventoryCaptureOptions, InternalLogger?, CancellationToken, Task<IReadOnlyList<SubdomainDiscoveryEntry>>>? CtSubdomainEntryDiscoveryOverride { get; set; }
    internal Func<IReadOnlyList<string>, CertificateInventoryCaptureOptions, InternalLogger?, CancellationToken, Task<IReadOnlyList<string>>>? CtSubdomainDiscoveryOverride { get; set; }
    internal Func<IReadOnlyList<string>, CertificateInventoryCaptureOptions, InternalLogger?, CancellationToken, Task<IReadOnlyList<SubdomainDiscoveryEntry>>>? CtPassiveMetadataBackfillOverride { get; set; }
    internal Func<string, CancellationToken, Task<byte[]?>>? CtPassiveCertificateDownloadOverride { get; set; }
    internal Func<string, CertificateInventoryCaptureOptions, InternalLogger?, CancellationToken, Task<SubdomainDiscoveryEntry?>>? CtExactMetadataPostgreSqlOverride { get; set; }
    internal Func<CertificateInventorySnapshot, string, InternalLogger?, string>? PersistSnapshotOverride { get; set; }
    internal Func<CertificateInventoryCaptureOptions, DateTimeOffset, InternalLogger?, IReadOnlyDictionary<string, CertificateInventoryEntry>>? RecentSnapshotLookupOverride { get; set; }

    /// <summary>
    /// Captures one certificate inventory snapshot from the provided domains and discovery options.
    /// </summary>
    /// <param name="domains">Input domains for discovery.</param>
    /// <param name="options">Capture options.</param>
    /// <param name="logger">Optional logger instance.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Capture result with counts, warnings and the snapshot object.</returns>
    public async Task<CertificateInventoryCaptureResult> CaptureAsync(
        IEnumerable<string> domains,
        CertificateInventoryCaptureOptions options,
        InternalLogger? logger = null,
        CancellationToken cancellationToken = default) {
        if (domains == null) {
            throw new ArgumentNullException(nameof(domains));
        }
        if (options == null) {
            throw new ArgumentNullException(nameof(options));
        }
        if (options.HttpsPort < 1 || options.HttpsPort > 65535) {
            throw new ArgumentOutOfRangeException(nameof(options.HttpsPort), "HTTPS port must be between 1 and 65535.");
        }
        if (options.SmtpPort < 1 || options.SmtpPort > 65535) {
            throw new ArgumentOutOfRangeException(nameof(options.SmtpPort), "SMTP port must be between 1 and 65535.");
        }
        if (options.SubmissionPort < 1 || options.SubmissionPort > 65535) {
            throw new ArgumentOutOfRangeException(nameof(options.SubmissionPort), "Submission port must be between 1 and 65535.");
        }
        if (options.ImapPort < 1 || options.ImapPort > 65535) {
            throw new ArgumentOutOfRangeException(nameof(options.ImapPort), "IMAP port must be between 1 and 65535.");
        }
        if (options.Pop3Port < 1 || options.Pop3Port > 65535) {
            throw new ArgumentOutOfRangeException(nameof(options.Pop3Port), "POP3 port must be between 1 and 65535.");
        }
        if (options.HttpsTimeout <= TimeSpan.Zero || options.HttpsTimeout > TimeSpan.FromMinutes(10)) {
            throw new ArgumentOutOfRangeException(nameof(options.HttpsTimeout), "HttpsTimeout must be greater than zero and at most 10 minutes.");
        }
        if (options.MailTimeout <= TimeSpan.Zero || options.MailTimeout > TimeSpan.FromMinutes(10)) {
            throw new ArgumentOutOfRangeException(nameof(options.MailTimeout), "MailTimeout must be greater than zero and at most 10 minutes.");
        }
        if (options.MaxTargets < 0) {
            throw new ArgumentOutOfRangeException(nameof(options.MaxTargets), "MaxTargets must be 0 or greater.");
        }
        if (options.MaxProbeStartsPerSecond < 0) {
            throw new ArgumentOutOfRangeException(nameof(options.MaxProbeStartsPerSecond), "MaxProbeStartsPerSecond must be 0 or greater.");
        }
        if (options.RecentSnapshotTtl < TimeSpan.Zero) {
            throw new ArgumentOutOfRangeException(nameof(options.RecentSnapshotTtl), "RecentSnapshotTtl must be non-negative.");
        }
        if (options.RecentFailureSnapshotTtl < TimeSpan.Zero) {
            throw new ArgumentOutOfRangeException(nameof(options.RecentFailureSnapshotTtl), "RecentFailureSnapshotTtl must be non-negative.");
        }
        if (options.ReprobeExpiringWithinDays < 0) {
            throw new ArgumentOutOfRangeException(nameof(options.ReprobeExpiringWithinDays), "ReprobeExpiringWithinDays must be 0 or greater.");
        }
        if (options.MaxCtRowsPerDomain < 0) {
            throw new ArgumentOutOfRangeException(nameof(options.MaxCtRowsPerDomain), "MaxCtRowsPerDomain must be 0 or greater.");
        }
        if (options.MaxCtSubdomainsPerDomain < 0) {
            throw new ArgumentOutOfRangeException(nameof(options.MaxCtSubdomainsPerDomain), "MaxCtSubdomainsPerDomain must be 0 or greater.");
        }
        if (options.NativeCtSharedMaxRowsTotal < 0) {
            throw new ArgumentOutOfRangeException(nameof(options.NativeCtSharedMaxRowsTotal), "NativeCtSharedMaxRowsTotal must be 0 or greater.");
        }
        if (options.NativeCtSharedMaxSubdomainsTotal < 0) {
            throw new ArgumentOutOfRangeException(nameof(options.NativeCtSharedMaxSubdomainsTotal), "NativeCtSharedMaxSubdomainsTotal must be 0 or greater.");
        }
        if (options.NativeCtEntryBatchSize < 1 || options.NativeCtEntryBatchSize > 2048) {
            throw new ArgumentOutOfRangeException(nameof(options.NativeCtEntryBatchSize), "NativeCtEntryBatchSize must be between 1 and 2048.");
        }
        if (options.NativeCtInitialBackfillEntriesPerLog < 0) {
            throw new ArgumentOutOfRangeException(nameof(options.NativeCtInitialBackfillEntriesPerLog), "NativeCtInitialBackfillEntriesPerLog must be 0 or greater.");
        }
        if (options.NativeCtRequestDelay < TimeSpan.Zero) {
            throw new ArgumentOutOfRangeException(nameof(options.NativeCtRequestDelay), "NativeCtRequestDelay must be non-negative.");
        }
        if (options.NativeCtRequestTimeout <= TimeSpan.Zero || options.NativeCtRequestTimeout > TimeSpan.FromMinutes(5)) {
            throw new ArgumentOutOfRangeException(nameof(options.NativeCtRequestTimeout), "NativeCtRequestTimeout must be greater than zero and at most 5 minutes.");
        }
        if (options.NativeCtRetryCount < 0) {
            throw new ArgumentOutOfRangeException(nameof(options.NativeCtRetryCount), "NativeCtRetryCount must be 0 or greater.");
        }
        if (options.NativeCtRetryBaseDelay < TimeSpan.Zero) {
            throw new ArgumentOutOfRangeException(nameof(options.NativeCtRetryBaseDelay), "NativeCtRetryBaseDelay must be non-negative.");
        }
        if (options.NativeCtRetryMaxDelay < TimeSpan.Zero) {
            throw new ArgumentOutOfRangeException(nameof(options.NativeCtRetryMaxDelay), "NativeCtRetryMaxDelay must be non-negative.");
        }
        if (options.PassiveCtRequestTimeout < TimeSpan.Zero || options.PassiveCtRequestTimeout > TimeSpan.FromMinutes(5)) {
            throw new ArgumentOutOfRangeException(nameof(options.PassiveCtRequestTimeout), "PassiveCtRequestTimeout must be non-negative and at most 5 minutes.");
        }
        if (options.PassiveCtRetryCount < 0) {
            throw new ArgumentOutOfRangeException(nameof(options.PassiveCtRetryCount), "PassiveCtRetryCount must be 0 or greater.");
        }
        if (options.PassiveCtRetryBaseDelay < TimeSpan.Zero) {
            throw new ArgumentOutOfRangeException(nameof(options.PassiveCtRetryBaseDelay), "PassiveCtRetryBaseDelay must be non-negative.");
        }
        if (options.PassiveCtRetryMaxDelay < TimeSpan.Zero) {
            throw new ArgumentOutOfRangeException(nameof(options.PassiveCtRetryMaxDelay), "PassiveCtRetryMaxDelay must be non-negative.");
        }
        if (options.PassiveCtSourceCooldown < TimeSpan.Zero) {
            throw new ArgumentOutOfRangeException(nameof(options.PassiveCtSourceCooldown), "PassiveCtSourceCooldown must be non-negative.");
        }
        if (options.PassiveCtCrtShMinimumSpacing < TimeSpan.Zero) {
            throw new ArgumentOutOfRangeException(nameof(options.PassiveCtCrtShMinimumSpacing), "PassiveCtCrtShMinimumSpacing must be non-negative.");
        }
        if (options.PassiveCtCertSpotterMinimumSpacing < TimeSpan.Zero) {
            throw new ArgumentOutOfRangeException(nameof(options.PassiveCtCertSpotterMinimumSpacing), "PassiveCtCertSpotterMinimumSpacing must be non-negative.");
        }
        if (options.PassiveCtCrtShMaximumRequestsPerRun < 0) {
            throw new ArgumentOutOfRangeException(nameof(options.PassiveCtCrtShMaximumRequestsPerRun), "PassiveCtCrtShMaximumRequestsPerRun must be non-negative.");
        }
        if (options.PassiveCtCertSpotterMaximumRequestsPerRun < 0) {
            throw new ArgumentOutOfRangeException(nameof(options.PassiveCtCertSpotterMaximumRequestsPerRun), "PassiveCtCertSpotterMaximumRequestsPerRun must be non-negative.");
        }
        if (options.PassiveCtParallelism < 1) {
            throw new ArgumentOutOfRangeException(nameof(options.PassiveCtParallelism), "PassiveCtParallelism must be at least 1.");
        }
        if (options.NativeCtCircuitBreakerFailureThreshold < 1) {
            throw new ArgumentOutOfRangeException(nameof(options.NativeCtCircuitBreakerFailureThreshold), "NativeCtCircuitBreakerFailureThreshold must be 1 or greater.");
        }
        if (options.NativeCtCircuitBreakerDuration <= TimeSpan.Zero) {
            throw new ArgumentOutOfRangeException(nameof(options.NativeCtCircuitBreakerDuration), "NativeCtCircuitBreakerDuration must be greater than zero.");
        }
        if (options.NativeCtCatchUpLagThreshold < 1) {
            throw new ArgumentOutOfRangeException(nameof(options.NativeCtCatchUpLagThreshold), "NativeCtCatchUpLagThreshold must be 1 or greater.");
        }
        if (options.NativeCtCatchUpMaxEntriesPerLog < 0) {
            throw new ArgumentOutOfRangeException(nameof(options.NativeCtCatchUpMaxEntriesPerLog), "NativeCtCatchUpMaxEntriesPerLog must be 0 or greater.");
        }
        if (options.NativeCtCatchUpBatchSize < 1 || options.NativeCtCatchUpBatchSize > 2048) {
            throw new ArgumentOutOfRangeException(nameof(options.NativeCtCatchUpBatchSize), "NativeCtCatchUpBatchSize must be between 1 and 2048.");
        }

        logger ??= new InternalLogger(false);

        var warnings = new List<string>();
        var nativeCtLogDiagnostics = new List<string>();
        var nativeCtLogDiagnosticEntries = new List<NativeCtLogDiagnosticEntry>();
        var passiveCtDiagnosticEntries = new List<PassiveCtDiagnosticEntry>();
        var targetDecisionDiagnostics = new List<TargetDecisionDiagnosticEntry>();
        var ctDiscoveredSubdomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ctDiscoveredSubdomainEntries = new Dictionary<string, SubdomainDiscoveryEntry>(StringComparer.OrdinalIgnoreCase);
        const int totalStages = 9;
        var stage = 0;
        void AdvanceStage(string currentOperation) {
            stage++;
            logger.WriteProgress("CertificateInventoryCapture", currentOperation, stage * 100d / totalStages, stage, totalStages);
        }

        AppendCtConfigurationWarnings(options, warnings);
        var normalizedDomains = NormalizeDomains(domains, warnings);
        var seeds = BuildSeeds(normalizedDomains);
        var normalizedCtDiscoveryDomains = options.CtDiscoveryDomains.Count == 0
            ? normalizedDomains
            : NormalizeDomains(options.CtDiscoveryDomains, warnings);
        var ctDiscoverySeeds = BuildSeeds(normalizedCtDiscoveryDomains);
        logger.WriteVerbose("Certificate inventory capture started for {0} normalized domain(s).", normalizedDomains.Count);
        logger.WriteVerbose(
            "Seed classification: exactHostSeeds={0}, registrableDomainSeeds={1}.",
            seeds.Count(static seed => seed.IsExactHostSeed),
            seeds.Count(static seed => !seed.IsExactHostSeed));
        if (options.CtDiscoveryDomains.Count > 0) {
            logger.WriteVerbose(
                "CT discovery scope override selected {0} normalized domain(s) from {1} total seed(s).",
                normalizedCtDiscoveryDomains.Count,
                normalizedDomains.Count);
        }
        logger.WriteVerbose(
            "Capture settings: MaxParallelism={0}, DiscoveryParallelism={1}, PassiveCtParallelism={2}, MaxTargets={3}, MaxProbeStartsPerSecond={4}.",
            options.MaxParallelism,
            options.DiscoveryParallelism,
            options.PassiveCtParallelism,
            options.MaxTargets,
            options.MaxProbeStartsPerSecond);
        AdvanceStage("Domain normalization");

        var mxHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var mxByDomain = new ConcurrentDictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
        var httpsTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var httpsTargetOriginsByEndpointKey = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        var mailTargets = new Dictionary<string, MailEndpointTarget>(StringComparer.OrdinalIgnoreCase);
        var ctPromotedHttpsCount = 0;
        var ctSkippedHttpsPromotionCount = 0;
        var ctSkippedUnresolvedHttpsPromotionCount = 0;
        var ctSkippedLowConfidenceHttpsPromotionCount = 0;
        var ctSkippedDuplicateHttpsPromotionCount = 0;
        var mxPromotedHttpsCount = 0;
        var mxPromotedMailCount = 0;
        var mxInvalidArtifactCount = 0;
        var mxDuplicateHostCount = 0;
        var mxSkippedDuplicateHttpsPromotionCount = 0;

        foreach (var seed in seeds) {
            cancellationToken.ThrowIfCancellationRequested();
            if (seed.IsExactHostSeed) {
                AddHttpsTarget(
                    httpsTargets,
                    httpsTargetOriginsByEndpointKey,
                    BuildHttpsUrl(seed.Name, options.HttpsPort),
                    TargetOriginSeedExactHost);
            } else if (options.IncludeApexHttps) {
                AddHttpsTarget(
                    httpsTargets,
                    httpsTargetOriginsByEndpointKey,
                    BuildHttpsUrl(seed.Name, options.HttpsPort),
                    TargetOriginSeedApex);
            }
            if (!seed.IsExactHostSeed && options.IncludeWwwHttps) {
                AddHttpsTarget(
                    httpsTargets,
                    httpsTargetOriginsByEndpointKey,
                    BuildHttpsUrl($"www.{seed.Name}", options.HttpsPort),
                    TargetOriginSeedWww);
            }
        }

        if (options.IncludeCtDiscoveredSubdomains && normalizedCtDiscoveryDomains.Count > 0) {
            IReadOnlyList<SubdomainDiscoveryEntry> discoveredSubdomains;
            if (CtSubdomainEntryDiscoveryOverride != null) {
                discoveredSubdomains = await CtSubdomainEntryDiscoveryOverride(normalizedCtDiscoveryDomains, options, logger, cancellationToken).ConfigureAwait(false);
            } else if (CtSubdomainDiscoveryOverride != null) {
                var overridden = await CtSubdomainDiscoveryOverride(normalizedCtDiscoveryDomains, options, logger, cancellationToken).ConfigureAwait(false);
                discoveredSubdomains = overridden
                    .Where(name => !string.IsNullOrWhiteSpace(name))
                    .Select(name => new SubdomainDiscoveryEntry {
                        Name = name.Trim(),
                        CtSources = new[] { "override" }
                    })
                    .ToList();
            } else {
                discoveredSubdomains = await DiscoverCtSubdomainsAsync(
                    ctDiscoverySeeds,
                    options,
                    warnings,
                    nativeCtLogDiagnostics,
                    nativeCtLogDiagnosticEntries,
                    passiveCtDiagnosticEntries,
                    logger,
                    cancellationToken).ConfigureAwait(false);
            }

            discoveredSubdomains = await BackfillMissingCtCertificateMetadataAsync(
                normalizedCtDiscoveryDomains,
                discoveredSubdomains,
                options,
                warnings,
                passiveCtDiagnosticEntries,
                logger,
                cancellationToken).ConfigureAwait(false);

            int skippedLowConfidenceCtProbeTargets = 0;
            foreach (var subdomain in discoveredSubdomains) {
                if (subdomain == null || string.IsNullOrWhiteSpace(subdomain.Name)) {
                    continue;
                }

                var normalizedSubdomain = subdomain.Name.Trim();
                ctDiscoveredSubdomains.Add(normalizedSubdomain);
                MergeCtSubdomainEntry(ctDiscoveredSubdomainEntries, subdomain);
                if (ShouldPromoteCtDiscoveredSubdomainToHttpsProbe(normalizedSubdomain, subdomain, options)) {
                    if (AddHttpsTarget(
                            httpsTargets,
                            httpsTargetOriginsByEndpointKey,
                            BuildHttpsUrl(normalizedSubdomain, options.HttpsPort),
                            TargetOriginCtDiscovery)) {
                        ctPromotedHttpsCount++;
                    } else {
                        ctSkippedHttpsPromotionCount++;
                        ctSkippedDuplicateHttpsPromotionCount++;
                    }
                } else if (!options.VerifyCtDiscoveredSubdomains &&
                           subdomain.ResolutionStatus == SubdomainResolutionStatus.Unknown &&
                           LooksLikeLowConfidenceCtOnlyProbeVariant(normalizedSubdomain)) {
                    skippedLowConfidenceCtProbeTargets++;
                    ctSkippedHttpsPromotionCount++;
                    ctSkippedLowConfidenceHttpsPromotionCount++;
                } else {
                    ctSkippedHttpsPromotionCount++;
                    if (subdomain.ResolutionStatus != SubdomainResolutionStatus.Resolves) {
                        ctSkippedUnresolvedHttpsPromotionCount++;
                    }
                }
            }

            if (skippedLowConfidenceCtProbeTargets > 0) {
                logger.WriteVerbose(
                    "CT discovery preserved {0} low-confidence historical-only candidate(s) without promoting them into HTTPS probes.",
                    skippedLowConfidenceCtProbeTargets);
            }

            logger.WriteVerbose("CT subdomain discovery returned {0} unique candidate(s).", ctDiscoveredSubdomains.Count);
        }

        IReadOnlyList<SubdomainDiscoveryEntry> exactHostSeedCtMetadata = await BackfillExactHostSeedCtMetadataAsync(
            seeds,
            ctDiscoveredSubdomainEntries,
            options,
            warnings,
            passiveCtDiagnosticEntries,
            logger,
            cancellationToken).ConfigureAwait(false);
        foreach (var exactEntry in exactHostSeedCtMetadata) {
            if (exactEntry == null || string.IsNullOrWhiteSpace(exactEntry.Name)) {
                continue;
            }

            var normalizedExactName = exactEntry.Name.Trim();
            ctDiscoveredSubdomains.Add(normalizedExactName);
            MergeCtSubdomainEntry(ctDiscoveredSubdomainEntries, exactEntry);
        }
        AdvanceStage("CT subdomain discovery");

        if (options.IncludeMxHosts || options.IncludeMxHttps) {
            var dnsConfiguration = new DnsConfiguration {
                DnsEndpoint = options.DnsEndpoint
            };
            var maxLookupParallelism = Math.Max(1, options.DiscoveryParallelism);
            var mxLookupSeeds = seeds
                .Where(static seed => !seed.IsExactHostSeed)
                .Select(static seed => seed.Name)
                .ToList();
            var totalLookups = mxLookupSeeds.Count;
            var completedLookups = 0;
            using var gate = new SemaphoreSlim(maxLookupParallelism, maxLookupParallelism);
            var tasks = new List<Task>(mxLookupSeeds.Count);
            foreach (var domain in mxLookupSeeds) {
                await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
                tasks.Add(Task.Run(async () => {
                    try {
                        logger.WriteVerbose("Resolving MX records for {0}.", domain);
                        IReadOnlyList<string> hosts;
                        if (MxLookupOverride != null) {
                            hosts = await MxLookupOverride(domain, dnsConfiguration, options.MaxMxHostsPerDomain, cancellationToken).ConfigureAwait(false);
                        } else {
                            hosts = await ResolveMxHostsAsync(domain, dnsConfiguration, options.MaxMxHostsPerDomain, cancellationToken).ConfigureAwait(false);
                        }
                        mxByDomain[domain] = hosts;
                        logger.WriteVerbose("Resolved {0} MX host(s) for {1}.", hosts.Count, domain);
                    } catch (Exception ex) {
                        lock (warnings) {
                            warnings.Add($"MX discovery failed for {domain}: {ex.Message}");
                        }
                    } finally {
                        var completed = Interlocked.Increment(ref completedLookups);
                        logger.WriteProgress(
                            "CertificateInventoryCapture.MxDiscovery",
                            domain,
                            totalLookups == 0 ? 100d : completed * 100d / totalLookups,
                            completed,
                            totalLookups);
                        gate.Release();
                    }
                }, cancellationToken));
            }
            await Task.WhenAll(tasks).ConfigureAwait(false);

            foreach (var kv in mxByDomain) {
                foreach (var host in kv.Value) {
                    if (TryNormalizeMxHostCandidate(host, out var normalizedHost)) {
                        if (!mxHosts.Add(normalizedHost)) {
                            mxDuplicateHostCount++;
                        }
                    } else {
                        mxInvalidArtifactCount++;
                    }
                }
            }
        }
        AdvanceStage("MX discovery");
        logger.WriteVerbose("Discovered {0} MX host(s).", mxHosts.Count);

        if (options.IncludeMxHttps) {
            foreach (var mxHost in mxHosts) {
                if (AddHttpsTarget(
                        httpsTargets,
                        httpsTargetOriginsByEndpointKey,
                        BuildHttpsUrl(mxHost, options.HttpsPort),
                        TargetOriginMxHttps)) {
                    mxPromotedHttpsCount++;
                } else {
                    mxSkippedDuplicateHttpsPromotionCount++;
                }
            }
        }

        foreach (var mxHost in mxHosts) {
            var mailCountBefore = mailTargets.Count;
            AddMailTargetsForHost(mxHost, options, mailTargets, TargetOriginMxMail);
            mxPromotedMailCount += mailTargets.Count - mailCountBefore;
        }

        ApplyAdditionalEndpoints(options, httpsTargets, httpsTargetOriginsByEndpointKey, mailTargets, warnings, targetDecisionDiagnostics);
        IReadOnlyDictionary<string, RecentInventoryEndpointEntry> recentByEndpoint =
            new Dictionary<string, RecentInventoryEndpointEntry>(StringComparer.OrdinalIgnoreCase);
        if (ShouldLoadRecentSnapshotEntries(options)) {
            var now = DateTimeOffset.UtcNow;
            if (RecentSnapshotLookupOverride != null) {
                recentByEndpoint = WrapRecentSnapshotEntries(RecentSnapshotLookupOverride(options, now, logger), now);
            } else {
                recentByEndpoint = LoadRecentSnapshotEntries(options, now);
            }
        }

        var cachedEntries = new List<CertificateInventoryEntry>();
        var reusedSuccessCandidates = new List<ReusedRecentSuccessCandidate>();
        var httpsTargetsToProbe = httpsTargets.ToList();
        var mailTargetsToProbe = mailTargets.Values.ToList();
        var reusedHttps = 0;
        var reusedMail = 0;
        var reusedStableFailureHttps = 0;
        var reusedStableFailureMail = 0;
        if (ShouldLoadRecentSnapshotEntries(options)) {
            var now = DateTimeOffset.UtcNow;

            if (recentByEndpoint.Count > 0) {
                var filteredHttps = new List<string>(httpsTargetsToProbe.Count);
                foreach (var target in httpsTargetsToProbe) {
                    if (TryBuildHttpsEndpointKey(target, out var key) &&
                        recentByEndpoint.TryGetValue(key, out var cached) &&
                        TryReuseCachedEntry(cached, now, options, out bool reusedStableFailure)) {
                        var trackedOrigins = GetTrackedOrigins(httpsTargetOriginsByEndpointKey, key);
                        ApplyEntryProvenance(
                            cached.Entry,
                            trackedOrigins,
                            reusedStableFailure ? CaptureDispositionReusedRecentStableFailure : CaptureDispositionReusedRecentSuccess,
                            replaceTargetOrigins: true);
                        if (reusedStableFailure) {
                            cachedEntries.Add(cached.Entry);
                            reusedHttps++;
                        } else {
                            reusedSuccessCandidates.Add(new ReusedRecentSuccessCandidate {
                                Kind = ReusedTargetKind.Https,
                                Target = target,
                                Service = "HTTPS",
                                Entry = cached.Entry,
                                Priority = ComputeCachedEntryPriority(cached.Entry, options.ReprobeExpiringWithinDays),
                                SortDays = ParseSortDays(cached.Entry),
                                TargetOrigins = trackedOrigins
                            });
                        }
                        if (reusedStableFailure) {
                            reusedStableFailureHttps++;
                        }
                    } else {
                        filteredHttps.Add(target);
                    }
                }
                httpsTargetsToProbe = filteredHttps;

                var filteredMail = new List<MailEndpointTarget>(mailTargetsToProbe.Count);
                foreach (var target in mailTargetsToProbe) {
                    var key = BuildEndpointKey(target.Host, target.Port, target.Service);
                    if (recentByEndpoint.TryGetValue(key, out var cached) &&
                        TryReuseCachedEntry(cached, now, options, out bool reusedStableFailure)) {
                        ApplyEntryProvenance(
                            cached.Entry,
                            target.TargetOrigins,
                            reusedStableFailure ? CaptureDispositionReusedRecentStableFailure : CaptureDispositionReusedRecentSuccess,
                            replaceTargetOrigins: true);
                        if (reusedStableFailure) {
                            cachedEntries.Add(cached.Entry);
                            reusedMail++;
                        } else {
                            reusedSuccessCandidates.Add(new ReusedRecentSuccessCandidate {
                                Kind = ReusedTargetKind.Mail,
                                Target = BuildMailTargetLabel(target),
                                Service = target.Service,
                                Entry = cached.Entry,
                                Priority = ComputeCachedEntryPriority(cached.Entry, options.ReprobeExpiringWithinDays),
                                SortDays = ParseSortDays(cached.Entry),
                                TargetOrigins = target.TargetOrigins,
                                MailTarget = target
                            });
                        }
                        if (reusedStableFailure) {
                            reusedStableFailureMail++;
                        }
                    } else {
                        filteredMail.Add(target);
                    }
                }
                mailTargetsToProbe = filteredMail;

                logger.WriteVerbose(
                    "Reused {0} cached endpoint result(s) from recent snapshots (HTTPS: {1}, Mail: {2}, StableFailureHTTPS: {3}, StableFailureMail: {4}).",
                    reusedHttps + reusedMail,
                    reusedHttps,
                    reusedMail,
                    reusedStableFailureHttps,
                    reusedStableFailureMail);
            }
        }

        httpsTargets.Clear();
        foreach (var target in httpsTargetsToProbe) {
            httpsTargets.Add(target);
        }
        PruneTrackedHttpsOrigins(httpsTargetOriginsByEndpointKey, httpsTargetsToProbe);

        mailTargets.Clear();
        foreach (var target in mailTargetsToProbe) {
            AddMailTarget(mailTargets, target);
        }

        var httpsTargetCountBeforeLimit = httpsTargets.Count;
        var mailTargetCountBeforeLimit = mailTargets.Count;
        ApplyTargetLimitIncludingReusedSuccesses(
            options,
            httpsTargets,
            httpsTargetOriginsByEndpointKey,
            mailTargets,
            cachedEntries,
            reusedSuccessCandidates,
            warnings,
            recentByEndpoint,
            options.ReprobeExpiringWithinDays,
            targetDecisionDiagnostics,
            ref reusedHttps,
            ref reusedMail);
        var httpsTargetCountDroppedByLimit = Math.Max(0, httpsTargetCountBeforeLimit - httpsTargets.Count);
        var mailTargetCountDroppedByLimit = Math.Max(0, mailTargetCountBeforeLimit - mailTargets.Count);
        httpsTargetsToProbe = httpsTargets.ToList();
        mailTargetsToProbe = mailTargets.Values.ToList();

        if (ShouldLoadRecentSnapshotEntries(options) && recentByEndpoint.Count > 0) {
            var now = DateTimeOffset.UtcNow;

            var filteredHttps = new List<string>(httpsTargetsToProbe.Count);
            foreach (var target in httpsTargetsToProbe) {
                if (TryBuildHttpsEndpointKey(target, out var key) &&
                    recentByEndpoint.TryGetValue(key, out var cached) &&
                    TryReuseCachedEntry(cached, now, options, out bool reusedStableFailure) &&
                    !reusedStableFailure) {
                    ApplyEntryProvenance(
                        cached.Entry,
                        GetTrackedOrigins(httpsTargetOriginsByEndpointKey, key),
                        CaptureDispositionReusedRecentSuccess,
                        replaceTargetOrigins: true);
                    cachedEntries.Add(cached.Entry);
                    reusedHttps++;
                } else {
                    filteredHttps.Add(target);
                }
            }
            httpsTargetsToProbe = filteredHttps;

            var filteredMail = new List<MailEndpointTarget>(mailTargetsToProbe.Count);
            foreach (var target in mailTargetsToProbe) {
                var key = BuildEndpointKey(target.Host, target.Port, target.Service);
                if (recentByEndpoint.TryGetValue(key, out var cached) &&
                    TryReuseCachedEntry(cached, now, options, out bool reusedStableFailure) &&
                    !reusedStableFailure) {
                    ApplyEntryProvenance(
                        cached.Entry,
                        target.TargetOrigins,
                        CaptureDispositionReusedRecentSuccess,
                        replaceTargetOrigins: true);
                    cachedEntries.Add(cached.Entry);
                    reusedMail++;
                } else {
                    filteredMail.Add(target);
                }
            }
            mailTargetsToProbe = filteredMail;

            logger.WriteVerbose(
                "Reused {0} cached endpoint result(s) from recent snapshots (HTTPS: {1}, Mail: {2}, StableFailureHTTPS: {3}, StableFailureMail: {4}).",
                reusedHttps + reusedMail,
                reusedHttps,
                reusedMail,
                reusedStableFailureHttps,
                reusedStableFailureMail);
        }

        AdvanceStage("Endpoint expansion");
        logger.WriteVerbose("Prepared {0} HTTPS target(s) and {1} mail target(s).", httpsTargets.Count, mailTargets.Count);
        AdvanceStage("Recent snapshot cache");

        IReadOnlyList<CertificateMonitor.Entry> httpsEntries;
        if (HttpsProbeOverride != null) {
            httpsEntries = await HttpsProbeOverride(httpsTargetsToProbe.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList(), options, logger, cancellationToken).ConfigureAwait(false);
        } else {
            httpsEntries = await ProbeHttpsAsync(httpsTargetsToProbe, options, logger, cancellationToken).ConfigureAwait(false);
        }
        AdvanceStage("HTTPS probing");
        logger.WriteVerbose("HTTPS probing produced {0} observation(s).", httpsEntries.Count);

        var mailEntries = await ProbeMailAsync(mailTargetsToProbe, options, logger, cancellationToken).ConfigureAwait(false);
        AdvanceStage("Mail TLS probing");
        logger.WriteVerbose("Mail TLS probing produced {0} observation(s).", mailEntries.Count);

        var allEntries = new List<CertificateInventoryEntry>(cachedEntries.Count + httpsEntries.Count + mailEntries.Count);
        allEntries.AddRange(cachedEntries);
        foreach (var httpsEntry in httpsEntries) {
            var inventoryEntry = CertificateMonitor.ToInventoryEntry(httpsEntry);
            ApplyEntryProvenance(
                inventoryEntry,
                GetTrackedOrigins(httpsTargetOriginsByEndpointKey, inventoryEntry),
                CaptureDispositionLiveProbe);
            allEntries.Add(inventoryEntry);
        }
        allEntries.AddRange(mailEntries);

        var deduped = DeduplicateEntries(allEntries);
        var capturedAtUtc = DateTimeOffset.UtcNow;
        EnrichEntriesWithCtSubdomainMetadata(deduped, ctDiscoveredSubdomainEntries, capturedAtUtc);
        var distinctPorts = deduped
            .Select(e => e.Port)
            .Where(port => port > 0)
            .Distinct()
            .OrderBy(port => port)
            .ToList();
        var targetDecisionSummary = BuildTargetDecisionSummary(targetDecisionDiagnostics);
        var snapshot = new CertificateInventorySnapshot {
            CapturedAtUtc = capturedAtUtc,
            Port = distinctPorts.Count == 1 ? distinctPorts[0] : 0,
            Entries = deduped,
            NativeCtLogDiagnostics = nativeCtLogDiagnosticEntries.Select(CloneNativeCtLogDiagnosticEntry).ToList(),
            NativeCtLogDiagnosticsRaw = nativeCtLogDiagnostics.ToList(),
            PassiveCtDiagnostics = passiveCtDiagnosticEntries.Select(ClonePassiveCtDiagnosticEntry).ToList(),
            TargetDecisionDiagnostics = targetDecisionDiagnostics.Select(CloneTargetDecisionDiagnosticEntry).ToList(),
            TargetDecisionSummary = targetDecisionSummary.Select(CloneTargetDecisionSummaryEntry).ToList()
        };
        AdvanceStage("Snapshot synthesis");

        var snapshotPath = string.Empty;
        if (options.PersistSnapshot) {
            if (PersistSnapshotOverride != null) {
                snapshotPath = PersistSnapshotOverride(snapshot, options.CacheDirectory, logger);
            } else {
                var monitor = new CertificateMonitor {
                    CacheDirectory = options.CacheDirectory,
                    PersistInventorySnapshots = false
                };
                snapshotPath = monitor.SaveInventorySnapshot(snapshot, logger);
            }
        }
        AdvanceStage("Snapshot persistence");

        var uniqueEndpoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var validCount = 0;
        var expiredCount = 0;
        var failedCount = 0;
        foreach (var entry in deduped) {
            var host = !string.IsNullOrWhiteSpace(entry.ResolvedHost) ? entry.ResolvedHost! : entry.Host;
            uniqueEndpoints.Add($"{host}:{entry.Port}");
            if (entry.Valid) {
                validCount++;
            }
            if (entry.Expired) {
                expiredCount++;
            }
            if (string.IsNullOrWhiteSpace(entry.CertificateThumbprint)) {
                failedCount++;
            }
        }

        var mxSourceDomainsByHost = BuildMxSourceDomainsByHost(mxByDomain);

        return new CertificateInventoryCaptureResult {
            CapturedAtUtc = capturedAtUtc,
            SnapshotPath = snapshotPath,
            DomainCount = normalizedDomains.Count,
            MxHostCount = mxHosts.Count,
            HttpsEndpointCount = httpsTargets.Count,
            MailEndpointCount = mailTargets.Count,
            EntryCount = deduped.Count,
            ReusedRecentEntryCount = reusedHttps + reusedMail,
            ReusedRecentHttpsCount = reusedHttps,
            ReusedRecentMailCount = reusedMail,
            ReusedRecentFailureEntryCount = reusedStableFailureHttps + reusedStableFailureMail,
            ReusedRecentFailureHttpsCount = reusedStableFailureHttps,
            ReusedRecentFailureMailCount = reusedStableFailureMail,
            ProbedHttpsCount = httpsTargetsToProbe.Count,
            ProbedMailCount = mailTargetsToProbe.Count,
            CtDiscoveredSubdomainCount = ctDiscoveredSubdomains.Count,
            CtPromotedHttpsCount = ctPromotedHttpsCount,
            CtSkippedHttpsPromotionCount = ctSkippedHttpsPromotionCount,
            CtSkippedUnresolvedHttpsPromotionCount = ctSkippedUnresolvedHttpsPromotionCount,
            CtSkippedLowConfidenceHttpsPromotionCount = ctSkippedLowConfidenceHttpsPromotionCount,
            CtSkippedDuplicateHttpsPromotionCount = ctSkippedDuplicateHttpsPromotionCount,
            MxPromotedHttpsCount = mxPromotedHttpsCount,
            MxPromotedMailCount = mxPromotedMailCount,
            MxInvalidArtifactCount = mxInvalidArtifactCount,
            MxDuplicateHostCount = mxDuplicateHostCount,
            MxSkippedDuplicateHttpsPromotionCount = mxSkippedDuplicateHttpsPromotionCount,
            HttpsTargetCountBeforeLimit = httpsTargetCountBeforeLimit,
            MailTargetCountBeforeLimit = mailTargetCountBeforeLimit,
            HttpsTargetCountDroppedByLimit = httpsTargetCountDroppedByLimit,
            MailTargetCountDroppedByLimit = mailTargetCountDroppedByLimit,
            TargetOriginCounts = BuildTargetOriginCounts(deduped),
            CaptureDispositionCounts = BuildCaptureDispositionCounts(deduped),
            UniqueEndpointCount = uniqueEndpoints.Count,
            ValidCount = validCount,
            ExpiredCount = expiredCount,
            FailedCount = failedCount,
            Domains = normalizedDomains,
            MxHosts = mxHosts.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList(),
            MxSourceDomainsByHost = mxSourceDomainsByHost,
            HttpsEndpoints = httpsTargets.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList(),
            CtDiscoveredSubdomains = ctDiscoveredSubdomains.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList(),
            CtDiscoveredSubdomainEntries = ctDiscoveredSubdomainEntries.Values
                .OrderBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
                .Select(CloneSubdomainEntry)
                .ToList(),
            MailEndpoints = mailTargets.Values
                .OrderBy(x => x.Host, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.Port)
                .Select(BuildMailTargetLabel)
                .ToList(),
            Warnings = warnings,
            NativeCtLogDiagnostics = nativeCtLogDiagnostics,
            NativeCtLogDiagnosticEntries = nativeCtLogDiagnosticEntries,
            PassiveCtDiagnosticEntries = passiveCtDiagnosticEntries,
            TargetDecisionDiagnostics = targetDecisionDiagnostics.Select(CloneTargetDecisionDiagnosticEntry).ToList(),
            TargetDecisionSummary = targetDecisionSummary.Select(CloneTargetDecisionSummaryEntry).ToList(),
            Snapshot = snapshot
        };
    }

    private static IReadOnlyDictionary<string, IReadOnlyList<string>> BuildMxSourceDomainsByHost(
        IReadOnlyDictionary<string, IReadOnlyList<string>> mxByDomain) {
        if (mxByDomain == null || mxByDomain.Count == 0) {
            return new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
        }

        var sourceDomainsByHost = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in mxByDomain) {
            var domain = (kv.Key ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(domain)) {
                continue;
            }

            foreach (var host in kv.Value ?? Array.Empty<string>()) {
                if (!TryNormalizeMxHostCandidate(host, out var normalizedHost)) {
                    continue;
                }

                if (!sourceDomainsByHost.TryGetValue(normalizedHost, out var sourceDomains)) {
                    sourceDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    sourceDomainsByHost[normalizedHost] = sourceDomains;
                }

                sourceDomains.Add(domain);
            }
        }

        return sourceDomainsByHost.ToDictionary(
            static kv => kv.Key,
            static kv => (IReadOnlyList<string>)kv.Value
                .OrderBy(static domain => domain, StringComparer.OrdinalIgnoreCase)
                .ToList(),
            StringComparer.OrdinalIgnoreCase);
    }

    private static List<string> NormalizeDomains(IEnumerable<string> domains, List<string> warnings) {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rawDomain in domains) {
            if (string.IsNullOrWhiteSpace(rawDomain)) {
                continue;
            }
            var candidate = rawDomain.Trim();
            if (candidate.IndexOf("://", StringComparison.Ordinal) >= 0 && Uri.TryCreate(candidate, UriKind.Absolute, out var uri)) {
                candidate = uri.Host;
            }
            candidate = candidate.Trim().Trim('.');
            if (string.IsNullOrWhiteSpace(candidate)) {
                continue;
            }

            try {
                var normalized = DomainHelper.ValidateIdn(candidate);
                if (!string.IsNullOrWhiteSpace(normalized)) {
                    set.Add(normalized.TrimEnd('.'));
                }
            } catch (Exception ex) {
                warnings.Add($"Skipping invalid domain '{candidate}': {ex.Message}");
            }
        }
        return set.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static List<CertificateInventorySeed> BuildSeeds(IReadOnlyList<string> normalizedDomains) {
        if (normalizedDomains == null || normalizedDomains.Count == 0) {
            return new List<CertificateInventorySeed>();
        }

        var seeds = new List<CertificateInventorySeed>(normalizedDomains.Count);
        foreach (var normalizedDomain in normalizedDomains) {
            if (string.IsNullOrWhiteSpace(normalizedDomain)) {
                continue;
            }

            var registrableDomain = GetRegistrableDomainOrSelf(normalizedDomain);
            seeds.Add(new CertificateInventorySeed {
                Name = normalizedDomain,
                RegistrableDomain = registrableDomain,
                IsExactHostSeed = !string.Equals(registrableDomain, normalizedDomain, StringComparison.OrdinalIgnoreCase)
            });
        }

        return seeds;
    }

    private static string GetRegistrableDomainOrSelf(string candidate) {
        if (string.IsNullOrWhiteSpace(candidate)) {
            return candidate;
        }

        try {
            return EmbeddedPublicSuffixList.Value.GetRegistrableDomain(candidate);
        } catch {
            var labels = candidate.Split('.');
            if (labels.Length <= 2) {
                return candidate;
            }

            return string.Join(".", labels.Skip(labels.Length - 2));
        }
    }

    private static PublicSuffixList LoadPublicSuffixList() {
        try {
            using Stream? stream = typeof(CertificateInventoryCapture).Assembly
                .GetManifestResourceStream("DomainDetective.public_suffix_list.dat");
            if (stream != null) {
                return PublicSuffixList.Load(stream);
            }
        } catch {
            // Best-effort only; callers fall back to host-preserving heuristics.
        }

        return new PublicSuffixList();
    }

    private static string BuildHttpsUrl(string host, int defaultPort) {
        if (host.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            host.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) {
            if (Uri.TryCreate(host, UriKind.Absolute, out var existing)) {
                var builder = new UriBuilder(existing) {
                    Scheme = Uri.UriSchemeHttps,
                    Port = existing.IsDefaultPort ? defaultPort : existing.Port
                };
                return builder.Uri.ToString();
            }
        }

        var candidate = host;
        if (!candidate.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) {
            candidate = $"https://{candidate}";
        }
        var parsed = new UriBuilder(candidate) {
            Scheme = Uri.UriSchemeHttps
        };
        if (parsed.Port <= 0 || parsed.Port == 80) {
            parsed.Port = defaultPort;
        }
        return parsed.Uri.ToString();
    }

    private static bool ShouldPromoteCtDiscoveredSubdomainToHttpsProbe(
        string normalizedSubdomain,
        SubdomainDiscoveryEntry subdomain,
        CertificateInventoryCaptureOptions options) {
        if (subdomain == null) {
            return false;
        }

        if (!options.PromoteCtDiscoveredSubdomainsToHttpsProbes) {
            return false;
        }

        if (options.VerifyCtDiscoveredSubdomains) {
            return subdomain.ResolutionStatus == SubdomainResolutionStatus.Resolves;
        }

        if (subdomain.ResolutionStatus == SubdomainResolutionStatus.Resolves) {
            return true;
        }

        if (subdomain.ResolutionStatus != SubdomainResolutionStatus.Unknown) {
            return false;
        }

        return !LooksLikeLowConfidenceCtOnlyProbeVariant(normalizedSubdomain);
    }

    private static bool LooksLikeLowConfidenceCtOnlyProbeVariant(string? candidate) {
        if (string.IsNullOrWhiteSpace(candidate)) {
            return false;
        }

        string normalized = candidate!.Trim().TrimEnd('.');
        int separatorIndex = normalized.IndexOf('.');
        if (separatorIndex <= 0) {
            return false;
        }

        string firstLabel = normalized.Substring(0, separatorIndex);
        // CT noise commonly shows up as ww/w/wwww-prefixed variants. Keep those out of
        // opportunistic HTTPS probing when resolution is still unknown, but do not
        // suppress longer labels such as "wwwww" that may be intentionally named hosts.
        if (firstLabel.Length == 3 || firstLabel.Length > 4) {
            return false;
        }

        return firstLabel.All(static character => character == 'w' || character == 'W');
    }

    private static void AddMailTargetsForHost(
        string host,
        CertificateInventoryCaptureOptions options,
        Dictionary<string, MailEndpointTarget> targets,
        params string[] targetOrigins) {
        List<string> normalizedTargetOrigins = targetOrigins
            .Where(static origin => !string.IsNullOrWhiteSpace(origin))
            .Select(static origin => origin.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (options.IncludeSmtpStartTls) {
            AddMailTarget(targets, new MailEndpointTarget {
                Host = host,
                Port = options.SmtpPort,
                Protocol = MailTlsAnalysis.MailProtocol.Smtp,
                Service = "SMTP-STARTTLS",
                Scheme = "smtp",
                ChainSource = "mailtls-starttls",
                TargetOrigins = normalizedTargetOrigins
            });
        }
        if (options.IncludeSubmissionStartTls) {
            AddMailTarget(targets, new MailEndpointTarget {
                Host = host,
                Port = options.SubmissionPort,
                Protocol = MailTlsAnalysis.MailProtocol.Smtp,
                Service = "SMTP-SUBMISSION-STARTTLS",
                Scheme = "submission",
                ChainSource = "mailtls-starttls",
                TargetOrigins = normalizedTargetOrigins
            });
        }
        if (options.IncludeImapTls) {
            AddMailTarget(targets, new MailEndpointTarget {
                Host = host,
                Port = options.ImapPort,
                Protocol = MailTlsAnalysis.MailProtocol.Imap,
                Service = "IMAPS",
                Scheme = "imaps",
                ChainSource = "mailtls-directtls",
                TargetOrigins = normalizedTargetOrigins
            });
        }
        if (options.IncludePop3Tls) {
            AddMailTarget(targets, new MailEndpointTarget {
                Host = host,
                Port = options.Pop3Port,
                Protocol = MailTlsAnalysis.MailProtocol.Pop3,
                Service = "POP3S",
                Scheme = "pop3s",
                ChainSource = "mailtls-directtls",
                TargetOrigins = normalizedTargetOrigins
            });
        }
    }

    private static void AddMailTarget(Dictionary<string, MailEndpointTarget> targets, MailEndpointTarget target) {
        var key = BuildMailTargetKey(target.Host, target.Port, target.Service);
        if (!targets.TryGetValue(key, out MailEndpointTarget? existing)) {
            targets[key] = target;
            return;
        }

        existing.TargetOrigins = MergeDistinctStrings(existing.TargetOrigins, target.TargetOrigins).ToList();
    }

    private static string BuildMailTargetKey(string host, int port, string service) {
        return $"{host.Trim().ToLowerInvariant()}|{port}|{service.Trim().ToUpperInvariant()}";
    }

}

internal static class CertificateInventoryCmdletPathDefaults {
    internal static string DefaultCacheDirectory => System.IO.Path.Combine(System.IO.Path.GetTempPath(), "DomainDetective", "cert-monitor");
}
