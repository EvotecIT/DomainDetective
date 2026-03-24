using DnsClientX;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Management.Automation;
using System.Threading;

namespace DomainDetective.PowerShell;

/// <summary>Captures and optionally persists a certificate inventory snapshot from domains and discovered endpoints.</summary>
/// <para>Discovers HTTPS and mail TLS endpoints (for example MX-derived STARTTLS) and stores normalized certificate evidence in the inventory snapshot format used by certificate inventory analytics cmdlets.</para>
/// <example>
///   <summary>Capture snapshot for explicit domains</summary>
///   <code>Invoke-DDCertificateInventory -DomainName evotec.xyz,evotec.pl -CacheDirectory .\cert-monitor</code>
/// </example>
/// <example>
///   <summary>Capture snapshot from file and export captured entries</summary>
///   <code>Invoke-DDCertificateInventory -DomainsFile .\domains.txt -Endpoint https://api.example.com:8443</code>
/// </example>
/// <example>
///   <summary>Capture snapshot with extended CT enrichment</summary>
///   <code>Invoke-DDCertificateInventory -DomainName example.com -CtProfile Extended -EnableShodanCtSource -ShodanApiKeyEnv SHODAN_API_KEY</code>
/// </example>
/// <example>
///   <summary>Capture snapshot including CT-discovered subdomains</summary>
///   <code>Invoke-DDCertificateInventory -DomainName eurofins.com -IncludeCtSubdomains -VerifyCtSubdomains -MaxCtSubdomainsPerDomain 5000 -Verbose</code>
/// </example>
/// <example>
///   <summary>Use native CT log polling without crt.sh fallback</summary>
///   <code>Invoke-DDCertificateInventory -DomainName eurofins.com -IncludeCtSubdomains -EnableNativeCtLogSubdomains -NativeCtLogOnly -NativeCtInitialBackfillEntriesPerLog 5000 -Verbose</code>
/// </example>
/// <example>
///   <summary>Run a throttled test capture</summary>
///   <code>Invoke-DDCertificateInventory -DomainName eurofins.com -IncludeCtSubdomains -Limit 150 -MaxProbeStartsPerSecond 20 -MaxProbeErrorWarnings 10 -Verbose</code>
/// </example>
/// <example>
///   <summary>Reuse recent captured endpoints to reduce repeated probing</summary>
///   <code>Invoke-DDCertificateInventory -DomainName eurofins.com -IncludeCtSubdomains -ReuseRecentResults -RecentResultTtlHours 24 -ReprobeExpiringWithinDays 14</code>
/// </example>
/// <example>
///   <summary>Reuse recent stable failures for short-lived verification lanes</summary>
///   <code>Invoke-DDCertificateInventory -DomainName eurofins.com -ReuseRecentFailureResults -RecentFailureResultTtlHours 1 -HttpsTimeoutSeconds 20</code>
/// </example>
[Cmdlet(VerbsLifecycle.Invoke, "DDCertificateInventory")]
[OutputType(typeof(CertificateInventoryCaptureResult))]
public sealed class CmdletInvokeCertificateInventory : PSCmdlet {
    private readonly List<string> _domains = new();

    /// <summary>Domain list to scan. Can be provided from pipeline.</summary>
    [Parameter(Mandatory = false, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string[] DomainName { get; set; } = Array.Empty<string>();

    /// <summary>Optional text file with domains/endpoints (one per line).</summary>
    [Parameter(Mandatory = false)]
    public string? DomainsFile { get; set; }

    /// <summary>Certificate monitor cache directory containing the inventory folder.</summary>
    [Parameter(Mandatory = false)]
    public string? CacheDirectory { get; set; }

    /// <summary>DNS endpoint used for MX discovery.</summary>
    [Parameter(Mandatory = false)]
    public DnsEndpoint DnsEndpoint { get; set; } = DnsEndpoint.System;

    /// <summary>Do not probe apex domains over HTTPS.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter NoApexHttps { get; set; }

    /// <summary>Do not probe www.&lt;domain&gt; over HTTPS.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter NoWwwHttps { get; set; }

    /// <summary>Enable HTTPS probing for discovered MX hosts.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter IncludeMxHttps { get; set; }

    /// <summary>Disable MX discovery from DNS.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter DisableMxDiscovery { get; set; }

    /// <summary>Disable SMTP STARTTLS probing on port 25.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter DisableSmtpStartTls { get; set; }

    /// <summary>Disable SMTP STARTTLS probing on submission port 587.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter DisableSubmissionStartTls { get; set; }

    /// <summary>Enable IMAP TLS probing on port 993.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter IncludeImapTls { get; set; }

    /// <summary>Enable POP3 TLS probing on port 995.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter IncludePop3Tls { get; set; }

    /// <summary>Discover CT-observed subdomains for each input domain and probe them over HTTPS.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter IncludeCtSubdomains { get; set; }

    /// <summary>When used with -IncludeCtSubdomains, only include CT subdomains that currently resolve in DNS.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter VerifyCtSubdomains { get; set; }

    /// <summary>Maximum CT rows processed per domain when CT subdomain discovery is enabled (0 means no explicit cap override).</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int MaxCtRowsPerDomain { get; set; } = 10000;

    /// <summary>Maximum CT subdomains retained per domain when CT subdomain discovery is enabled (0 means no explicit cap override).</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int MaxCtSubdomainsPerDomain { get; set; } = 2000;

    /// <summary>Enable native RFC6962 CT log polling for CT subdomain discovery.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter EnableNativeCtLogSubdomains { get; set; }

    /// <summary>Disable shared native CT ingestion pass across all domains (uses per-domain native CT discovery instead).</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter DisableNativeCtSharedIngestion { get; set; }

    /// <summary>Use only native CT log polling for CT subdomain discovery (skip crt.sh/Cert Spotter).</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter NativeCtLogOnly { get; set; }

    /// <summary>Enable passive/public CT fallback for CT subdomain discovery.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter EnablePassiveCtFallback { get; set; }

    /// <summary>Enable passive/public CT metadata rescue without broadly enabling passive CT discovery fallback.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter EnablePassiveCtMetadataFallback { get; set; }

    /// <summary>Native CT log list URL used to resolve CT logs.</summary>
    [Parameter(Mandatory = false)]
    public string NativeCtLogListUrl { get; set; } = "https://www.gstatic.com/ct/log_list/v3/log_list.json";

    /// <summary>Optional explicit CT log URL list for native CT polling.</summary>
    [Parameter(Mandatory = false)]
    public string[] NativeCtLogUrl { get; set; } = Array.Empty<string>();

    /// <summary>Maximum CT logs processed per domain when native CT polling is enabled.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int NativeCtMaxLogs { get; set; } = 12;

    /// <summary>Maximum CT entries processed per log per domain when native CT polling is enabled.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int NativeCtMaxEntriesPerLog { get; set; } = 2000;

    /// <summary>Maximum get-entries batch size when native CT polling is enabled.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(1, 2048)]
    public int NativeCtEntryBatchSize { get; set; } = 256;

    /// <summary>Initial per-log backfill when no native CT cursor exists (0 starts at current tree head).</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int NativeCtInitialBackfillEntriesPerLog { get; set; } = 2000;

    /// <summary>Optional native CT cursor state file path (defaults to inventory/ct-native-cursor.json under CacheDirectory).</summary>
    [Parameter(Mandatory = false)]
    public string? NativeCtCursorStatePath { get; set; }

    /// <summary>Include pending CT logs when using native CT log list ingestion.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter NativeCtIncludePendingLogs { get; set; }

    /// <summary>Optional delay in milliseconds between native CT requests.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, 60000)]
    public int NativeCtRequestDelayMilliseconds { get; set; } = 0;

    /// <summary>Maximum retry count for transient native CT HTTP failures.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, 20)]
    public int NativeCtRetryCount { get; set; } = 3;

    /// <summary>Base delay in milliseconds between native CT retry attempts.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, 60000)]
    public int NativeCtRetryBaseDelayMilliseconds { get; set; } = 500;

    /// <summary>Maximum delay in milliseconds between native CT retry attempts.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, 300000)]
    public int NativeCtRetryMaxDelayMilliseconds { get; set; } = 10000;

    /// <summary>Consecutive native CT failures required before opening the per-log circuit breaker.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(1, 100)]
    public int NativeCtCircuitBreakerFailureThreshold { get; set; } = 3;

    /// <summary>Native CT circuit-breaker open duration in seconds.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(1, 86400)]
    public int NativeCtCircuitBreakerDurationSeconds { get; set; } = 600;

    /// <summary>Disable native CT catch-up mode that expands limits when cursor lag is high.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter DisableNativeCtCatchUpMode { get; set; }

    /// <summary>Native CT cursor lag threshold that enables catch-up mode.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(1, int.MaxValue)]
    public int NativeCtCatchUpLagThreshold { get; set; } = 50000;

    /// <summary>Maximum CT entries processed per log while native CT catch-up mode is active.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int NativeCtCatchUpMaxEntriesPerLog { get; set; } = 20000;

    /// <summary>Maximum get-entries batch size while native CT catch-up mode is active.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(1, 2048)]
    public int NativeCtCatchUpBatchSize { get; set; } = 1024;

    /// <summary>Additional endpoint(s) to probe (supports https:// and mail schemes).</summary>
    [Parameter(Mandatory = false)]
    public string[] Endpoint { get; set; } = Array.Empty<string>();

    /// <summary>Maximum MX hosts retained per domain (0 means unlimited).</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int MaxMxHostsPerDomain { get; set; } = 50;

    /// <summary>Maximum concurrent probe operations.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(1, 512)]
    public int MaxParallelism { get; set; } = 16;

    /// <summary>Maximum concurrent domain discovery operations.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(1, 512)]
    public int DiscoveryParallelism { get; set; } = 20;

    /// <summary>Mail TLS timeout in seconds.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(1, 300)]
    public int MailTimeoutSeconds { get; set; } = 15;

    /// <summary>HTTPS certificate probe timeout in seconds.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(1, 300)]
    public int HttpsTimeoutSeconds { get; set; } = 30;

    /// <summary>Maximum number of detailed endpoint probe error warnings to emit (0 emits only a summary warning).</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, 10000)]
    public int MaxProbeErrorWarnings { get; set; } = 25;

    /// <summary>Maximum total probe targets (HTTPS + mail) kept after discovery; useful for quick test runs (0 means unlimited).</summary>
    [Parameter(Mandatory = false)]
    [Alias("Limit")]
    [ValidateRange(0, int.MaxValue)]
    public int MaxTargets { get; set; }

    /// <summary>Maximum number of probe starts per second (0 means unlimited).</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, 10000)]
    public int MaxProbeStartsPerSecond { get; set; }

    /// <summary>Reuse recent persisted endpoint results to avoid re-probing unchanged endpoints.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter ReuseRecentResults { get; set; }

    /// <summary>How old persisted snapshot entries can be to qualify for reuse.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, 24 * 365)]
    public int RecentResultTtlHours { get; set; } = 24;

    /// <summary>Reuse recent persisted stable failures to avoid immediately re-probing dead or timeout-heavy endpoints.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter ReuseRecentFailureResults { get; set; }

    /// <summary>How old persisted stable failure entries can be to qualify for reuse.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, 24 * 365)]
    public int RecentFailureResultTtlHours { get; set; } = 1;

    /// <summary>Always re-probe endpoints with certificates expiring within this many days.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, 3650)]
    public int ReprobeExpiringWithinDays { get; set; } = 14;

    /// <summary>Skip revocation checks for HTTPS probes.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter SkipRevocation { get; set; }

    /// <summary>CT enrichment profile. Values: Default, Disabled, Public, Extended.</summary>
    [Parameter(Mandatory = false)]
    public CertificateCtEnrichmentProfile CtProfile { get; set; } = CertificateCtEnrichmentProfile.Default;

    /// <summary>Disable the default crt.sh template during CT lookups.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter DisableDefaultCtTemplate { get; set; }

    /// <summary>Additional CT API templates (must include a {0} fingerprint placeholder).</summary>
    [Parameter(Mandatory = false)]
    public string[] CtApiTemplate { get; set; } = Array.Empty<string>();

    /// <summary>Enable Censys CT source.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter EnableCensysCtSource { get; set; }

    /// <summary>Censys API identifier.</summary>
    [Parameter(Mandatory = false)]
    public string? CensysApiId { get; set; }

    /// <summary>Censys API secret. Prefer CensysApiSecretEnv for safer automation.</summary>
    [Parameter(Mandatory = false)]
    public string? CensysApiSecret { get; set; }

    /// <summary>Environment variable name containing Censys API secret.</summary>
    [Parameter(Mandatory = false)]
    public string? CensysApiSecretEnv { get; set; }

    /// <summary>Censys CT API URL template containing a {0} fingerprint placeholder.</summary>
    [Parameter(Mandatory = false)]
    public string? CensysCtApiUrlTemplate { get; set; }

    /// <summary>Enable Shodan CT source.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter EnableShodanCtSource { get; set; }

    /// <summary>Shodan API key. Prefer ShodanApiKeyEnv for safer automation.</summary>
    [Parameter(Mandatory = false)]
    public string? ShodanApiKey { get; set; }

    /// <summary>Environment variable name containing Shodan API key.</summary>
    [Parameter(Mandatory = false)]
    public string? ShodanApiKeyEnv { get; set; }

    /// <summary>Shodan CT API URL template containing {0} fingerprint and {1} API key placeholders.</summary>
    [Parameter(Mandatory = false)]
    public string? ShodanCtApiUrlTemplate { get; set; }

    /// <summary>Do not persist snapshot file; only return in-memory result.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter NoPersist { get; set; }

    /// <summary>Collects pipeline domain inputs for later capture execution.</summary>
    protected override void ProcessRecord() {
        if (DomainName == null || DomainName.Length == 0) {
            return;
        }
        foreach (var value in DomainName) {
            if (string.IsNullOrWhiteSpace(value)) {
                continue;
            }
            _domains.Add(value.Trim());
        }
    }

    /// <summary>Performs endpoint discovery, certificate probing, and snapshot persistence.</summary>
    protected override void EndProcessing() {
        var domains = new List<string>(_domains);
        if (!string.IsNullOrWhiteSpace(DomainsFile)) {
            var fullPath = Path.GetFullPath(DomainsFile!);
            if (!File.Exists(fullPath)) {
                ThrowTerminatingError(new ErrorRecord(
                    new FileNotFoundException("Domains file was not found.", fullPath),
                    "DomainsFileNotFound",
                    ErrorCategory.ObjectNotFound,
                    DomainsFile));
                return;
            }

            foreach (var line in File.ReadAllLines(fullPath)) {
                var trimmed = line?.Trim() ?? string.Empty;
                if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith("#", StringComparison.Ordinal)) {
                    continue;
                }
                domains.Add(trimmed);
            }
        }

        if (domains.Count == 0) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("Provide at least one domain via -DomainName or -DomainsFile.", nameof(DomainName)),
                "NoDomainsProvided",
                ErrorCategory.InvalidArgument,
                DomainName));
            return;
        }

        var options = new CertificateInventoryCaptureOptions {
            CacheDirectory = CertificateInventoryCmdletHelpers.ResolveCacheDirectory(CacheDirectory),
            DnsEndpoint = DnsEndpoint,
            IncludeApexHttps = !NoApexHttps.IsPresent,
            IncludeWwwHttps = !NoWwwHttps.IsPresent,
            IncludeMxHosts = !DisableMxDiscovery.IsPresent,
            IncludeMxHttps = IncludeMxHttps.IsPresent,
            IncludeSmtpStartTls = !DisableSmtpStartTls.IsPresent,
            IncludeSubmissionStartTls = !DisableSubmissionStartTls.IsPresent,
            IncludeImapTls = IncludeImapTls.IsPresent,
            IncludePop3Tls = IncludePop3Tls.IsPresent,
            IncludeCtDiscoveredSubdomains = IncludeCtSubdomains.IsPresent,
            VerifyCtDiscoveredSubdomains = VerifyCtSubdomains.IsPresent,
            MaxCtRowsPerDomain = MaxCtRowsPerDomain,
            MaxCtSubdomainsPerDomain = MaxCtSubdomainsPerDomain,
            EnableNativeCtLogSubdomainSource = EnableNativeCtLogSubdomains.IsPresent,
            EnableNativeCtSharedIngestion = !DisableNativeCtSharedIngestion.IsPresent,
            NativeCtLogOnly = NativeCtLogOnly.IsPresent,
            EnablePassiveCtFallback = EnablePassiveCtFallback.IsPresent,
            EnablePassiveCtMetadataFallback = EnablePassiveCtMetadataFallback.IsPresent,
            NativeCtLogListUrl = NativeCtLogListUrl,
            NativeCtMaxLogs = NativeCtMaxLogs,
            NativeCtMaxEntriesPerLog = NativeCtMaxEntriesPerLog,
            NativeCtEntryBatchSize = NativeCtEntryBatchSize,
            NativeCtInitialBackfillEntriesPerLog = NativeCtInitialBackfillEntriesPerLog,
            NativeCtCursorStatePath = NativeCtCursorStatePath,
            NativeCtIncludePendingLogs = NativeCtIncludePendingLogs.IsPresent,
            NativeCtRequestDelay = TimeSpan.FromMilliseconds(NativeCtRequestDelayMilliseconds),
            NativeCtRetryCount = NativeCtRetryCount,
            NativeCtRetryBaseDelay = TimeSpan.FromMilliseconds(NativeCtRetryBaseDelayMilliseconds),
            NativeCtRetryMaxDelay = TimeSpan.FromMilliseconds(NativeCtRetryMaxDelayMilliseconds),
            NativeCtCircuitBreakerFailureThreshold = NativeCtCircuitBreakerFailureThreshold,
            NativeCtCircuitBreakerDuration = TimeSpan.FromSeconds(NativeCtCircuitBreakerDurationSeconds),
            NativeCtEnableCatchUpMode = !DisableNativeCtCatchUpMode.IsPresent,
            NativeCtCatchUpLagThreshold = NativeCtCatchUpLagThreshold,
            NativeCtCatchUpMaxEntriesPerLog = NativeCtCatchUpMaxEntriesPerLog,
            NativeCtCatchUpBatchSize = NativeCtCatchUpBatchSize,
            MaxMxHostsPerDomain = MaxMxHostsPerDomain,
            MaxParallelism = MaxParallelism,
            DiscoveryParallelism = DiscoveryParallelism,
            MailTimeout = TimeSpan.FromSeconds(MailTimeoutSeconds),
            HttpsTimeout = TimeSpan.FromSeconds(HttpsTimeoutSeconds),
            MaxTargets = MaxTargets,
            MaxProbeStartsPerSecond = MaxProbeStartsPerSecond,
            ReuseRecentSnapshotEntries = ReuseRecentResults.IsPresent,
            RecentSnapshotTtl = TimeSpan.FromHours(RecentResultTtlHours),
            ReuseRecentFailureSnapshotEntries = ReuseRecentFailureResults.IsPresent,
            RecentFailureSnapshotTtl = TimeSpan.FromHours(RecentFailureResultTtlHours),
            ReprobeExpiringWithinDays = ReprobeExpiringWithinDays,
            SkipRevocation = SkipRevocation.IsPresent,
            CtProfile = CtProfile,
            IncludeDefaultCtTemplate = !DisableDefaultCtTemplate.IsPresent,
            EnableCensysCtSource = EnableCensysCtSource.IsPresent,
            CensysApiId = CensysApiId,
            CensysApiSecret = ResolveSecret(CensysApiSecret, CensysApiSecretEnv),
            CensysCtApiUrlTemplate = CensysCtApiUrlTemplate,
            EnableShodanCtSource = EnableShodanCtSource.IsPresent,
            ShodanApiKey = ResolveSecret(ShodanApiKey, ShodanApiKeyEnv),
            ShodanCtApiUrlTemplate = ShodanCtApiUrlTemplate,
            PersistSnapshot = !NoPersist.IsPresent
        };
        if (Endpoint != null && Endpoint.Length > 0) {
            foreach (var endpoint in Endpoint) {
                if (!string.IsNullOrWhiteSpace(endpoint)) {
                    options.AdditionalEndpoints.Add(endpoint.Trim());
                }
            }
        }
        if (NativeCtLogUrl != null && NativeCtLogUrl.Length > 0) {
            foreach (var logUrl in NativeCtLogUrl) {
                if (!string.IsNullOrWhiteSpace(logUrl)) {
                    options.NativeCtLogUrls.Add(logUrl.Trim());
                }
            }
        }
        if (CtApiTemplate != null && CtApiTemplate.Length > 0) {
            foreach (var template in CtApiTemplate) {
                if (!string.IsNullOrWhiteSpace(template)) {
                    options.CtApiTemplates.Add(template.Trim());
                }
            }
        }

        var capture = new CertificateInventoryCapture();
        var logger = new InternalLogger(false);

        var verboseQueue = new ConcurrentQueue<string>();
        var warningQueue = new ConcurrentQueue<string>();
        var errorQueue = new ConcurrentQueue<string>();
        var progressQueue = new ConcurrentQueue<LogEventArgs>();
        var progressRecordIds = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var nextProgressRecordId = 1;
        var totalProbeErrors = 0;
        var emittedProbeErrorWarnings = 0;
        var suppressedProbeErrorWarnings = 0;

        try {

            logger.OnVerboseMessage += (_, e) => {
                if (!string.IsNullOrWhiteSpace(e.Message)) {
                    verboseQueue.Enqueue(e.Message);
                }
            };
            logger.OnWarningMessage += (_, e) => {
                if (!string.IsNullOrWhiteSpace(e.Message)) {
                    warningQueue.Enqueue(e.Message);
                }
            };
            logger.OnErrorMessage += (_, e) => {
                if (!string.IsNullOrWhiteSpace(e.Message)) {
                    errorQueue.Enqueue(e.Message);
                }
            };
            logger.OnProgressMessage += (_, e) => progressQueue.Enqueue(e);

            var task = capture.CaptureAsync(domains, options, logger);
            while (!task.IsCompleted) {
                FlushQueues(verboseQueue, warningQueue, errorQueue, progressQueue, false);
                Thread.Sleep(75);
            }

            FlushQueues(verboseQueue, warningQueue, errorQueue, progressQueue, false);
            var result = task.GetAwaiter().GetResult();
            FlushQueues(verboseQueue, warningQueue, errorQueue, progressQueue, true);
            WriteObject(result);
        } catch (Exception ex) {
            ThrowTerminatingError(new ErrorRecord(
                ex,
                "CertificateInventoryCaptureFailed",
                ErrorCategory.InvalidOperation,
                domains));
        }

        void FlushQueues(
            ConcurrentQueue<string> verboseQueueLocal,
            ConcurrentQueue<string> warningQueueLocal,
            ConcurrentQueue<string> errorQueueLocal,
            ConcurrentQueue<LogEventArgs> progressQueueLocal,
            bool finalPass) {
            while (verboseQueueLocal.TryDequeue(out var message)) {
                WriteVerbose(message);
            }

            while (warningQueueLocal.TryDequeue(out var warning)) {
                WriteWarning(warning);
            }

            while (errorQueueLocal.TryDequeue(out var error)) {
                totalProbeErrors++;
                var compact = CompactProbeError(error);
                if (emittedProbeErrorWarnings < MaxProbeErrorWarnings) {
                    emittedProbeErrorWarnings++;
                    WriteWarning($"[capture-error] {compact}");
                } else {
                    suppressedProbeErrorWarnings++;
                }
            }

            while (progressQueueLocal.TryDequeue(out var progress)) {
                var activity = string.IsNullOrWhiteSpace(progress.ProgressActivity)
                    ? "CertificateInventoryCapture"
                    : progress.ProgressActivity!;
                var operation = string.IsNullOrWhiteSpace(progress.ProgressCurrentOperation)
                    ? "Processing"
                    : progress.ProgressCurrentOperation!;

                int recordId;
                if (!progressRecordIds.TryGetValue(activity, out recordId)) {
                    recordId = nextProgressRecordId++;
                    progressRecordIds[activity] = recordId;
                }

                var record = new ProgressRecord(recordId, activity, operation);
                record.PercentComplete = progress.ProgressPercentage.GetValueOrDefault(0);
                if (record.PercentComplete >= 100) {
                    record.RecordType = ProgressRecordType.Completed;
                }
                WriteProgress(record);
            }

            if (finalPass && suppressedProbeErrorWarnings > 0) {
                WriteWarning($"[capture-error] {suppressedProbeErrorWarnings} additional endpoint probe error warning(s) were suppressed (total endpoint probe errors: {totalProbeErrors}).");
            }
        }
    }

    private static string CompactProbeError(string error) {
        if (string.IsNullOrWhiteSpace(error)) {
            return "Endpoint probe failed.";
        }

        var normalized = error.Replace('\r', ' ').Replace('\n', ' ').Trim();
        var stackIndex = normalized.IndexOf("   at ", StringComparison.Ordinal);
        if (stackIndex > 0) {
            normalized = normalized.Substring(0, stackIndex).Trim();
        }
        if (normalized.Length > 320) {
            normalized = normalized.Substring(0, 320).TrimEnd() + "...";
        }
        return normalized;
    }

    private static string? ResolveSecret(string? directValue, string? envVariableName) {
        if (!string.IsNullOrWhiteSpace(directValue)) {
            return directValue;
        }
        if (envVariableName == null) {
            return null;
        }
        var trimmedName = envVariableName.Trim();
        if (trimmedName.Length == 0) {
            return null;
        }
        return Environment.GetEnvironmentVariable(trimmedName);
    }
}
