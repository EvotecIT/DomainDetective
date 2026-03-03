using DnsClientX;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
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

    /// <summary>Maximum CT rows processed per domain while discovering CT subdomains (0 means no explicit cap override).</summary>
    public int MaxCtRowsPerDomain { get; set; } = 10_000;

    /// <summary>Maximum CT-discovered subdomains retained per domain (0 means no explicit cap override).</summary>
    public int MaxCtSubdomainsPerDomain { get; set; } = 2_000;

    /// <summary>When true, uses native RFC6962 CT log polling for subdomain discovery.</summary>
    public bool EnableNativeCtLogSubdomainSource { get; set; }

    /// <summary>When true (default), reuses one native CT ingestion pass across all domains in a capture run.</summary>
    public bool EnableNativeCtSharedIngestion { get; set; } = true;

    /// <summary>When true, uses only native CT log polling for subdomain discovery (skips crt.sh/Cert Spotter).</summary>
    public bool NativeCtLogOnly { get; set; }

    /// <summary>Native CT log list URL used to resolve trusted CT logs.</summary>
    public string NativeCtLogListUrl { get; set; } = "https://www.gstatic.com/ct/log_list/v3/log_list.json";

    /// <summary>Optional explicit CT log URLs for native subdomain discovery.</summary>
    public List<string> NativeCtLogUrls { get; } = new();

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

    /// <summary>Optional delay between native CT HTTP requests.</summary>
    public TimeSpan NativeCtRequestDelay { get; set; } = TimeSpan.Zero;

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

    /// <summary>Maximum total probe targets (HTTPS + mail) kept after discovery; 0 means unlimited.</summary>
    public int MaxTargets { get; set; }

    /// <summary>Maximum number of probe starts per second; 0 means unlimited.</summary>
    public int MaxProbeStartsPerSecond { get; set; }

    /// <summary>When true, reuses recent persisted snapshot endpoint results to avoid re-probing unchanged endpoints.</summary>
    public bool ReuseRecentSnapshotEntries { get; set; }

    /// <summary>Maximum age of persisted snapshots considered for endpoint reuse.</summary>
    public TimeSpan RecentSnapshotTtl { get; set; } = TimeSpan.FromHours(24);

    /// <summary>Do not reuse cached endpoint results when certificate expires within this many days.</summary>
    public int ReprobeExpiringWithinDays { get; set; } = 14;

    /// <summary>When true, skips revocation checks for HTTPS certificate analysis.</summary>
    public bool SkipRevocation { get; set; }

    /// <summary>Baseline CT enrichment profile for HTTPS probes.</summary>
    public CertificateCtEnrichmentProfile CtProfile { get; set; } = CertificateCtEnrichmentProfile.Default;

    /// <summary>When true, keeps the default crt.sh API template in CT discovery.</summary>
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

    /// <summary>CT-discovered subdomain count included for HTTPS probing.</summary>
    public int CtDiscoveredSubdomainCount { get; set; }

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

    /// <summary>HTTPS endpoints probed in this run.</summary>
    public IReadOnlyList<string> HttpsEndpoints { get; set; } = Array.Empty<string>();

    /// <summary>CT-discovered subdomains included for HTTPS probing.</summary>
    public IReadOnlyList<string> CtDiscoveredSubdomains { get; set; } = Array.Empty<string>();

    /// <summary>Mail endpoints probed in this run.</summary>
    public IReadOnlyList<string> MailEndpoints { get; set; } = Array.Empty<string>();

    /// <summary>Non-fatal warnings captured during discovery/probing.</summary>
    public IReadOnlyList<string> Warnings { get; set; } = Array.Empty<string>();

    /// <summary>Captured snapshot object.</summary>
    public CertificateInventorySnapshot Snapshot { get; set; } = new();
}

/// <summary>
/// Captures certificate inventory snapshots from explicit domains and discovered service endpoints.
/// </summary>
public sealed class CertificateInventoryCapture {
    private sealed class MailEndpointTarget {
        public string Host { get; set; } = string.Empty;
        public int Port { get; set; }
        public MailTlsAnalysis.MailProtocol Protocol { get; set; }
        public string Service { get; set; } = string.Empty;
        public string Scheme { get; set; } = string.Empty;
        public string ChainSource { get; set; } = string.Empty;
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
    internal Func<IReadOnlyList<string>, CertificateInventoryCaptureOptions, InternalLogger?, CancellationToken, Task<IReadOnlyList<string>>>? CtSubdomainDiscoveryOverride { get; set; }
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
        if (options.MaxTargets < 0) {
            throw new ArgumentOutOfRangeException(nameof(options.MaxTargets), "MaxTargets must be 0 or greater.");
        }
        if (options.MaxProbeStartsPerSecond < 0) {
            throw new ArgumentOutOfRangeException(nameof(options.MaxProbeStartsPerSecond), "MaxProbeStartsPerSecond must be 0 or greater.");
        }
        if (options.RecentSnapshotTtl < TimeSpan.Zero) {
            throw new ArgumentOutOfRangeException(nameof(options.RecentSnapshotTtl), "RecentSnapshotTtl must be non-negative.");
        }
        if (options.ReprobeExpiringWithinDays < 0) {
            throw new ArgumentOutOfRangeException(nameof(options.ReprobeExpiringWithinDays), "ReprobeExpiringWithinDays must be 0 or greater.");
        }

        logger ??= new InternalLogger(false);

        var warnings = new List<string>();
        var ctDiscoveredSubdomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        const int totalStages = 9;
        var stage = 0;
        void AdvanceStage(string currentOperation) {
            stage++;
            logger.WriteProgress("CertificateInventoryCapture", currentOperation, stage * 100d / totalStages, stage, totalStages);
        }

        AppendCtConfigurationWarnings(options, warnings);
        var normalizedDomains = NormalizeDomains(domains, warnings);
        logger.WriteVerbose("Certificate inventory capture started for {0} normalized domain(s).", normalizedDomains.Count);
        logger.WriteVerbose("Capture settings: MaxParallelism={0}, DiscoveryParallelism={1}, MaxTargets={2}, MaxProbeStartsPerSecond={3}.", options.MaxParallelism, options.DiscoveryParallelism, options.MaxTargets, options.MaxProbeStartsPerSecond);
        AdvanceStage("Domain normalization");

        var mxHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var httpsTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var mailTargets = new Dictionary<string, MailEndpointTarget>(StringComparer.OrdinalIgnoreCase);

        foreach (var domain in normalizedDomains) {
            cancellationToken.ThrowIfCancellationRequested();
            if (options.IncludeApexHttps) {
                httpsTargets.Add(BuildHttpsUrl(domain, options.HttpsPort));
            }
            if (options.IncludeWwwHttps) {
                httpsTargets.Add(BuildHttpsUrl($"www.{domain}", options.HttpsPort));
            }
        }

        if (options.IncludeCtDiscoveredSubdomains && normalizedDomains.Count > 0) {
            IReadOnlyList<string> discoveredSubdomains;
            if (CtSubdomainDiscoveryOverride != null) {
                discoveredSubdomains = await CtSubdomainDiscoveryOverride(normalizedDomains, options, logger, cancellationToken).ConfigureAwait(false);
            } else {
                discoveredSubdomains = await DiscoverCtSubdomainsAsync(normalizedDomains, options, warnings, logger, cancellationToken).ConfigureAwait(false);
            }

            foreach (var subdomain in discoveredSubdomains) {
                if (!string.IsNullOrWhiteSpace(subdomain)) {
                    ctDiscoveredSubdomains.Add(subdomain);
                    httpsTargets.Add(BuildHttpsUrl(subdomain, options.HttpsPort));
                }
            }

            logger.WriteVerbose("CT subdomain discovery returned {0} unique candidate(s).", ctDiscoveredSubdomains.Count);
        }
        AdvanceStage("CT subdomain discovery");

        if (options.IncludeMxHosts || options.IncludeMxHttps) {
            var dnsConfiguration = new DnsConfiguration {
                DnsEndpoint = options.DnsEndpoint
            };
            var maxLookupParallelism = Math.Max(1, options.DiscoveryParallelism);
            var totalLookups = normalizedDomains.Count;
            var completedLookups = 0;
            using var gate = new SemaphoreSlim(maxLookupParallelism, maxLookupParallelism);
            var tasks = new List<Task>(normalizedDomains.Count);
            var mxByDomain = new ConcurrentDictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var domain in normalizedDomains) {
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
                    if (!string.IsNullOrWhiteSpace(host)) {
                        mxHosts.Add(host);
                    }
                }
            }
        }
        AdvanceStage("MX discovery");
        logger.WriteVerbose("Discovered {0} MX host(s).", mxHosts.Count);

        if (options.IncludeMxHttps) {
            foreach (var mxHost in mxHosts) {
                httpsTargets.Add(BuildHttpsUrl(mxHost, options.HttpsPort));
            }
        }

        foreach (var mxHost in mxHosts) {
            AddMailTargetsForHost(mxHost, options, mailTargets);
        }

        ApplyAdditionalEndpoints(options, httpsTargets, mailTargets, warnings);
        ApplyTargetLimit(options, httpsTargets, mailTargets, warnings);
        AdvanceStage("Endpoint expansion");
        logger.WriteVerbose("Prepared {0} HTTPS target(s) and {1} mail target(s).", httpsTargets.Count, mailTargets.Count);

        var cachedEntries = new List<CertificateInventoryEntry>();
        var httpsTargetsToProbe = httpsTargets.ToList();
        var mailTargetsToProbe = mailTargets.Values.ToList();
        if (options.ReuseRecentSnapshotEntries && options.RecentSnapshotTtl > TimeSpan.Zero) {
            var now = DateTimeOffset.UtcNow;
            IReadOnlyDictionary<string, CertificateInventoryEntry> recentByEndpoint;
            if (RecentSnapshotLookupOverride != null) {
                recentByEndpoint = RecentSnapshotLookupOverride(options, now, logger);
            } else {
                recentByEndpoint = LoadRecentSnapshotEntries(options, now);
            }

            if (recentByEndpoint.Count > 0) {
                var reusedHttps = 0;
                var reusedMail = 0;

                var filteredHttps = new List<string>(httpsTargetsToProbe.Count);
                foreach (var target in httpsTargetsToProbe) {
                    if (TryBuildHttpsEndpointKey(target, out var key) &&
                        recentByEndpoint.TryGetValue(key, out var cached) &&
                        ShouldReuseCachedEntry(cached, now, options.ReprobeExpiringWithinDays)) {
                        cachedEntries.Add(cached);
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
                        ShouldReuseCachedEntry(cached, now, options.ReprobeExpiringWithinDays)) {
                        cachedEntries.Add(cached);
                        reusedMail++;
                    } else {
                        filteredMail.Add(target);
                    }
                }
                mailTargetsToProbe = filteredMail;

                logger.WriteVerbose("Reused {0} cached endpoint result(s) from recent snapshots (HTTPS: {1}, Mail: {2}).", reusedHttps + reusedMail, reusedHttps, reusedMail);
            }
        }
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
            allEntries.Add(CertificateMonitor.ToInventoryEntry(httpsEntry));
        }
        allEntries.AddRange(mailEntries);

        var deduped = DeduplicateEntries(allEntries);
        var capturedAtUtc = DateTimeOffset.UtcNow;
        var distinctPorts = deduped
            .Select(e => e.Port)
            .Where(port => port > 0)
            .Distinct()
            .OrderBy(port => port)
            .ToList();
        var snapshot = new CertificateInventorySnapshot {
            CapturedAtUtc = capturedAtUtc,
            Port = distinctPorts.Count == 1 ? distinctPorts[0] : 0,
            Entries = deduped
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

        return new CertificateInventoryCaptureResult {
            CapturedAtUtc = capturedAtUtc,
            SnapshotPath = snapshotPath,
            DomainCount = normalizedDomains.Count,
            MxHostCount = mxHosts.Count,
            HttpsEndpointCount = httpsTargets.Count,
            MailEndpointCount = mailTargets.Count,
            EntryCount = deduped.Count,
            CtDiscoveredSubdomainCount = ctDiscoveredSubdomains.Count,
            UniqueEndpointCount = uniqueEndpoints.Count,
            ValidCount = validCount,
            ExpiredCount = expiredCount,
            FailedCount = failedCount,
            Domains = normalizedDomains,
            MxHosts = mxHosts.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList(),
            HttpsEndpoints = httpsTargets.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList(),
            CtDiscoveredSubdomains = ctDiscoveredSubdomains.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList(),
            MailEndpoints = mailTargets.Values
                .OrderBy(x => x.Host, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.Port)
                .Select(BuildMailTargetLabel)
                .ToList(),
            Warnings = warnings,
            Snapshot = snapshot
        };
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

    private static void AddMailTargetsForHost(string host, CertificateInventoryCaptureOptions options, Dictionary<string, MailEndpointTarget> targets) {
        if (options.IncludeSmtpStartTls) {
            AddMailTarget(targets, new MailEndpointTarget {
                Host = host,
                Port = options.SmtpPort,
                Protocol = MailTlsAnalysis.MailProtocol.Smtp,
                Service = "SMTP-STARTTLS",
                Scheme = "smtp",
                ChainSource = "mailtls-starttls"
            });
        }
        if (options.IncludeSubmissionStartTls) {
            AddMailTarget(targets, new MailEndpointTarget {
                Host = host,
                Port = options.SubmissionPort,
                Protocol = MailTlsAnalysis.MailProtocol.Smtp,
                Service = "SMTP-SUBMISSION-STARTTLS",
                Scheme = "submission",
                ChainSource = "mailtls-starttls"
            });
        }
        if (options.IncludeImapTls) {
            AddMailTarget(targets, new MailEndpointTarget {
                Host = host,
                Port = options.ImapPort,
                Protocol = MailTlsAnalysis.MailProtocol.Imap,
                Service = "IMAPS",
                Scheme = "imaps",
                ChainSource = "mailtls-directtls"
            });
        }
        if (options.IncludePop3Tls) {
            AddMailTarget(targets, new MailEndpointTarget {
                Host = host,
                Port = options.Pop3Port,
                Protocol = MailTlsAnalysis.MailProtocol.Pop3,
                Service = "POP3S",
                Scheme = "pop3s",
                ChainSource = "mailtls-directtls"
            });
        }
    }

    private static void AddMailTarget(Dictionary<string, MailEndpointTarget> targets, MailEndpointTarget target) {
        var key = BuildMailTargetKey(target.Host, target.Port, target.Service);
        targets[key] = target;
    }

    private static string BuildMailTargetKey(string host, int port, string service) {
        return $"{host.Trim().ToLowerInvariant()}|{port}|{service.Trim().ToUpperInvariant()}";
    }

    private static string BuildMailTargetLabel(MailEndpointTarget target) {
        return $"{target.Scheme}://{target.Host}:{target.Port}";
    }

    private static string BuildEndpointKey(string host, int port, string service) {
        return $"{host.Trim().TrimEnd('.').ToLowerInvariant()}|{port}|{service.Trim().ToUpperInvariant()}";
    }

    private static bool TryBuildHttpsEndpointKey(string target, out string key) {
        key = string.Empty;
        if (string.IsNullOrWhiteSpace(target)) {
            return false;
        }

        if (!Uri.TryCreate(target, UriKind.Absolute, out var uri) || string.IsNullOrWhiteSpace(uri.Host)) {
            return false;
        }

        var port = uri.IsDefaultPort ? 443 : uri.Port;
        var service = CertificateServiceClassifier.GuessService(Uri.UriSchemeHttps, port);
        key = BuildEndpointKey(uri.Host, port, service);
        return true;
    }

    private static bool ShouldReuseCachedEntry(CertificateInventoryEntry entry, DateTimeOffset now, int reprobeExpiringWithinDays) {
        if (entry == null) {
            return false;
        }
        if (!entry.IsReachable) {
            return false;
        }
        if (string.IsNullOrWhiteSpace(entry.CertificateThumbprint)) {
            return false;
        }
        if (entry.Expired) {
            return false;
        }
        if (entry.NotAfterUtc.HasValue) {
            var cutoff = now.AddDays(Math.Max(0, reprobeExpiringWithinDays));
            var notAfter = entry.NotAfterUtc.Value;
            if (notAfter <= cutoff) {
                return false;
            }
        }
        return true;
    }

    private static IReadOnlyDictionary<string, CertificateInventoryEntry> LoadRecentSnapshotEntries(CertificateInventoryCaptureOptions options, DateTimeOffset now) {
        if (options == null || !options.ReuseRecentSnapshotEntries || options.RecentSnapshotTtl <= TimeSpan.Zero) {
            return new Dictionary<string, CertificateInventoryEntry>(StringComparer.OrdinalIgnoreCase);
        }

        using var monitor = new CertificateMonitor {
            CacheDirectory = options.CacheDirectory,
            PersistInventorySnapshots = false
        };

        var since = now - options.RecentSnapshotTtl;
        var snapshots = monitor.LoadInventorySnapshots(sinceUtc: since, latestOnly: false);
        if (snapshots.Count == 0) {
            return new Dictionary<string, CertificateInventoryEntry>(StringComparer.OrdinalIgnoreCase);
        }

        var ordered = snapshots.OrderBy(snapshot => snapshot.CapturedAtUtc).ToList();
        var byEndpoint = new Dictionary<string, CertificateInventoryEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var snapshot in ordered) {
            if (snapshot.Entries == null || snapshot.Entries.Count == 0) {
                continue;
            }
            foreach (var entry in snapshot.Entries) {
                if (entry == null) {
                    continue;
                }
                var host = !string.IsNullOrWhiteSpace(entry.ResolvedHost) ? entry.ResolvedHost! : entry.Host;
                if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(entry.Service) || entry.Port <= 0) {
                    continue;
                }
                var key = BuildEndpointKey(host, entry.Port, entry.Service);
                byEndpoint[key] = entry;
            }
        }

        return byEndpoint;
    }

    private static void ApplyTargetLimit(
        CertificateInventoryCaptureOptions options,
        HashSet<string> httpsTargets,
        Dictionary<string, MailEndpointTarget> mailTargets,
        List<string> warnings) {
        if (options.MaxTargets <= 0) {
            return;
        }

        var totalTargets = httpsTargets.Count + mailTargets.Count;
        if (totalTargets <= options.MaxTargets) {
            return;
        }

        var originalHttps = httpsTargets.Count;
        var originalMail = mailTargets.Count;
        var limit = options.MaxTargets;
        var allowedMail = Math.Min(originalMail, limit);
        var allowedHttps = Math.Max(0, limit - allowedMail);

        if (originalMail > allowedMail) {
            var keptMail = mailTargets.Values
                .OrderBy(target => target.Host, StringComparer.OrdinalIgnoreCase)
                .ThenBy(target => target.Port)
                .ThenBy(target => target.Service, StringComparer.OrdinalIgnoreCase)
                .Take(allowedMail)
                .ToList();

            mailTargets.Clear();
            foreach (var target in keptMail) {
                AddMailTarget(mailTargets, target);
            }
        }

        if (originalHttps > allowedHttps) {
            var keptHttps = httpsTargets
                .OrderBy(target => target, StringComparer.OrdinalIgnoreCase)
                .Take(allowedHttps)
                .ToList();

            httpsTargets.Clear();
            foreach (var target in keptHttps) {
                httpsTargets.Add(target);
            }
        }

        warnings.Add($"Probe target list capped from {totalTargets} to {options.MaxTargets} by MaxTargets (HTTPS: {originalHttps}->{httpsTargets.Count}, Mail: {originalMail}->{mailTargets.Count}).");
    }

    private static void ApplyAdditionalEndpoints(
        CertificateInventoryCaptureOptions options,
        HashSet<string> httpsTargets,
        Dictionary<string, MailEndpointTarget> mailTargets,
        List<string> warnings) {
        foreach (var raw in options.AdditionalEndpoints) {
            if (string.IsNullOrWhiteSpace(raw)) {
                continue;
            }
            var value = raw.Trim();
            if (value.IndexOf("://", StringComparison.Ordinal) >= 0) {
                if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || string.IsNullOrWhiteSpace(uri.Host)) {
                    warnings.Add($"Skipping invalid endpoint '{value}'.");
                    continue;
                }

                var scheme = uri.Scheme.ToLowerInvariant();
                if (scheme == Uri.UriSchemeHttp || scheme == Uri.UriSchemeHttps) {
                    var builder = new UriBuilder(uri) {
                        Scheme = Uri.UriSchemeHttps,
                        Port = uri.IsDefaultPort ? options.HttpsPort : uri.Port
                    };
                    httpsTargets.Add(builder.Uri.ToString());
                    continue;
                }

                if (TryCreateMailTargetFromScheme(uri, options, out var target)) {
                    AddMailTarget(mailTargets, target!);
                    continue;
                }

                warnings.Add($"Skipping unsupported endpoint scheme in '{value}'.");
                continue;
            }

            if (TryParseHostAndPort(value, out var hostWithPort, out var parsedPort)) {
                if (TryCreateMailTargetFromPort(hostWithPort, parsedPort, out var targetByPort)) {
                    AddMailTarget(mailTargets, targetByPort!);
                } else {
                    httpsTargets.Add(BuildHttpsUrl($"{hostWithPort}:{parsedPort}", options.HttpsPort));
                }
            } else {
                httpsTargets.Add(BuildHttpsUrl(value, options.HttpsPort));
            }
        }
    }

    private static bool TryCreateMailTargetFromScheme(Uri uri, CertificateInventoryCaptureOptions options, out MailEndpointTarget? target) {
        target = null;
        var host = uri.Host.Trim().TrimEnd('.');
        if (string.IsNullOrWhiteSpace(host)) {
            return false;
        }
        var scheme = uri.Scheme.ToLowerInvariant();
        if (scheme == "smtp") {
            target = new MailEndpointTarget {
                Host = host,
                Port = uri.IsDefaultPort ? options.SmtpPort : uri.Port,
                Protocol = MailTlsAnalysis.MailProtocol.Smtp,
                Service = "SMTP-STARTTLS",
                Scheme = "smtp",
                ChainSource = "mailtls-starttls"
            };
            return true;
        }
        if (scheme == "submission") {
            target = new MailEndpointTarget {
                Host = host,
                Port = uri.IsDefaultPort ? options.SubmissionPort : uri.Port,
                Protocol = MailTlsAnalysis.MailProtocol.Smtp,
                Service = "SMTP-SUBMISSION-STARTTLS",
                Scheme = "submission",
                ChainSource = "mailtls-starttls"
            };
            return true;
        }
        if (scheme == "imap" || scheme == "imaps") {
            target = new MailEndpointTarget {
                Host = host,
                Port = uri.IsDefaultPort ? options.ImapPort : uri.Port,
                Protocol = MailTlsAnalysis.MailProtocol.Imap,
                Service = "IMAPS",
                Scheme = "imaps",
                ChainSource = "mailtls-directtls"
            };
            return true;
        }
        if (scheme == "pop3" || scheme == "pop3s") {
            target = new MailEndpointTarget {
                Host = host,
                Port = uri.IsDefaultPort ? options.Pop3Port : uri.Port,
                Protocol = MailTlsAnalysis.MailProtocol.Pop3,
                Service = "POP3S",
                Scheme = "pop3s",
                ChainSource = "mailtls-directtls"
            };
            return true;
        }
        return false;
    }

    private static bool TryCreateMailTargetFromPort(string host, int port, out MailEndpointTarget? target) {
        target = null;
        var normalized = host.Trim().TrimEnd('.');
        if (string.IsNullOrWhiteSpace(normalized)) {
            return false;
        }

        if (port == 25) {
            target = new MailEndpointTarget {
                Host = normalized,
                Port = port,
                Protocol = MailTlsAnalysis.MailProtocol.Smtp,
                Service = "SMTP-STARTTLS",
                Scheme = "smtp",
                ChainSource = "mailtls-starttls"
            };
            return true;
        }
        if (port == 587) {
            target = new MailEndpointTarget {
                Host = normalized,
                Port = port,
                Protocol = MailTlsAnalysis.MailProtocol.Smtp,
                Service = "SMTP-SUBMISSION-STARTTLS",
                Scheme = "submission",
                ChainSource = "mailtls-starttls"
            };
            return true;
        }
        if (port == 993) {
            target = new MailEndpointTarget {
                Host = normalized,
                Port = port,
                Protocol = MailTlsAnalysis.MailProtocol.Imap,
                Service = "IMAPS",
                Scheme = "imaps",
                ChainSource = "mailtls-directtls"
            };
            return true;
        }
        if (port == 995) {
            target = new MailEndpointTarget {
                Host = normalized,
                Port = port,
                Protocol = MailTlsAnalysis.MailProtocol.Pop3,
                Service = "POP3S",
                Scheme = "pop3s",
                ChainSource = "mailtls-directtls"
            };
            return true;
        }
        return false;
    }

    private static bool TryParseHostAndPort(string value, out string host, out int port) {
        host = string.Empty;
        port = 0;
        var idx = value.LastIndexOf(':');
        if (idx <= 0 || idx >= value.Length - 1) {
            return false;
        }
        var maybeHost = value.Substring(0, idx).Trim();
        var maybePort = value.Substring(idx + 1).Trim();
        if (!int.TryParse(maybePort, out var parsed) || parsed < 1 || parsed > 65535) {
            return false;
        }
        if (string.IsNullOrWhiteSpace(maybeHost)) {
            return false;
        }
        host = maybeHost;
        port = parsed;
        return true;
    }

    private static async Task<IReadOnlyList<string>> ResolveMxHostsAsync(string domain, DnsConfiguration dnsConfiguration, int maxMxHostsPerDomain, CancellationToken cancellationToken) {
        var answers = await dnsConfiguration.QueryDNS(domain, DnsRecordType.MX, cancellationToken: cancellationToken).ConfigureAwait(false);
        var hosts = new List<string>();
        foreach (var answer in answers) {
            if (TryExtractMxHost(answer.DataRaw, out var host) ||
                TryExtractMxHost(answer.Data, out host)) {
                hosts.Add(host);
            }
        }

        var distinct = hosts
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(h => h, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (maxMxHostsPerDomain > 0 && distinct.Count > maxMxHostsPerDomain) {
            distinct = distinct.Take(maxMxHostsPerDomain).ToList();
        }
        return distinct;
    }

    internal static bool TryExtractMxHost(string? rawValue, out string host) {
        host = string.Empty;
        if (string.IsNullOrWhiteSpace(rawValue)) {
            return false;
        }

        var parts = rawValue!
            .Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) {
            return false;
        }

        var candidate = parts.Length == 1 ? parts[0].Trim() : parts[parts.Length - 1].Trim();
        if (string.Equals(candidate, ".", StringComparison.Ordinal)) {
            return false;
        }

        candidate = candidate.Trim().TrimEnd('.');
        if (string.IsNullOrWhiteSpace(candidate)) {
            return false;
        }

        if (int.TryParse(candidate, out _)) {
            return false;
        }

        host = candidate;
        return true;
    }

    private static async Task<IReadOnlyList<string>> DiscoverCtSubdomainsAsync(
        IReadOnlyList<string> domains,
        CertificateInventoryCaptureOptions options,
        List<string> warnings,
        InternalLogger logger,
        CancellationToken cancellationToken) {
        if (domains == null || domains.Count == 0 || !options.IncludeCtDiscoveredSubdomains) {
            return Array.Empty<string>();
        }

        if (options.EnableNativeCtLogSubdomainSource &&
            options.EnableNativeCtSharedIngestion &&
            domains.Count > 1) {
            logger.WriteVerbose("Using shared native CT ingestion for {0} domain(s).", domains.Count);
            return await DiscoverCtSubdomainsNativeSharedAsync(domains, options, warnings, logger, cancellationToken).ConfigureAwait(false);
        }

        var discovered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var warningLock = new object();
        var discoveredLock = new object();
        var maxParallelism = Math.Max(1, options.DiscoveryParallelism);
        var nativeCtCursorStatePath = options.NativeCtCursorStatePath;
        if (string.IsNullOrWhiteSpace(nativeCtCursorStatePath) && options.EnableNativeCtLogSubdomainSource) {
            nativeCtCursorStatePath = System.IO.Path.Combine(options.CacheDirectory, "inventory", "ct-native-cursor.json");
        }
        using var gate = new SemaphoreSlim(maxParallelism, maxParallelism);
        var tasks = new List<Task>(domains.Count);
        foreach (var domain in domains) {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            tasks.Add(Task.Run(async () => {
                try {
                    var analysis = new SubdomainsAnalysis {
                        DnsConfiguration = new DnsConfiguration {
                            DnsEndpoint = options.DnsEndpoint
                        },
                        VerifyStillResolves = options.VerifyCtDiscoveredSubdomains,
                        DetectSensitiveSubdomains = false,
                        ScanSensitiveSubdomainTxt = false,
                        DetectAiInfrastructureExposure = false,
                        EnableNativeCtLogSource = options.EnableNativeCtLogSubdomainSource,
                        NativeCtLogOnly = options.NativeCtLogOnly,
                        NativeCtLogListUrl = options.NativeCtLogListUrl,
                        NativeCtMaxLogs = options.NativeCtMaxLogs,
                        NativeCtMaxEntriesPerLog = options.NativeCtMaxEntriesPerLog,
                        NativeCtEntryBatchSize = options.NativeCtEntryBatchSize,
                        NativeCtInitialBackfillEntriesPerLog = options.NativeCtInitialBackfillEntriesPerLog,
                        NativeCtCursorStatePath = nativeCtCursorStatePath,
                        NativeCtIncludePendingLogs = options.NativeCtIncludePendingLogs,
                        NativeCtRequestDelay = options.NativeCtRequestDelay
                    };
                    if (options.NativeCtLogUrls != null && options.NativeCtLogUrls.Count > 0) {
                        foreach (var logUrl in options.NativeCtLogUrls) {
                            if (!string.IsNullOrWhiteSpace(logUrl)) {
                                analysis.NativeCtLogUrls.Add(logUrl.Trim());
                            }
                        }
                    }
                    if (options.MaxCtRowsPerDomain > 0) {
                        analysis.MaxCtRowsToProcess = options.MaxCtRowsPerDomain;
                    }
                    if (options.MaxCtSubdomainsPerDomain > 0) {
                        analysis.MaxSubdomains = options.MaxCtSubdomainsPerDomain;
                        analysis.MaxResolutionChecks = options.MaxCtSubdomainsPerDomain;
                    }

                    await analysis.AnalyzeAsync(domain, logger, cancellationToken).ConfigureAwait(false);
                    if (!analysis.QuerySucceeded && !string.IsNullOrWhiteSpace(analysis.FailureReason)) {
                        lock (warningLock) {
                            warnings.Add($"CT subdomain discovery failed for {domain}: {analysis.FailureReason}");
                        }
                    } else if (analysis.ResultsCapped) {
                        lock (warningLock) {
                            warnings.Add($"CT subdomain discovery results were capped for {domain}.");
                        }
                    }

                    var candidates = analysis.Subdomains ?? Array.Empty<SubdomainDiscoveryEntry>();
                    foreach (var candidate in candidates) {
                        if (candidate == null || string.IsNullOrWhiteSpace(candidate.Name)) {
                            continue;
                        }
                        if (options.VerifyCtDiscoveredSubdomains &&
                            candidate.ResolutionStatus != SubdomainResolutionStatus.Resolves) {
                            continue;
                        }

                        lock (discoveredLock) {
                            discovered.Add(candidate.Name);
                        }
                    }
                } catch (Exception ex) {
                    lock (warningLock) {
                        warnings.Add($"CT subdomain discovery failed for {domain}: {ex.Message}");
                    }
                } finally {
                    gate.Release();
                }
            }, cancellationToken));
        }

        await Task.WhenAll(tasks).ConfigureAwait(false);
        return discovered.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static async Task<IReadOnlyList<string>> DiscoverCtSubdomainsNativeSharedAsync(
        IReadOnlyList<string> domains,
        CertificateInventoryCaptureOptions options,
        List<string> warnings,
        InternalLogger logger,
        CancellationToken cancellationToken) {
        var nativeCtCursorStatePath = options.NativeCtCursorStatePath;
        if (string.IsNullOrWhiteSpace(nativeCtCursorStatePath)) {
            nativeCtCursorStatePath = System.IO.Path.Combine(options.CacheDirectory, "inventory", "ct-native-cursor.json");
        }

        var source = new NativeCtLogSubdomainDiscovery();
        var effectiveMaxRows = ComputeNativeSharedMaxRows(domains.Count, options.MaxCtRowsPerDomain);
        var sourceOptions = new NativeCtLogSubdomainDiscoveryOptions {
            BaseDomain = domains[0],
            MaxCtRowsToProcess = effectiveMaxRows,
            MaxSubdomains = options.MaxCtSubdomainsPerDomain > 0 ? options.MaxCtSubdomainsPerDomain : 10000,
            LogListUrl = options.NativeCtLogListUrl,
            ExplicitLogUrls = options.NativeCtLogUrls.ToList(),
            MaxLogsToProcess = options.NativeCtMaxLogs,
            MaxEntriesPerLog = options.NativeCtMaxEntriesPerLog,
            EntryBatchSize = options.NativeCtEntryBatchSize,
            InitialBackfillEntriesPerLog = options.NativeCtInitialBackfillEntriesPerLog,
            CursorStatePath = nativeCtCursorStatePath,
            IncludePendingLogs = options.NativeCtIncludePendingLogs,
            RequestDelay = options.NativeCtRequestDelay
        };

        var batchResult = await source.DiscoverForDomainsAsync(domains, sourceOptions, logger, cancellationToken).ConfigureAwait(false);
        foreach (var warning in batchResult.Warnings) {
            warnings.Add(warning);
        }

        if (!batchResult.SourceSucceeded && !batchResult.ResultsCapped) {
            warnings.Add("Native CT shared ingestion did not return successful CT log responses.");
        }
        if (batchResult.ResultsCapped) {
            warnings.Add("Native CT shared ingestion reached configured caps.");
        }

        var discovered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var domain in domains) {
            if (!batchResult.SubdomainsByDomain.TryGetValue(domain, out var entries)) {
                continue;
            }

            foreach (var name in entries.Keys) {
                discovered.Add(name);
            }
        }

        if (!options.VerifyCtDiscoveredSubdomains || discovered.Count == 0) {
            return discovered.OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToList();
        }

        var verifyCap = ComputeVerifyCap(domains.Count, options.MaxCtSubdomainsPerDomain, discovered.Count);
        var namesToVerify = discovered
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .Take(verifyCap)
            .ToList();
        if (verifyCap < discovered.Count) {
            warnings.Add($"CT subdomain DNS verification capped at {verifyCap} host(s) during shared native ingestion.");
        }

        var resolved = await VerifyDiscoveredSubdomainsResolveAsync(namesToVerify, options, cancellationToken).ConfigureAwait(false);
        return resolved.OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static int ComputeNativeSharedMaxRows(int domainCount, int maxCtRowsPerDomain) {
        if (domainCount <= 0) {
            return maxCtRowsPerDomain > 0 ? maxCtRowsPerDomain : 200000;
        }

        if (maxCtRowsPerDomain <= 0) {
            return 200000;
        }

        var multiplier = Math.Min(25, domainCount);
        var candidate = (long)maxCtRowsPerDomain * multiplier;
        if (candidate > 2000000) {
            candidate = 2000000;
        }
        if (candidate < maxCtRowsPerDomain) {
            candidate = maxCtRowsPerDomain;
        }
        return (int)candidate;
    }

    private static int ComputeVerifyCap(int domainCount, int maxCtSubdomainsPerDomain, int discoveredCount) {
        if (discoveredCount <= 0) {
            return 0;
        }

        if (maxCtSubdomainsPerDomain <= 0) {
            return discoveredCount;
        }

        var candidate = (long)maxCtSubdomainsPerDomain * Math.Max(1, domainCount);
        if (candidate > int.MaxValue) {
            candidate = int.MaxValue;
        }

        var cap = (int)candidate;
        if (cap <= 0) {
            cap = discoveredCount;
        }
        if (cap > discoveredCount) {
            cap = discoveredCount;
        }
        return cap;
    }

    private static async Task<HashSet<string>> VerifyDiscoveredSubdomainsResolveAsync(
        IReadOnlyList<string> names,
        CertificateInventoryCaptureOptions options,
        CancellationToken cancellationToken) {
        var resolved = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (names == null || names.Count == 0) {
            return resolved;
        }

        var dns = new DnsConfiguration {
            DnsEndpoint = options.DnsEndpoint
        };
        var lockObject = new object();
        var maxParallelism = Math.Max(1, options.DiscoveryParallelism);
        using var semaphore = new SemaphoreSlim(maxParallelism, maxParallelism);
        var tasks = new List<Task>(names.Count);
        foreach (var name in names) {
            await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            tasks.Add(Task.Run(async () => {
                try {
                    var hasAddress = false;
                    var a = await dns.QueryDNS(name, DnsRecordType.A, cancellationToken: cancellationToken).ConfigureAwait(false);
                    if (a != null && a.Length > 0) {
                        hasAddress = true;
                    } else {
                        var aaaa = await dns.QueryDNS(name, DnsRecordType.AAAA, cancellationToken: cancellationToken).ConfigureAwait(false);
                        hasAddress = aaaa != null && aaaa.Length > 0;
                    }

                    if (hasAddress) {
                        lock (lockObject) {
                            resolved.Add(name);
                        }
                    }
                } catch {
                } finally {
                    semaphore.Release();
                }
            }, cancellationToken));
        }

        await Task.WhenAll(tasks).ConfigureAwait(false);
        return resolved;
    }

    private static async Task<IReadOnlyList<CertificateMonitor.Entry>> ProbeHttpsAsync(
        IEnumerable<string> httpsTargets,
        CertificateInventoryCaptureOptions options,
        InternalLogger logger,
        CancellationToken cancellationToken) {
        var list = httpsTargets.Where(target => !string.IsNullOrWhiteSpace(target)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (list.Count == 0) {
            return Array.Empty<CertificateMonitor.Entry>();
        }

        using var monitor = new CertificateMonitor {
            CacheDirectory = options.CacheDirectory,
            PersistInventorySnapshots = false,
            MaxParallelism = Math.Max(1, options.MaxParallelism)
        };
        logger.WriteVerbose("Starting HTTPS probe for {0} endpoint(s).", list.Count);
        if (options.MaxProbeStartsPerSecond > 0) {
            logger.WriteVerbose("Probe start rate limit enabled: up to {0} start(s)/second.", options.MaxProbeStartsPerSecond);
        }
        var rateLimiter = new ProbeStartRateLimiter(options.MaxProbeStartsPerSecond);
        monitor.AnalysisOverride = async (url, port, internalLogger, token) => {
            await rateLimiter.WaitAsync(token).ConfigureAwait(false);
            var analysis = new CertificateAnalysis {
                CaptureTlsDetails = true
            };
            ConfigureHttpsAnalysis(analysis, options);
            await analysis.AnalyzeUrl(url, port, internalLogger, token).ConfigureAwait(false);
            return analysis;
        };

        await monitor.Analyze(list, options.HttpsPort, logger, cancellationToken, showProgress: true).ConfigureAwait(false);
        logger.WriteVerbose("Completed HTTPS probe for {0} endpoint(s).", list.Count);
        return monitor.Results.ToList();
    }

    internal static void ConfigureHttpsAnalysis(CertificateAnalysis analysis, CertificateInventoryCaptureOptions options) {
        if (analysis == null) {
            throw new ArgumentNullException(nameof(analysis));
        }
        if (options == null) {
            throw new ArgumentNullException(nameof(options));
        }

        analysis.SkipRevocation = options.SkipRevocation;

        if (options.CtProfile == CertificateCtEnrichmentProfile.Disabled) {
            analysis.CtLogApiTemplates.Clear();
            analysis.EnableCensysCtSource = false;
            analysis.CensysApiId = null;
            analysis.CensysApiSecret = null;
            analysis.CensysCtApiUrlTemplate = string.Empty;
            analysis.EnableShodanCtSource = false;
            analysis.ShodanApiKey = null;
            analysis.ShodanCtApiUrlTemplate = string.Empty;
            return;
        }

        if (options.CtProfile == CertificateCtEnrichmentProfile.Public || !options.IncludeDefaultCtTemplate) {
            analysis.CtLogApiTemplates.Clear();
        }
        if (options.IncludeDefaultCtTemplate) {
            AddCtTemplateIfMissing(analysis.CtLogApiTemplates, "https://crt.sh/?sha256={0}&output=json");
        }
        foreach (var template in options.CtApiTemplates) {
            AddCtTemplateIfMissing(analysis.CtLogApiTemplates, template);
        }

        var autoEnableCommercialSources = options.CtProfile == CertificateCtEnrichmentProfile.Extended;
        var hasCensysCredentials = !string.IsNullOrWhiteSpace(options.CensysApiId) &&
                                   !string.IsNullOrWhiteSpace(options.CensysApiSecret);
        var hasShodanCredentials = !string.IsNullOrWhiteSpace(options.ShodanApiKey);

        analysis.EnableCensysCtSource = options.EnableCensysCtSource || (autoEnableCommercialSources && hasCensysCredentials);
        analysis.CensysApiId = options.CensysApiId;
        analysis.CensysApiSecret = options.CensysApiSecret;
        if (!string.IsNullOrWhiteSpace(options.CensysCtApiUrlTemplate)) {
            analysis.CensysCtApiUrlTemplate = options.CensysCtApiUrlTemplate!;
        }

        analysis.EnableShodanCtSource = options.EnableShodanCtSource || (autoEnableCommercialSources && hasShodanCredentials);
        analysis.ShodanApiKey = options.ShodanApiKey;
        if (!string.IsNullOrWhiteSpace(options.ShodanCtApiUrlTemplate)) {
            analysis.ShodanCtApiUrlTemplate = options.ShodanCtApiUrlTemplate!;
        }
    }

    private static void AddCtTemplateIfMissing(ICollection<string> templates, string? template) {
        if (template == null) {
            return;
        }
        if (string.IsNullOrWhiteSpace(template)) {
            return;
        }
        var trimmed = template.Trim();
        foreach (var existing in templates) {
            if (string.Equals(existing, trimmed, StringComparison.OrdinalIgnoreCase)) {
                return;
            }
        }
        templates.Add(trimmed);
    }

    private static void AppendCtConfigurationWarnings(CertificateInventoryCaptureOptions options, List<string> warnings) {
        if (options.CtProfile == CertificateCtEnrichmentProfile.Disabled) {
            return;
        }

        if (options.EnableCensysCtSource) {
            if (string.IsNullOrWhiteSpace(options.CensysApiId) || string.IsNullOrWhiteSpace(options.CensysApiSecret)) {
                warnings.Add("Censys CT source is enabled but CensysApiId/CensysApiSecret are missing; Censys source will not be used.");
            }
            if (string.IsNullOrWhiteSpace(options.CensysCtApiUrlTemplate)) {
                warnings.Add("Censys CT source is enabled but CensysCtApiUrlTemplate is empty; source may report template errors.");
            }
        } else if (options.CtProfile == CertificateCtEnrichmentProfile.Extended) {
            if (string.IsNullOrWhiteSpace(options.CensysApiId) || string.IsNullOrWhiteSpace(options.CensysApiSecret)) {
                warnings.Add("CT profile 'Extended' can auto-enable Censys when credentials are present. Censys credentials are not configured.");
            }
        }

        if (options.EnableShodanCtSource) {
            if (string.IsNullOrWhiteSpace(options.ShodanApiKey)) {
                warnings.Add("Shodan CT source is enabled but ShodanApiKey is missing; Shodan source will not be used.");
            }
        } else if (options.CtProfile == CertificateCtEnrichmentProfile.Extended) {
            if (string.IsNullOrWhiteSpace(options.ShodanApiKey)) {
                warnings.Add("CT profile 'Extended' can auto-enable Shodan when credentials are present. Shodan API key is not configured.");
            }
        }
    }

    private static async Task<IReadOnlyList<CertificateInventoryEntry>> ProbeMailAsync(
        IReadOnlyList<MailEndpointTarget> mailTargets,
        CertificateInventoryCaptureOptions options,
        InternalLogger logger,
        CancellationToken cancellationToken) {
        if (mailTargets == null || mailTargets.Count == 0) {
            return Array.Empty<CertificateInventoryEntry>();
        }

        var results = new ConcurrentBag<CertificateInventoryEntry>();
        var parallelism = Math.Max(1, options.MaxParallelism);
        var totalTargets = mailTargets.Count;
        var completedTargets = 0;
        logger.WriteVerbose("Starting mail TLS probe for {0} endpoint(s).", totalTargets);
        var rateLimiter = new ProbeStartRateLimiter(options.MaxProbeStartsPerSecond);
        using var gate = new SemaphoreSlim(parallelism, parallelism);
        var tasks = new List<Task>(mailTargets.Count);
        foreach (var target in mailTargets) {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            tasks.Add(Task.Run(async () => {
                try {
                    await rateLimiter.WaitAsync(cancellationToken).ConfigureAwait(false);
                    logger.WriteVerbose("Probing mail endpoint {0}:{1} ({2}).", target.Host, target.Port, target.Service);
                    var analysis = new MailTlsAnalysis {
                        Timeout = options.MailTimeout
                    };
                    await analysis.AnalyzeServer(target.Protocol, target.Host, target.Port, logger, cancellationToken).ConfigureAwait(false);
                    var key = $"{target.Host}:{target.Port}";
                    if (analysis.ServerResults.TryGetValue(key, out var tlsResult)) {
                        results.Add(ToInventoryEntry(target, tlsResult));
                    } else {
                        results.Add(ToInventoryEntry(target, new MailTlsAnalysis.TlsResult()));
                    }
                } catch {
                    results.Add(ToInventoryEntry(target, new MailTlsAnalysis.TlsResult()));
                } finally {
                    var completed = Interlocked.Increment(ref completedTargets);
                    logger.WriteProgress(
                        "CertificateInventoryCapture.Mail",
                        $"{target.Service} {target.Host}:{target.Port}",
                        totalTargets == 0 ? 100d : completed * 100d / totalTargets,
                        completed,
                        totalTargets);
                    gate.Release();
                }
            }, cancellationToken));
        }
        await Task.WhenAll(tasks).ConfigureAwait(false);
        logger.WriteVerbose("Completed mail TLS probe for {0} endpoint(s).", totalTargets);
        return results.ToList();
    }

    private static List<CertificateInventoryEntry> DeduplicateEntries(List<CertificateInventoryEntry> entries) {
        var byEndpoint = new Dictionary<string, CertificateInventoryEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries) {
            if (entry == null) {
                continue;
            }
            var host = !string.IsNullOrWhiteSpace(entry.ResolvedHost) ? entry.ResolvedHost! : entry.Host;
            var key = $"{host}|{entry.Port}|{entry.Service}";
            if (!byEndpoint.TryGetValue(key, out var existing)) {
                byEndpoint[key] = entry;
                continue;
            }

            if (GetEntryScore(entry) > GetEntryScore(existing)) {
                byEndpoint[key] = entry;
            }
        }

        return byEndpoint.Values
            .OrderBy(e => e.Host, StringComparer.OrdinalIgnoreCase)
            .ThenBy(e => e.Port)
            .ThenBy(e => e.Service, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static int GetEntryScore(CertificateInventoryEntry entry) {
        var score = 0;
        if (!string.IsNullOrWhiteSpace(entry.CertificateThumbprint)) {
            score += 10;
        }
        if (entry.IsReachable) {
            score += 4;
        }
        if (entry.Valid) {
            score += 6;
        }
        if (entry.ChainComplete) {
            score += 2;
        }
        return score;
    }

    private static CertificateInventoryEntry ToInventoryEntry(MailEndpointTarget target, MailTlsAnalysis.TlsResult result) {
        var certificate = result.Certificate;
        var chain = result.Chain != null && result.Chain.Count > 0
            ? result.Chain
            : (certificate != null ? new List<X509Certificate2> { certificate } : new List<X509Certificate2>());
        var root = chain.Count > 0 ? chain[chain.Count - 1] : null;

        var issuerIdentity = CertificateIssuerClassifier.Classify(certificate);
        var rootIdentity = CertificateIssuerClassifier.Classify(root);
        var eku = CertificateExtendedKeyUsageAnalyzer.Analyze(certificate);

        var keyAlgorithm = !string.IsNullOrWhiteSpace(result.PublicKeyAlgorithm)
            ? result.PublicKeyAlgorithm!
            : (certificate?.PublicKey?.Oid?.FriendlyName ?? certificate?.PublicKey?.Oid?.Value ?? string.Empty);
        var keySize = result.PublicKeySize ?? GetPublicKeySize(certificate);
        var signatureOid = certificate?.SignatureAlgorithm?.Value ?? string.Empty;
        var sha1Signature = signatureOid == "1.2.840.113549.1.1.5" ||
                            signatureOid == "1.2.840.10040.4.3" ||
                            signatureOid == "1.3.14.3.2.29";
        var rsaPssSignature = signatureOid == "1.2.840.113549.1.1.10";
        var authenticationProfile = string.IsNullOrWhiteSpace(eku.AuthenticationProfile)
            ? CertificateAuthenticationProfileClassifier.Classify(eku)
            : eku.AuthenticationProfile;

        var notBeforeUtc = certificate != null
            ? new DateTimeOffset(certificate.NotBefore.ToUniversalTime())
            : (result.CertificateNotBefore.HasValue ? new DateTimeOffset(result.CertificateNotBefore.Value.ToUniversalTime()) : (DateTimeOffset?)null);
        var notAfterUtc = certificate != null
            ? new DateTimeOffset(certificate.NotAfter.ToUniversalTime())
            : (result.CertificateNotAfter.HasValue ? new DateTimeOffset(result.CertificateNotAfter.Value.ToUniversalTime()) : (DateTimeOffset?)null);
        var isReachable = result.StartTlsAdvertised || certificate != null;
        var valid = certificate != null && result.CertificateValid && !result.IsExpired;
        var chainComplete = certificate != null && result.ChainValid && chain.Count > 1;

        var entry = new CertificateInventoryEntry {
            Host = target.Host,
            ResolvedHost = target.Host,
            Url = $"{target.Scheme}://{target.Host}:{target.Port}",
            Scheme = target.Scheme,
            Port = target.Port,
            Service = target.Service,
            CertificateSubject = certificate?.Subject ?? result.CertificateSubject,
            CertificateIssuer = certificate?.Issuer ?? result.CertificateIssuer,
            CertificateThumbprint = certificate?.Thumbprint ?? result.CertificateThumbprint,
            CertificateSerialNumber = certificate?.SerialNumber ?? result.CertificateSerialNumber,
            CertificateIssuerCommonName = issuerIdentity.CommonName,
            CertificateIssuerOrganization = issuerIdentity.Organization,
            CertificateIssuerNormalized = issuerIdentity.NormalizedName,
            CertificateAuthorityFamily = issuerIdentity.AuthorityFamily,
            CertificateRootSubject = root?.Subject,
            CertificateRootIssuer = root?.Issuer,
            CertificateRootThumbprint = root?.Thumbprint,
            CertificateRootIssuerCommonName = rootIdentity.CommonName,
            CertificateRootIssuerOrganization = rootIdentity.Organization,
            CertificateRootIssuerNormalized = rootIdentity.NormalizedName,
            CertificateRootAuthorityFamily = rootIdentity.AuthorityFamily,
            CertificateChainLength = chain.Count,
            CertificateIntermediateCount = Math.Max(0, chain.Count - 2),
            IsKnownCertificateAuthority = issuerIdentity.IsKnownAuthority,
            IsKnownRootCertificateAuthority = rootIdentity.IsKnownAuthority,
            NotBeforeUtc = notBeforeUtc,
            NotAfterUtc = notAfterUtc,
            Valid = valid,
            Expired = result.IsExpired,
            ChainComplete = chainComplete,
            IsReachable = isReachable,
            IsSelfSigned = IsSelfSigned(certificate),
            HostnameMatch = certificate != null && result.HostnameMatch,
            PresentInCtLogs = false,
            DaysToExpire = result.DaysToExpire,
            DaysValid = result.DaysValid,
            Protocol = result.Protocol.ToString(),
            KeyAlgorithm = keyAlgorithm,
            KeySize = keySize,
            WeakKey = keySize > 0 && keySize < 2048,
            Sha1Signature = sha1Signature,
            RsaPssSignature = rsaPssSignature,
            HasEnhancedKeyUsageExtension = eku.HasEnhancedKeyUsageExtension,
            HasAnyExtendedKeyUsageOid = eku.HasAnyExtendedKeyUsageOid,
            AllowsServerAuthentication = eku.AllowsServerAuthentication,
            AllowsClientAuthentication = eku.AllowsClientAuthentication,
            AllowsSecureEmail = eku.AllowsSecureEmail,
            AuthenticationProfile = authenticationProfile,
            CertificateChainSource = target.ChainSource
        };
        entry.CertificateChainSources.Add(target.ChainSource);
        if (eku.Oids.Count > 0) {
            entry.ExtendedKeyUsageOids.AddRange(eku.Oids);
        }
        if (result.CertificateDnsNames.Count > 0) {
            entry.SubjectAlternativeNames.AddRange(result.CertificateDnsNames.Distinct(StringComparer.OrdinalIgnoreCase));
        }
        foreach (var chainElement in chain) {
            if (!string.IsNullOrWhiteSpace(chainElement.Subject)) {
                entry.CertificateChainSubjects.Add(chainElement.Subject);
            }
            if (!string.IsNullOrWhiteSpace(chainElement.Issuer)) {
                entry.CertificateChainIssuers.Add(chainElement.Issuer);
            }
            if (!string.IsNullOrWhiteSpace(chainElement.Thumbprint)) {
                entry.CertificateChainThumbprints.Add(chainElement.Thumbprint);
            }
        }

        return entry;
    }

    private static int GetPublicKeySize(X509Certificate2? certificate) {
        if (certificate == null) {
            return 0;
        }
        try {
            using (var rsa = certificate.GetRSAPublicKey()) {
                if (rsa != null) {
                    return rsa.KeySize;
                }
            }
        } catch {
        }
        try {
            using (var ecdsa = certificate.GetECDsaPublicKey()) {
                if (ecdsa != null) {
                    return ecdsa.KeySize;
                }
            }
        } catch {
        }
        try {
            using (var dsa = certificate.GetDSAPublicKey()) {
                if (dsa != null) {
                    return dsa.KeySize;
                }
            }
        } catch {
        }
        return 0;
    }

    private static bool IsSelfSigned(X509Certificate2? certificate) {
        if (certificate == null) {
            return false;
        }
        if (string.IsNullOrWhiteSpace(certificate.Subject) || string.IsNullOrWhiteSpace(certificate.Issuer)) {
            return false;
        }
        return string.Equals(certificate.Subject, certificate.Issuer, StringComparison.OrdinalIgnoreCase);
    }
}

internal static class CertificateInventoryCmdletPathDefaults {
    internal static string DefaultCacheDirectory => System.IO.Path.Combine(System.IO.Path.GetTempPath(), "DomainDetective", "cert-monitor");
}
