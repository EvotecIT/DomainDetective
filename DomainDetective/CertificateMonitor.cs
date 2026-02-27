using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;
using PeriodicTimer = System.Threading.PeriodicTimer;

namespace DomainDetective {
    /// <summary>
    /// Aggregates certificate validity information for multiple hosts.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// The monitor periodically connects to configured hosts and records
    /// certificate details such as expiration, validity, and chain state.
    /// </remarks>
    public class CertificateMonitor : IDisposable {
        /// <summary>Result entry for a single host.</summary>
        public class Entry {
            /// <summary>Host that was checked.</summary>
            public string Host { get; init; } = string.Empty;
            /// <summary>Resolved endpoint URL used for the check.</summary>
            public string Url { get; init; } = string.Empty;
            /// <summary>Resolved endpoint host name.</summary>
            public string ResolvedHost { get; init; } = string.Empty;
            /// <summary>Resolved endpoint scheme.</summary>
            public string Scheme { get; init; } = "https";
            /// <summary>Resolved endpoint port.</summary>
            public int Port { get; init; } = 443;
            /// <summary>Best-effort service classification derived from endpoint details.</summary>
            public string Service { get; init; } = "HTTPS";
            /// <summary>Certificate expiry date.</summary>
            public DateTime ExpiryDate { get; init; }
            /// <summary>Whether the certificate chain was validated successfully.</summary>
            public bool Valid { get; init; }
            /// <summary>Whether the certificate is expired.</summary>
            public bool Expired { get; init; }
            /// <summary>Whether the certificate chain contained all intermediates.</summary>
            public bool ChainComplete { get; init; }
            /// <summary>The negotiated TLS protocol.</summary>
            public SslProtocols Protocol { get; init; }
            /// <summary>Captured analysis details.</summary>
            public CertificateAnalysis Analysis { get; init; } = null!;
        }

        private PeriodicTimer? _timer;
        private CancellationTokenSource? _cts;
        private Task? _loopTask;
        /// <summary>Optional override for certificate analysis (primarily for testing).</summary>
        internal Func<string, int, InternalLogger, CancellationToken, Task<CertificateAnalysis>>? AnalysisOverride { get; set; }
        private IReadOnlyList<string> _monitorHosts = Array.Empty<string>();
        private int _monitorPort;
        private InternalLogger? _monitorLogger;

        /// <summary>Directory used to cache certificate data.</summary>
        public string CacheDirectory { get; set; } =
            Path.Combine(Path.GetTempPath(), "DomainDetective", "cert-monitor");

        /// <summary>Duration cached files are kept.</summary>
        public TimeSpan CacheRetention { get; set; } = TimeSpan.FromDays(7);
        /// <summary>Persist monitor runs as inventory snapshots (opt-in).</summary>
        public bool PersistInventorySnapshots { get; set; }

        /// <summary>Directory used for persisted inventory snapshots.</summary>
        public string InventoryDirectory => Path.Combine(CacheDirectory, "inventory");

        private void CleanExpiredCacheEntries() {
            try {
                if (!Directory.Exists(CacheDirectory)) {
                    return;
                }

                var inventoryRoot = Path.GetFullPath(InventoryDirectory)
                    .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
                foreach (var file in Directory.EnumerateFiles(CacheDirectory, "*", SearchOption.AllDirectories)) {
                    var fullFilePath = Path.GetFullPath(file);
                    if (fullFilePath.StartsWith(inventoryRoot, StringComparison.OrdinalIgnoreCase)) {
                        continue;
                    }

                    if (DateTime.UtcNow - File.GetLastWriteTimeUtc(file) > CacheRetention) {
                        File.Delete(file);
                    }
                }

                foreach (var directory in Directory.EnumerateDirectories(CacheDirectory, "*", SearchOption.AllDirectories)
                             .OrderByDescending(x => x.Length)) {
                    if (!Directory.EnumerateFileSystemEntries(directory).Any()) {
                        Directory.Delete(directory);
                    }
                }
            } catch {
                // ignore errors from cleanup
            }
        }

        /// <summary>Indicates whether monitoring is active.</summary>
        public bool IsRunning => _timer != null;

        /// <summary>Threshold in days for considering a certificate expiring soon.</summary>
        public int ExpiryWarningDays { get; set; } = 30;
        /// <summary>Maximum number of hosts analyzed in parallel per run.</summary>
        public int MaxParallelism { get; set; } = 8;

        /// <summary>Collection of monitoring results.</summary>
        public List<Entry> Results { get; } = new();

        /// <summary>Begins periodic monitoring of the specified hosts.</summary>
        /// <param name="hosts">Hosts to monitor.</param>
        /// <param name="interval">Interval between checks.</param>
        /// <param name="port">Port used for HTTPS.</param>
        /// <param name="logger">Optional logger instance.</param>
        public void Start(IEnumerable<string> hosts, TimeSpan interval, int port = 443, InternalLogger? logger = null) {
            Stop();
            CleanExpiredCacheEntries();
            _monitorHosts = hosts.ToList();
            _monitorPort = port;
            _monitorLogger = logger;
            _cts = new CancellationTokenSource();
            _timer = new PeriodicTimer(interval);
            _loopTask = Task.Run(async () => {
                await Analyze(_monitorHosts, _monitorPort, _monitorLogger ?? new InternalLogger()).ConfigureAwait(false);
                while (_timer != null && await _timer.WaitForNextTickAsync(_cts.Token).ConfigureAwait(false)) {
                    await Analyze(_monitorHosts, _monitorPort, _monitorLogger ?? new InternalLogger()).ConfigureAwait(false);
                }
            });
        }

        /// <summary>Stops periodic monitoring.</summary>
        public void Stop() {
            StopAsync().GetAwaiter().GetResult();
        }

        /// <summary>Stops periodic monitoring asynchronously.</summary>
        public async Task StopAsync() {
            _cts?.Cancel();
            if (_loopTask != null) {
                try {
                    await _loopTask.ConfigureAwait(false);
                } catch (TaskCanceledException) {
                    // ignore cancellation
                } catch (OperationCanceledException) {
                    // ignore cancellation
                }
            }
            _timer?.Dispose();
            _timer = null;
            _cts?.Dispose();
            _cts = null;
            _loopTask = null;
        }

        /// <summary>Checks certificates for the provided hosts.</summary>
        /// <param name="hosts">Hostnames or URLs to verify.</param>
        /// <param name="port">Port used for HTTPS.</param>
        /// <param name="logger">Logger instance for diagnostics.</param>
        /// <param name="cancellationToken">Optional cancellation token.</param>
        /// <param name="showProgress">When true, writes progress via the logger.</param>
        public async Task Analyze(IEnumerable<string> hosts, int port = 443, InternalLogger? logger = null, CancellationToken cancellationToken = default, bool showProgress = true) {
            logger ??= new InternalLogger();
            Results.Clear();
            var list = hosts.ToList();
            if (list.Count > 0) {
                var entries = new Entry?[list.Count];
                var parallelism = Math.Max(1, MaxParallelism);
                int processed = 0;
                var gate = new SemaphoreSlim(parallelism, parallelism);
                var tasks = new List<Task>(list.Count);
                var schedulingCanceled = false;
                try {
                    for (var i = 0; i < list.Count; i++) {
                        try {
                            cancellationToken.ThrowIfCancellationRequested();
                            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
                        } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                            schedulingCanceled = true;
                            break;
                        }

                        var index = i;
                        var host = list[index];
                        tasks.Add(ProcessHostAsync(index, host));
                    }

                    if (tasks.Count > 0) {
                        await Task.WhenAll(tasks).ConfigureAwait(false);
                    }
                } finally {
                    gate.Dispose();
                }

                if (schedulingCanceled) {
                    cancellationToken.ThrowIfCancellationRequested();
                }

                foreach (var entry in entries) {
                    if (entry != null) {
                        Results.Add(entry);
                    }
                }

                async Task ProcessHostAsync(int index, string host) {
                    try {
                        CertificateServiceDescriptor target;
                        try {
                            target = CertificateServiceClassifier.Resolve(host, port);
                        } catch (ArgumentException) {
                            target = new CertificateServiceDescriptor {
                                Url = host,
                                Host = host,
                                Scheme = Uri.UriSchemeHttps,
                                Port = port,
                                Service = CertificateServiceClassifier.GuessService(Uri.UriSchemeHttps, port)
                            };
                        }

                        CertificateAnalysis analysis;
                        if (AnalysisOverride != null) {
                            analysis = await AnalysisOverride(target.Url, target.Port, logger, cancellationToken).ConfigureAwait(false);
                        } else {
                            analysis = new CertificateAnalysis
                            {
                                CaptureTlsDetails = true
                            };
                            await analysis.AnalyzeUrl(target.Url, target.Port, logger, cancellationToken).ConfigureAwait(false);
                        }

                        entries[index] = new Entry {
                            Host = host,
                            Url = target.Url,
                            ResolvedHost = target.Host,
                            Scheme = target.Scheme,
                            Port = target.Port,
                            Service = target.Service,
                            ExpiryDate = analysis.Certificate?.NotAfter ?? DateTime.MinValue,
                            Valid = analysis.IsValid,
                            Expired = analysis.IsExpired,
                            ChainComplete = analysis.Chain.Count > 1 && analysis.IsValid,
                            Protocol = analysis.TlsProtocol,
                            Analysis = analysis
                        };

                        var done = Interlocked.Increment(ref processed);
                        if (showProgress) {
                            logger.WriteProgress("CertificateMonitor", host, done * 100d / list.Count, done, list.Count);
                        }
                    } finally {
                        gate.Release();
                    }
                }
            }

            if (PersistInventorySnapshots) {
                SaveInventorySnapshot(port, logger);
            }
        }

        /// <summary>Number of hosts with valid certificates.</summary>
        public int ValidCount => Results.Count(e => e.Valid && !e.Expired);
        /// <summary>Number of hosts with certificates expiring soon.</summary>
        public int ExpiringCount => Results.Count(e => e.Valid && !e.Expired && (e.ExpiryDate - DateTime.UtcNow).TotalDays <= ExpiryWarningDays);
        /// <summary>Number of hosts with expired certificates.</summary>
        public int ExpiredCount => Results.Count(e => e.Expired);
        /// <summary>Number of hosts where validation failed.</summary>
        public int FailedCount => Results.Count(e => !e.Valid && !e.Expired && e.Analysis.Certificate == null);

        /// <summary>Number of certificates with complete chains.</summary>
        public int CompleteChainCount => Results.Count(e => e.ChainComplete);
        /// <summary>Number of certificates with incomplete chains.</summary>
        public int IncompleteChainCount => Results.Count(e => !e.ChainComplete && e.Analysis.Certificate != null);
        /// <summary>Number of hosts where the chain status couldn't be determined.</summary>
        public int UnknownChainCount => Results.Count(e => e.Analysis.Certificate == null);

        /// <summary>Loads persisted inventory snapshots from disk.</summary>
        /// <param name="sinceUtc">Optional lower bound for snapshot capture time.</param>
        public IReadOnlyList<CertificateInventorySnapshot> LoadInventorySnapshots(DateTimeOffset? sinceUtc = null) {
            if (!Directory.Exists(InventoryDirectory)) {
                return Array.Empty<CertificateInventorySnapshot>();
            }

            var files = Directory.GetFiles(InventoryDirectory, "*.json", SearchOption.TopDirectoryOnly);

            var snapshots = new List<CertificateInventorySnapshot>();
            foreach (var file in files) {
                try {
                    var json = File.ReadAllText(file, Encoding.UTF8);
                    var snapshot = JsonSerializer.Deserialize<CertificateInventorySnapshot>(json, JsonOptions.Default);
                    if (snapshot == null) {
                        continue;
                    }
                    if (sinceUtc.HasValue && snapshot.CapturedAtUtc < sinceUtc.Value) {
                        continue;
                    }
                    snapshots.Add(snapshot);
                } catch {
                    // ignore invalid inventory files
                }
            }

            return snapshots
                .OrderBy(snapshot => snapshot.CapturedAtUtc)
                .ToList();
        }

        private void SaveInventorySnapshot(int port, InternalLogger? logger) {
            try {
                Directory.CreateDirectory(InventoryDirectory);
                var snapshot = new CertificateInventorySnapshot {
                    CapturedAtUtc = DateTimeOffset.UtcNow,
                    Port = port
                };
                foreach (var entry in Results) {
                    snapshot.Entries.Add(ToInventoryEntry(entry));
                }

                var fileName = $"{snapshot.CapturedAtUtc:yyyyMMddTHHmmssfffffffZ}_{port}.json";
                var filePath = Path.Combine(InventoryDirectory, fileName);
                var json = JsonSerializer.Serialize(snapshot, JsonOptions.Default);
                File.WriteAllText(filePath, json, Encoding.UTF8);
            } catch (Exception ex) {
                logger?.WriteWarning("Failed to persist certificate inventory snapshot: {0}", ex.Message);
            }
        }

        private static CertificateInventoryEntry ToInventoryEntry(Entry entry) {
            var analysis = entry.Analysis;
            var certificate = analysis.Certificate;
            var issuerIdentity = CertificateIssuerClassifier.Classify(certificate);
            var chain = analysis.Chain != null && analysis.Chain.Count > 0
                ? analysis.Chain
                : (certificate != null ? new List<X509Certificate2> { certificate } : new List<X509Certificate2>());
            var root = chain.Count > 0 ? chain[chain.Count - 1] : null;
            var rootIdentity = CertificateIssuerClassifier.Classify(root);
            var snapshotEntry = new CertificateInventoryEntry {
                Host = entry.Host,
                ResolvedHost = entry.ResolvedHost,
                Url = string.IsNullOrWhiteSpace(entry.Url) ? analysis.Url : entry.Url,
                Scheme = entry.Scheme,
                Port = entry.Port,
                Service = entry.Service,
                CertificateSubject = certificate?.Subject,
                CertificateIssuer = certificate?.Issuer,
                CertificateThumbprint = certificate?.Thumbprint,
                CertificateSerialNumber = certificate?.SerialNumber,
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
                NotBeforeUtc = certificate?.NotBefore.ToUniversalTime(),
                NotAfterUtc = certificate?.NotAfter.ToUniversalTime(),
                Valid = entry.Valid,
                Expired = entry.Expired,
                ChainComplete = entry.ChainComplete,
                IsReachable = analysis.IsReachable,
                IsSelfSigned = analysis.IsSelfSigned,
                HostnameMatch = analysis.HostnameMatch,
                PresentInCtLogs = analysis.PresentInCtLogs,
                DaysToExpire = analysis.DaysToExpire,
                DaysValid = analysis.DaysValid,
                Protocol = entry.Protocol.ToString(),
                KeyAlgorithm = analysis.KeyAlgorithm,
                KeySize = analysis.KeySize,
                WeakKey = analysis.WeakKey,
                Sha1Signature = analysis.Sha1Signature,
                RsaPssSignature = analysis.RsaPssSignature,
                HasEnhancedKeyUsageExtension = analysis.HasEnhancedKeyUsageExtension,
                HasAnyExtendedKeyUsageOid = analysis.HasAnyExtendedKeyUsageOid,
                AllowsServerAuthentication = analysis.AllowsServerAuthentication,
                AllowsClientAuthentication = analysis.AllowsClientAuthentication,
                AllowsSecureEmail = analysis.AllowsSecureEmail,
                AuthenticationProfile = analysis.AuthenticationProfile,
                CertificateChainSource = analysis.ChainSource,
                CtDiscoverySources = analysis.CtDiscoverySources.ToArray(),
                CtTemplateFormatErrors = analysis.CtTemplateFormatErrors.ToArray()
            };
            snapshotEntry.CertificateChainSources.AddRange(analysis.ChainSourceHistory);
            snapshotEntry.ExtendedKeyUsageOids.AddRange(analysis.ExtendedKeyUsageOids);
            snapshotEntry.SubjectAlternativeNames.AddRange(analysis.SubjectAlternativeNames);
            foreach (var chainElement in chain) {
                if (!string.IsNullOrWhiteSpace(chainElement.Subject)) {
                    snapshotEntry.CertificateChainSubjects.Add(chainElement.Subject);
                }
                if (!string.IsNullOrWhiteSpace(chainElement.Issuer)) {
                    snapshotEntry.CertificateChainIssuers.Add(chainElement.Issuer);
                }
                if (!string.IsNullOrWhiteSpace(chainElement.Thumbprint)) {
                    snapshotEntry.CertificateChainThumbprints.Add(chainElement.Thumbprint);
                }
            }
            return snapshotEntry;
        }

        /// <summary>Builds a normalized summary view for persisted inventory snapshots.</summary>
        /// <param name="sinceUtc">Optional lower bound for snapshot capture time.</param>
        /// <param name="expiringWithinDays">Threshold window for expiring certificates.</param>
        /// <param name="maxExpiringEndpoints">Maximum number of expiring endpoints in the summary.</param>
        public CertificateInventorySummary BuildInventorySummary(
            DateTimeOffset? sinceUtc = null,
            int expiringWithinDays = 30,
            int maxExpiringEndpoints = 200) {
            var snapshots = LoadInventorySnapshots(sinceUtc);
            return CertificateInventoryAnalyzer.BuildSummary(
                snapshots,
                expiringWithinDays,
                maxExpiringEndpoints);
        }

        /// <summary>Builds endpoint-level certificate drift history from persisted inventory snapshots.</summary>
        /// <param name="sinceUtc">Optional lower bound for snapshot capture time.</param>
        /// <param name="changedOnly">When true, only returns endpoints with observed changes.</param>
        /// <param name="maxEndpoints">Maximum number of endpoint rows returned.</param>
        /// <param name="minimumSeverity">Optional minimum drift severity filter (None, Low, Medium, High).</param>
        /// <param name="requiredChangeKinds">Optional list of required drift change kinds (certificate, issuer, expiry, service, auth-profile, chain-source).</param>
        /// <param name="changeKindMatchMode">Optional change-kind matching mode (Any or All).</param>
        public CertificateInventoryDriftSummary BuildInventoryDrift(
            DateTimeOffset? sinceUtc = null,
            bool changedOnly = false,
            int maxEndpoints = 200,
            string? minimumSeverity = null,
            IEnumerable<string>? requiredChangeKinds = null,
            string? changeKindMatchMode = null) {
            var snapshots = LoadInventorySnapshots(sinceUtc);
            return CertificateInventoryDriftAnalyzer.BuildDrift(
                snapshots,
                changedOnly,
                maxEndpoints,
                minimumSeverity,
                requiredChangeKinds,
                changeKindMatchMode);
        }

        /// <summary>Builds a point-in-time diff between two inventory snapshots.</summary>
        /// <param name="sinceUtc">Optional lower bound for snapshot capture time.</param>
        /// <param name="previousCapturedAtUtc">Optional previous snapshot timestamp selector.</param>
        /// <param name="currentCapturedAtUtc">Optional current snapshot timestamp selector.</param>
        /// <param name="includeUnchanged">When true, includes unchanged endpoints in results.</param>
        /// <param name="maxEndpoints">Maximum endpoint rows returned.</param>
        public CertificateInventoryDiffSummary BuildInventoryDiff(
            DateTimeOffset? sinceUtc = null,
            DateTimeOffset? previousCapturedAtUtc = null,
            DateTimeOffset? currentCapturedAtUtc = null,
            bool includeUnchanged = false,
            int maxEndpoints = 500) {
            var snapshots = LoadInventorySnapshots(sinceUtc);
            return CertificateInventoryDiffAnalyzer.BuildDiff(
                snapshots,
                previousCapturedAtUtc,
                currentCapturedAtUtc,
                includeUnchanged,
                maxEndpoints);
        }

        /// <summary>Builds endpoint-level certificate risk posture from persisted inventory snapshots.</summary>
        /// <param name="sinceUtc">Optional lower bound for snapshot capture time.</param>
        /// <param name="includeNoRisk">When true, includes endpoints without detected risk findings.</param>
        /// <param name="expiringWithinDays">Warning window for expiring certificates.</param>
        /// <param name="criticalExpiringWithinDays">Critical window for expiring certificates.</param>
        /// <param name="maxEndpoints">Maximum endpoint rows returned.</param>
        /// <param name="minimumSeverity">Optional minimum endpoint severity filter (None, Low, Medium, High, Critical). Applied after includeNoRisk filtering.</param>
        /// <param name="reasonContains">Optional case-insensitive reason substring filter (for example CertificateExpired, WeakKey, CtNotObserved).</param>
        /// <param name="issuerContains">Optional case-insensitive issuer/root-issuer substring filter (for example DigiCert, Let's Encrypt, ISRG).</param>
        /// <param name="authorityFamilyEquals">Optional leaf authority-family exact-match filter (for example DigiCert, LetsEncrypt).</param>
        /// <param name="rootAuthorityFamilyEquals">Optional root authority-family exact-match filter (for example DigiCert, LetsEncrypt).</param>
        /// <param name="ctSourceContains">Optional CT/discovery source substring filter (for example crt.sh, shodan, censys).</param>
        /// <param name="ctTemplateErrorContains">Optional CT template/configuration error substring filter.</param>
        /// <param name="chainSourceContains">Optional chain-source substring filter (for example tls-handshake, aia-download).</param>
        /// <param name="thumbprintEquals">Optional leaf-certificate thumbprint exact-match filter (hex string expected).</param>
        /// <param name="serverAuthOnly">When true, only returns endpoint rows whose certificate allows server authentication EKU.</param>
        /// <param name="clientAuthOnly">When true, only returns endpoint rows whose certificate allows client authentication EKU.</param>
        /// <param name="secureEmailOnly">When true, only returns endpoint rows whose certificate allows secure-email EKU.</param>
        public CertificateInventoryRiskSummary BuildInventoryRisk(
            DateTimeOffset? sinceUtc = null,
            bool includeNoRisk = false,
            int expiringWithinDays = 30,
            int criticalExpiringWithinDays = 7,
            int maxEndpoints = 300,
            string? minimumSeverity = null,
            string? reasonContains = null,
            string? issuerContains = null,
            string? authorityFamilyEquals = null,
            string? rootAuthorityFamilyEquals = null,
            string? ctSourceContains = null,
            string? ctTemplateErrorContains = null,
            string? chainSourceContains = null,
            string? thumbprintEquals = null,
            bool serverAuthOnly = false,
            bool clientAuthOnly = false,
            bool secureEmailOnly = false) {
            var snapshots = LoadInventorySnapshots(sinceUtc);
            return CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk,
                expiringWithinDays,
                criticalExpiringWithinDays,
                maxEndpoints,
                minimumSeverity,
                reasonContains,
                issuerContains,
                authorityFamilyEquals,
                rootAuthorityFamilyEquals,
                ctSourceContains,
                ctTemplateErrorContains,
                chainSourceContains,
                thumbprintEquals,
                serverAuthOnly,
                clientAuthOnly,
                secureEmailOnly);
        }

        /// <summary>Builds certificate reuse and assignment mapping from persisted inventory snapshots.</summary>
        /// <param name="sinceUtc">Optional lower bound for snapshot capture time.</param>
        /// <param name="includeSingleEndpointCertificates">When true, includes certificates used by only one endpoint.</param>
        /// <param name="minEndpointCount">Minimum endpoint count required per certificate.</param>
        /// <param name="maxCertificates">Maximum certificate rows returned.</param>
        /// <param name="maxEndpointsPerCertificate">Maximum endpoint references returned per certificate row.</param>
        public CertificateInventoryReuseSummary BuildInventoryReuse(
            DateTimeOffset? sinceUtc = null,
            bool includeSingleEndpointCertificates = false,
            int minEndpointCount = 2,
            int maxCertificates = 300,
            int maxEndpointsPerCertificate = 30) {
            var snapshots = LoadInventorySnapshots(sinceUtc);
            return CertificateInventoryReuseAnalyzer.BuildReuse(
                snapshots,
                includeSingleEndpointCertificates,
                minEndpointCount,
                maxCertificates,
                maxEndpointsPerCertificate);
        }

        /// <summary>Queries persisted inventory entries using structured filters.</summary>
        /// <param name="query">Query options.</param>
        public CertificateInventoryQueryResult QueryInventoryEntries(CertificateInventoryQuery? query = null) {
            var effectiveQuery = query ?? new CertificateInventoryQuery();
            var result = new CertificateInventoryQueryResult();
            var maxResults = Math.Max(0, effectiveQuery.MaxResults);
            var matchedEndpointKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var latestOnly = effectiveQuery.LatestPerEndpointOnly;
            var observedEndpointKeys = latestOnly
                ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                : null;
            var snapshots = LoadInventorySnapshots(effectiveQuery.SinceUtc)
                .OrderByDescending(snapshot => snapshot.CapturedAtUtc)
                .ToList();
            result.LoadedSnapshotCount = snapshots.Count;
            var now = DateTimeOffset.UtcNow;
            foreach (var snapshot in snapshots) {
                if (effectiveQuery.UntilUtc.HasValue && snapshot.CapturedAtUtc > effectiveQuery.UntilUtc.Value) {
                    result.SkippedSnapshotCountByUntilUtc++;
                    continue;
                }

                result.ScannedSnapshotCount++;
                foreach (var entry in snapshot.Entries) {
                    result.ScannedEntryCount++;
                    string? endpointKey = null;
                    if (latestOnly) {
                        var latestObservedEndpointKeys = observedEndpointKeys!;
                        endpointKey = BuildEndpointKey(entry);
                        if (!latestObservedEndpointKeys.Add(endpointKey)) {
                            result.SkippedByLatestPerEndpointCount++;
                            continue;
                        }
                    }

                    result.EvaluatedEntryCount++;
                    if (!MatchesQuery(entry, effectiveQuery, now)) {
                        result.ExcludedByFiltersCount++;
                        continue;
                    }

                    result.MatchedEntryCount++;
                    if (endpointKey == null) {
                        endpointKey = BuildEndpointKey(entry);
                    }
                    matchedEndpointKeys.Add(endpointKey);
                    IncrementMatchedBreakdown(result, entry);
                    if (result.Entries.Count >= maxResults) {
                        result.Truncated = true;
                        continue;
                    }

                    result.Entries.Add(new CertificateInventoryObservedEntry {
                        CapturedAtUtc = snapshot.CapturedAtUtc,
                        Entry = entry
                    });
                }
            }

            result.MatchedUniqueEndpointCount = matchedEndpointKeys.Count;
            result.EntriesTruncatedByMaxResults = result.MatchedEntryCount - result.Entries.Count;
            return result;
        }

        private static bool MatchesQuery(CertificateInventoryEntry entry, CertificateInventoryQuery query, DateTimeOffset now) {
            var hostContains = query.HostContains;
            if (!string.IsNullOrWhiteSpace(hostContains)) {
                var hostNeedle = hostContains!.Trim();
                var hostHaystack = entry.ResolvedHost ?? entry.Host;
                if (hostHaystack.IndexOf(hostNeedle, StringComparison.OrdinalIgnoreCase) < 0) {
                    return false;
                }
            }

            var subjectContains = query.SubjectContains;
            if (!string.IsNullOrWhiteSpace(subjectContains)) {
                var subjectNeedle = subjectContains!.Trim();
                var subjectHaystack = entry.CertificateSubject ?? string.Empty;
                if (subjectHaystack.IndexOf(subjectNeedle, StringComparison.OrdinalIgnoreCase) < 0) {
                    return false;
                }
            }

            var sanContains = query.SanContains;
            if (!string.IsNullOrWhiteSpace(sanContains)) {
                var sanNeedle = sanContains!.Trim();
                var hasMatch = entry.SubjectAlternativeNames != null &&
                               entry.SubjectAlternativeNames.Any(san => !string.IsNullOrWhiteSpace(san) &&
                                                                        san.IndexOf(sanNeedle, StringComparison.OrdinalIgnoreCase) >= 0);
                if (!hasMatch) {
                    return false;
                }
            }

            var serviceEquals = query.ServiceEquals;
            if (!string.IsNullOrWhiteSpace(serviceEquals)) {
                var expectedService = serviceEquals!.Trim();
                var actualService = string.IsNullOrWhiteSpace(entry.Service)
                    ? CertificateServiceClassifier.GuessService(entry.Scheme ?? "https", entry.Port)
                    : entry.Service ?? string.Empty;
                if (!actualService.Equals(expectedService, StringComparison.OrdinalIgnoreCase)) {
                    return false;
                }
            }

            var issuerContains = query.IssuerContains;
            if (!string.IsNullOrWhiteSpace(issuerContains)) {
                var issuerNeedle = issuerContains!.Trim();
                var issuerHaystack = entry.CertificateIssuerNormalized ?? entry.CertificateIssuerOrganization ?? entry.CertificateIssuer ?? string.Empty;
                if (issuerHaystack.IndexOf(issuerNeedle, StringComparison.OrdinalIgnoreCase) < 0) {
                    return false;
                }
            }

            var authorityFamilyEquals = query.AuthorityFamilyEquals;
            if (!string.IsNullOrWhiteSpace(authorityFamilyEquals)) {
                var expectedFamily = authorityFamilyEquals!.Trim();
                var actualFamily = entry.CertificateAuthorityFamily ?? string.Empty;
                if (!actualFamily.Equals(expectedFamily, StringComparison.OrdinalIgnoreCase)) {
                    return false;
                }
            }

            var rootContains = query.RootContains;
            if (!string.IsNullOrWhiteSpace(rootContains)) {
                var rootNeedle = rootContains!.Trim();
                var rootHaystack = entry.CertificateRootIssuerNormalized ??
                                   entry.CertificateRootIssuerOrganization ??
                                   entry.CertificateRootIssuer ??
                                   entry.CertificateRootSubject ??
                                   string.Empty;
                if (rootHaystack.IndexOf(rootNeedle, StringComparison.OrdinalIgnoreCase) < 0) {
                    return false;
                }
            }

            var rootAuthorityFamilyEquals = query.RootAuthorityFamilyEquals;
            if (!string.IsNullOrWhiteSpace(rootAuthorityFamilyEquals)) {
                var expectedRootFamily = rootAuthorityFamilyEquals!.Trim();
                var actualRootFamily = entry.CertificateRootAuthorityFamily ?? string.Empty;
                if (!actualRootFamily.Equals(expectedRootFamily, StringComparison.OrdinalIgnoreCase)) {
                    return false;
                }
            }

            var ctSourceContains = query.CtSourceContains;
            if (!string.IsNullOrWhiteSpace(ctSourceContains)) {
                var ctNeedle = ctSourceContains!.Trim();
                var hasCtMatch = entry.CtDiscoverySources != null &&
                                 entry.CtDiscoverySources.Any(source =>
                                     !string.IsNullOrWhiteSpace(source) &&
                                     source.IndexOf(ctNeedle, StringComparison.OrdinalIgnoreCase) >= 0);
                if (!hasCtMatch) {
                    return false;
                }
            }

            var ctTemplateErrorContains = query.CtTemplateErrorContains;
            if (!string.IsNullOrWhiteSpace(ctTemplateErrorContains)) {
                var ctTemplateErrorNeedle = ctTemplateErrorContains!.Trim();
                var hasTemplateErrorMatch = CertificateInventoryEntryHelpers.EnumerateCtTemplateFormatErrors(entry).Any(error =>
                    error.IndexOf(ctTemplateErrorNeedle, StringComparison.OrdinalIgnoreCase) >= 0);
                if (!hasTemplateErrorMatch) {
                    return false;
                }
            }

            var chainSourceContains = query.ChainSourceContains;
            if (!string.IsNullOrWhiteSpace(chainSourceContains)) {
                var chainNeedle = chainSourceContains!.Trim();
                var hasChainSourceMatch = CertificateInventoryEntryHelpers.EnumerateChainSources(entry).Any(source =>
                    source.IndexOf(chainNeedle, StringComparison.OrdinalIgnoreCase) >= 0);
                if (!hasChainSourceMatch) {
                    return false;
                }
            }

            var thumbprintEquals = query.ThumbprintEquals;
            if (!string.IsNullOrWhiteSpace(thumbprintEquals)) {
                var expectedThumbprint = NormalizeThumbprint(thumbprintEquals);
                var actualThumbprint = NormalizeThumbprint(entry.CertificateThumbprint);
                if (expectedThumbprint.Length == 0 || !actualThumbprint.Equals(expectedThumbprint, StringComparison.OrdinalIgnoreCase)) {
                    return false;
                }
            }

            if (query.KnownAuthorityOnly.HasValue && query.KnownAuthorityOnly.Value != entry.IsKnownCertificateAuthority) {
                return false;
            }

            if (query.KnownRootAuthorityOnly.HasValue && query.KnownRootAuthorityOnly.Value != entry.IsKnownRootCertificateAuthority) {
                return false;
            }

            if (query.ValidOnly.HasValue && query.ValidOnly.Value != entry.Valid) {
                return false;
            }

            if (query.ExpiredOnly.HasValue) {
                var isExpired = entry.NotAfterUtc.HasValue ? entry.NotAfterUtc.Value <= now : entry.Expired;
                if (query.ExpiredOnly.Value != isExpired) {
                    return false;
                }
            }

            if (query.ChainCompleteOnly.HasValue && query.ChainCompleteOnly.Value != entry.ChainComplete) {
                return false;
            }

            if (query.HostnameMatchOnly.HasValue && query.HostnameMatchOnly.Value != entry.HostnameMatch) {
                return false;
            }

            if (query.SelfSignedOnly.HasValue && query.SelfSignedOnly.Value != entry.IsSelfSigned) {
                return false;
            }

            if (query.ReachableOnly.HasValue && query.ReachableOnly.Value != entry.IsReachable) {
                return false;
            }

            if (query.PresentInCtOnly.HasValue && query.PresentInCtOnly.Value != entry.PresentInCtLogs) {
                return false;
            }

            if (query.AllowsServerAuthOnly.HasValue && query.AllowsServerAuthOnly.Value != entry.AllowsServerAuthentication) {
                return false;
            }

            if (query.AllowsClientAuthOnly.HasValue && query.AllowsClientAuthOnly.Value != entry.AllowsClientAuthentication) {
                return false;
            }

            if (query.AllowsSecureEmailOnly.HasValue && query.AllowsSecureEmailOnly.Value != entry.AllowsSecureEmail) {
                return false;
            }

            if (query.WeakKeyOnly.HasValue && query.WeakKeyOnly.Value != entry.WeakKey) {
                return false;
            }

            if (query.Sha1SignatureOnly.HasValue && query.Sha1SignatureOnly.Value != entry.Sha1Signature) {
                return false;
            }

            if (query.NotYetValidOnly.HasValue) {
                var isNotYetValid = entry.NotBeforeUtc.HasValue && entry.NotBeforeUtc.Value > now;
                if (query.NotYetValidOnly.Value != isNotYetValid) {
                    return false;
                }
            }

            var authenticationProfileEquals = query.AuthenticationProfileEquals;
            if (!string.IsNullOrWhiteSpace(authenticationProfileEquals)) {
                var expectedProfile = authenticationProfileEquals!.Trim();
                var actualProfile = CertificateInventoryEntryHelpers.ResolveAuthenticationProfile(entry);
                if (!actualProfile.Equals(expectedProfile, StringComparison.OrdinalIgnoreCase)) {
                    return false;
                }
            }

            if (query.ExpiringWithinDays.HasValue) {
                if (!entry.NotAfterUtc.HasValue) {
                    return false;
                }

                var threshold = now.AddDays(Math.Max(0, query.ExpiringWithinDays.Value));
                if (entry.NotAfterUtc.Value > threshold || entry.NotAfterUtc.Value <= now) {
                    return false;
                }
            }

            return true;
        }

        private static string NormalizeThumbprint(string? value) {
            if (string.IsNullOrWhiteSpace(value)) {
                return string.Empty;
            }

            var chars = value.Where(c => !char.IsWhiteSpace(c) && c != ':').ToArray();
            return new string(chars).Trim().ToUpperInvariant();
        }

        private static void IncrementMatchedBreakdown(CertificateInventoryQueryResult result, CertificateInventoryEntry entry) {
            var service = string.IsNullOrWhiteSpace(entry.Service)
                ? CertificateServiceClassifier.GuessService(entry.Scheme ?? "https", entry.Port)
                : entry.Service!;
            IncrementCounter(result.MatchedServiceCounts, service);
            IncrementCounter(result.MatchedIssuerCounts, PickIssuer(entry));
            IncrementCounter(result.MatchedRootIssuerCounts, PickRootIssuer(entry));
            IncrementCounter(result.MatchedAuthenticationProfileCounts, CertificateInventoryEntryHelpers.ResolveAuthenticationProfile(entry));
            IncrementCounter(result.MatchedChainSourceCounts, CertificateInventoryEntryHelpers.PickChainSource(entry));
            IncrementCtSources(result.MatchedCtSourceCounts, entry);
            IncrementCtTemplateErrorCategories(result.MatchedCtTemplateErrorCounts, entry);
        }

        private static string BuildEndpointKey(CertificateInventoryEntry entry) {
            var host = entry.ResolvedHost ?? entry.Host;
            if (string.IsNullOrWhiteSpace(host)) {
                host = "unknown-host";
            }
            var port = entry.Port;
            if (port <= 0) {
                port = 443;
            }
            return $"{host}:{port}";
        }

        private static string PickIssuer(CertificateInventoryEntry entry) {
            if (!string.IsNullOrWhiteSpace(entry.CertificateIssuerNormalized)) {
                return entry.CertificateIssuerNormalized!;
            }
            if (!string.IsNullOrWhiteSpace(entry.CertificateIssuerOrganization)) {
                return entry.CertificateIssuerOrganization!;
            }
            if (!string.IsNullOrWhiteSpace(entry.CertificateIssuer)) {
                return CertificateIssuerClassifier.Classify(entry.CertificateIssuer).NormalizedName;
            }
            return "Unknown";
        }

        private static string PickRootIssuer(CertificateInventoryEntry entry) {
            if (!string.IsNullOrWhiteSpace(entry.CertificateRootIssuerNormalized)) {
                return entry.CertificateRootIssuerNormalized!;
            }
            if (!string.IsNullOrWhiteSpace(entry.CertificateRootIssuerOrganization)) {
                return entry.CertificateRootIssuerOrganization!;
            }
            if (!string.IsNullOrWhiteSpace(entry.CertificateRootIssuer)) {
                return CertificateIssuerClassifier.Classify(entry.CertificateRootIssuer).NormalizedName;
            }
            return "Unknown";
        }

        private static void IncrementCounter(Dictionary<string, int> counters, string key) {
            if (string.IsNullOrWhiteSpace(key)) {
                key = "Unknown";
            }

            counters[key] = counters.TryGetValue(key, out var count) ? count + 1 : 1;
        }

        private static void IncrementCtSources(Dictionary<string, int> counters, CertificateInventoryEntry entry) {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (entry.CtDiscoverySources != null) {
                foreach (var source in entry.CtDiscoverySources) {
                    if (string.IsNullOrWhiteSpace(source)) {
                        continue;
                    }

                    var normalized = source.Trim();
                    if (seen.Add(normalized)) {
                        IncrementCounter(counters, normalized);
                    }
                }
            }

            if (seen.Count == 0) {
                IncrementCounter(counters, "none");
            }
        }

        private static void IncrementCtTemplateErrorCategories(Dictionary<string, int> counters, CertificateInventoryEntry entry) {
            foreach (var error in CertificateInventoryEntryHelpers.EnumerateCtTemplateFormatErrors(entry)) {
                IncrementCounter(counters, ExtractCtTemplateErrorCategory(error));
            }
        }

        private static string ExtractCtTemplateErrorCategory(string error) {
            if (string.IsNullOrWhiteSpace(error)) {
                return "Unknown";
            }

            var separatorIndex = error.IndexOf(':');
            if (separatorIndex <= 0) {
                return "Unknown";
            }

            var category = error.Substring(0, separatorIndex).Trim();
            return string.IsNullOrWhiteSpace(category) ? "Unknown" : category;
        }

        /// <summary>Disposes timer resources.</summary>
        public void Dispose() {
            Stop();
        }
    }
}
