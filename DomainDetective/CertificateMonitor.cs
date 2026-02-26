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
        public Func<string, int, InternalLogger, CancellationToken, Task<CertificateAnalysis>>? AnalysisOverride { private get; set; }
        private IReadOnlyList<string> _monitorHosts = Array.Empty<string>();
        private int _monitorPort;
        private InternalLogger? _monitorLogger;

        /// <summary>Directory used to cache certificate data.</summary>
        public string CacheDirectory { get; set; } =
            Path.Combine(Path.GetTempPath(), "DomainDetective", "cert-monitor");

        /// <summary>Duration cached files are kept.</summary>
        public TimeSpan CacheRetention { get; set; } = TimeSpan.FromDays(7);
        /// <summary>Persist monitor runs as inventory snapshots.</summary>
        public bool PersistInventorySnapshots { get; set; } = true;

        /// <summary>Directory used for persisted inventory snapshots.</summary>
        public string InventoryDirectory => Path.Combine(CacheDirectory, "inventory");

        private void CleanExpiredCacheEntries() {
            try {
                if (!Directory.Exists(CacheDirectory)) {
                    return;
                }

                foreach (var file in Directory.GetFiles(CacheDirectory, "*", SearchOption.AllDirectories)) {
                    if (DateTime.UtcNow - File.GetLastWriteTimeUtc(file) > CacheRetention) {
                        File.Delete(file);
                    }
                }

                foreach (var directory in Directory.GetDirectories(CacheDirectory, "*", SearchOption.AllDirectories)
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
                using var gate = new SemaphoreSlim(parallelism, parallelism);
                var tasks = new List<Task>(list.Count);
                for (var i = 0; i < list.Count; i++) {
                    cancellationToken.ThrowIfCancellationRequested();
                    var index = i;
                    var host = list[index];
                    await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
                    tasks.Add(Task.Run(async () => {
                        try {
                            CertificateServiceDescriptor target;
                            try {
                                target = CertificateServiceClassifier.Resolve(host, port);
                            } catch {
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
                    }, cancellationToken));
                }

                await Task.WhenAll(tasks).ConfigureAwait(false);
                foreach (var entry in entries) {
                    if (entry != null) {
                        Results.Add(entry);
                    }
                }
            }

            if (PersistInventorySnapshots) {
                SaveInventorySnapshot(port);
            }
        }

        /// <summary>Number of hosts with valid certificates.</summary>
        public int ValidCount => Results.Count(e => e.Valid && !e.Expired);
        /// <summary>Number of hosts with certificates expiring soon.</summary>
        public int ExpiringCount => Results.Count(e => e.Valid && !e.Expired && (e.ExpiryDate - DateTime.Now).TotalDays <= ExpiryWarningDays);
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

            var files = Directory.GetFiles(InventoryDirectory, "*.json", SearchOption.TopDirectoryOnly)
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                .ToList();

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

            return snapshots;
        }

        private void SaveInventorySnapshot(int port) {
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
            } catch {
                // best effort persistence; monitoring should continue even when disk writes fail
            }
        }

        private static CertificateInventoryEntry ToInventoryEntry(Entry entry) {
            var analysis = entry.Analysis;
            var certificate = analysis.Certificate;
            var issuerIdentity = CertificateIssuerClassifier.Classify(certificate);
            var snapshotEntry = new CertificateInventoryEntry {
                Host = entry.Host,
                ResolvedHost = entry.ResolvedHost,
                Url = string.IsNullOrWhiteSpace(entry.Url) ? analysis.Url : entry.Url,
                Scheme = entry.Scheme,
                Port = entry.Port,
                Service = entry.Service,
                CertificateSubject = certificate?.Subject,
                CertificateIssuer = certificate?.Issuer,
                CertificateIssuerOrganization = issuerIdentity.Organization,
                CertificateIssuerNormalized = issuerIdentity.NormalizedName,
                CertificateAuthorityFamily = issuerIdentity.AuthorityFamily,
                IsKnownCertificateAuthority = issuerIdentity.IsKnownAuthority,
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
                HasAnyExtendedKeyUsage = analysis.HasAnyExtendedKeyUsage,
                AllowsServerAuthentication = analysis.AllowsServerAuthentication,
                AllowsClientAuthentication = analysis.AllowsClientAuthentication,
                AllowsSecureEmail = analysis.AllowsSecureEmail
            };
            snapshotEntry.ExtendedKeyUsageOids.AddRange(analysis.ExtendedKeyUsageOids);
            snapshotEntry.SubjectAlternativeNames.AddRange(analysis.SubjectAlternativeNames);
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

        /// <summary>Queries persisted inventory entries using structured filters.</summary>
        /// <param name="query">Query options.</param>
        public CertificateInventoryQueryResult QueryInventoryEntries(CertificateInventoryQuery? query = null) {
            var effectiveQuery = query ?? new CertificateInventoryQuery();
            var result = new CertificateInventoryQueryResult();
            var snapshots = LoadInventorySnapshots(effectiveQuery.SinceUtc)
                .OrderByDescending(snapshot => snapshot.CapturedAtUtc)
                .ToList();
            var now = DateTimeOffset.UtcNow;
            foreach (var snapshot in snapshots) {
                if (effectiveQuery.UntilUtc.HasValue && snapshot.CapturedAtUtc > effectiveQuery.UntilUtc.Value) {
                    continue;
                }

                result.ScannedSnapshotCount++;
                foreach (var entry in snapshot.Entries) {
                    result.ScannedEntryCount++;
                    if (!MatchesQuery(entry, effectiveQuery, now)) {
                        continue;
                    }

                    result.MatchedEntryCount++;
                    if (result.Entries.Count >= Math.Max(0, effectiveQuery.MaxResults)) {
                        result.Truncated = true;
                        return result;
                    }

                    result.Entries.Add(new CertificateInventoryObservedEntry {
                        CapturedAtUtc = snapshot.CapturedAtUtc,
                        Entry = entry
                    });
                }
            }

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

            if (query.KnownAuthorityOnly.HasValue && query.KnownAuthorityOnly.Value && !entry.IsKnownCertificateAuthority) {
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

        /// <summary>Disposes timer resources.</summary>
        public void Dispose() {
            Stop();
        }
    }
}
