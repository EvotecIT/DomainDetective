using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Net;
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
    public partial class CertificateMonitor : IDisposable {
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
            /// <summary>Actual remote address reached by the probe, when observable.</summary>
            public IPAddress? RemoteAddress { get; init; }
            /// <summary>UTC time when this endpoint probe completed.</summary>
            public DateTimeOffset ObservedAtUtc { get; init; }
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

                        DateTimeOffset observedAtUtc = DateTimeOffset.UtcNow;
                        entries[index] = new Entry {
                            Host = host,
                            Url = target.Url,
                            ResolvedHost = target.Host,
                            Scheme = target.Scheme,
                            Port = target.Port,
                            Service = target.Service,
                            RemoteAddress = analysis.RemoteAddress,
                            ObservedAtUtc = observedAtUtc,
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
        /// <param name="untilUtc">Optional upper bound for snapshot capture time.</param>
        /// <param name="maxSnapshots">Optional maximum number of snapshots to return (latest N).</param>
        /// <param name="latestOnly">When true, returns only the latest available snapshot after filtering.</param>
        public IReadOnlyList<CertificateInventorySnapshot> LoadInventorySnapshots(
            DateTimeOffset? sinceUtc = null,
            DateTimeOffset? untilUtc = null,
            int maxSnapshots = 0,
            bool latestOnly = false) {
            if (sinceUtc.HasValue && untilUtc.HasValue && sinceUtc.Value > untilUtc.Value) {
                return Array.Empty<CertificateInventorySnapshot>();
            }
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
                    if (untilUtc.HasValue && snapshot.CapturedAtUtc > untilUtc.Value) {
                        continue;
                    }
                    snapshots.Add(snapshot);
                } catch {
                    // ignore invalid inventory files
                }
            }

            var ordered = snapshots
                .OrderBy(snapshot => snapshot.CapturedAtUtc)
                .ToList();
            if (ordered.Count == 0) {
                return ordered;
            }

            if (latestOnly) {
                return new[] { ordered[ordered.Count - 1] };
            }

            if (maxSnapshots > 0 && ordered.Count > maxSnapshots) {
                ordered = ordered.Skip(ordered.Count - maxSnapshots).ToList();
            }

            return ordered;
        }

        private void SaveInventorySnapshot(int port, InternalLogger? logger) {
            var snapshot = new CertificateInventorySnapshot {
                CapturedAtUtc = DateTimeOffset.UtcNow,
                Port = port
            };
            foreach (var entry in Results) {
                snapshot.Entries.Add(ToInventoryEntry(entry));
            }
            SaveInventorySnapshot(snapshot, logger);
        }

        /// <summary>Persists the provided inventory snapshot to disk.</summary>
        /// <param name="snapshot">Snapshot to persist.</param>
        /// <param name="logger">Optional logger for non-terminating persistence errors.</param>
        /// <returns>Absolute path of the saved snapshot file, or an empty string when persistence fails.</returns>
        public string SaveInventorySnapshot(CertificateInventorySnapshot snapshot, InternalLogger? logger = null) {
            if (snapshot == null) {
                throw new ArgumentNullException(nameof(snapshot));
            }
            if (snapshot.CapturedAtUtc == default) {
                snapshot.CapturedAtUtc = DateTimeOffset.UtcNow;
            }

            try {
                Directory.CreateDirectory(InventoryDirectory);
                var effectivePort = snapshot.Port;
                var fileName = $"{snapshot.CapturedAtUtc:yyyyMMddTHHmmssfffffffZ}_{effectivePort}.json";
                var filePath = Path.Combine(InventoryDirectory, fileName);
                var json = JsonSerializer.Serialize(snapshot, JsonOptions.Default);
                File.WriteAllText(filePath, json, Encoding.UTF8);
                return filePath;
            } catch (Exception ex) {
                logger?.WriteWarning("Failed to persist certificate inventory snapshot: {0}", ex.Message);
                return string.Empty;
            }
        }

        /// <summary>Converts this value to inventory entry.</summary>
        public static CertificateInventoryEntry ToInventoryEntry(Entry entry) {
            var analysis = entry.Analysis;
            var certificate = analysis.Certificate;
            var hasLiveCertificateEvidence = HasLiveCertificateEvidence(analysis, certificate);
            var issuerIdentity = CertificateIssuerClassifier.Classify(certificate);
            var chain = analysis.Chain != null && analysis.Chain.Count > 0
                ? analysis.Chain
                : (certificate != null ? new List<X509Certificate2> { certificate } : new List<X509Certificate2>());
            var root = chain.Count > 0 ? chain[chain.Count - 1] : null;
            var rootIdentity = CertificateIssuerClassifier.Classify(root);
            var failureReason = hasLiveCertificateEvidence ? null : analysis.FailureReason;
            var failureKind = hasLiveCertificateEvidence
                ? CertificateFailureKind.None
                : (analysis.FailureKind != CertificateFailureKind.None
                    ? analysis.FailureKind
                    : CertificateFailureClassifier.ClassifyFailureReason(analysis.FailureReason));
            var snapshotEntry = new CertificateInventoryEntry {
                Host = entry.Host,
                ResolvedHost = entry.ResolvedHost,
                Url = string.IsNullOrWhiteSpace(entry.Url) ? analysis.Url : entry.Url,
                Scheme = entry.Scheme,
                Port = entry.Port,
                Service = entry.Service,
                RemoteAddress = entry.RemoteAddress?.ToString(),
                RemoteAddressFamily = entry.RemoteAddress?.AddressFamily.ToString(),
                ObservedAtUtc = entry.ObservedAtUtc == default ? null : entry.ObservedAtUtc,
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
                IsReachable = analysis.IsReachable || hasLiveCertificateEvidence,
                FailureReason = failureReason,
                FailureKind = failureKind,
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
            snapshotEntry.RedirectTargets = analysis.RedirectTargets.ToArray();
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

        private static bool HasLiveCertificateEvidence(CertificateAnalysis analysis, X509Certificate2? certificate) {
            if (analysis == null) {
                return false;
            }

            return certificate != null ||
                   !string.IsNullOrWhiteSpace(analysis.Subject) ||
                   analysis.Chain.Count > 0;
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
            var allSnapshots = LoadInventorySnapshots();
            var snapshots = allSnapshots;
            if (sinceUtc.HasValue) {
                snapshots = allSnapshots
                    .Where(snapshot => snapshot.CapturedAtUtc >= sinceUtc.Value)
                    .ToList();
            }

            var summary = CertificateInventoryDiffAnalyzer.BuildDiff(
                snapshots,
                previousCapturedAtUtc,
                currentCapturedAtUtc,
                includeUnchanged,
                maxEndpoints);
            AppendDiffSinceUtcSelectorWarnings(summary, allSnapshots, sinceUtc, previousCapturedAtUtc, currentCapturedAtUtc);
            return summary;
        }

        private static void AppendDiffSinceUtcSelectorWarnings(
            CertificateInventoryDiffSummary summary,
            IReadOnlyList<CertificateInventorySnapshot> allSnapshots,
            DateTimeOffset? sinceUtc,
            DateTimeOffset? previousCapturedAtUtc,
            DateTimeOffset? currentCapturedAtUtc) {
            if (!sinceUtc.HasValue) {
                return;
            }

            if (!previousCapturedAtUtc.HasValue && !currentCapturedAtUtc.HasValue) {
                return;
            }

            if (allSnapshots.Count == 0) {
                return;
            }

            var sinceCutoff = sinceUtc.Value;
            if (previousCapturedAtUtc.HasValue) {
                var fullPrevious = ResolveSnapshotAtOrBefore(allSnapshots, previousCapturedAtUtc.Value);
                if (fullPrevious != null &&
                    fullPrevious.CapturedAtUtc < sinceCutoff &&
                    (!summary.PreviousCapturedAtUtc.HasValue || summary.PreviousCapturedAtUtc.Value != fullPrevious.CapturedAtUtc)) {
                    var warning = string.Format(
                        "Requested previous snapshot at or before {0:yyyy-MM-dd HH:mm:ss} UTC resolves to {1:yyyy-MM-dd HH:mm:ss} UTC, but --since-utc ({2:yyyy-MM-dd HH:mm:ss} UTC) excluded it.",
                        previousCapturedAtUtc.Value.UtcDateTime,
                        fullPrevious.CapturedAtUtc.UtcDateTime,
                        sinceCutoff.UtcDateTime);
                    ReplaceDiffWarningIfMissing(
                        summary,
                        string.Format("Requested previous snapshot at or before {0:yyyy-MM-dd HH:mm:ss} UTC", previousCapturedAtUtc.Value.UtcDateTime),
                        warning);
                }
            }

            if (currentCapturedAtUtc.HasValue) {
                var fullCurrent = ResolveSnapshotAtOrBefore(allSnapshots, currentCapturedAtUtc.Value);
                if (fullCurrent != null &&
                    fullCurrent.CapturedAtUtc < sinceCutoff &&
                    (!summary.CurrentCapturedAtUtc.HasValue || summary.CurrentCapturedAtUtc.Value != fullCurrent.CapturedAtUtc)) {
                    var warning = string.Format(
                        "Requested current snapshot at or before {0:yyyy-MM-dd HH:mm:ss} UTC resolves to {1:yyyy-MM-dd HH:mm:ss} UTC, but --since-utc ({2:yyyy-MM-dd HH:mm:ss} UTC) excluded it.",
                        currentCapturedAtUtc.Value.UtcDateTime,
                        fullCurrent.CapturedAtUtc.UtcDateTime,
                        sinceCutoff.UtcDateTime);
                    ReplaceDiffWarningIfMissing(
                        summary,
                        string.Format("Requested current snapshot at or before {0:yyyy-MM-dd HH:mm:ss} UTC", currentCapturedAtUtc.Value.UtcDateTime),
                        warning);
                }
            }
        }

        private static void ReplaceDiffWarningIfMissing(
            CertificateInventoryDiffSummary summary,
            string warningPrefix,
            string warning) {
            if (!string.IsNullOrWhiteSpace(warningPrefix)) {
                for (var i = summary.Warnings.Count - 1; i >= 0; i--) {
                    var existing = summary.Warnings[i];
                    if (!string.IsNullOrWhiteSpace(existing) &&
                        existing.StartsWith(warningPrefix, StringComparison.OrdinalIgnoreCase)) {
                        summary.Warnings.RemoveAt(i);
                    }
                }
            }

            AddDiffWarningIfMissing(summary, warning);
        }

        private static void AddDiffWarningIfMissing(CertificateInventoryDiffSummary summary, string warning) {
            if (string.IsNullOrWhiteSpace(warning)) {
                return;
            }

            foreach (var existing in summary.Warnings) {
                if (string.Equals(existing, warning, StringComparison.OrdinalIgnoreCase)) {
                    return;
                }
            }

            summary.Warnings.Add(warning);
        }

    }
}
