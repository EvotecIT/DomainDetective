using DnsClientX;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;

namespace DomainDetective;

public sealed partial class CertificateInventoryCapture {
    private static async Task<IReadOnlyList<SubdomainDiscoveryEntry>> DiscoverCtSubdomainsAsync(
        IReadOnlyList<CertificateInventorySeed> seeds,
        CertificateInventoryCaptureOptions options,
        List<string> warnings,
        List<string> nativeCtLogDiagnostics,
        List<NativeCtLogDiagnosticEntry> nativeCtLogDiagnosticEntries,
        List<PassiveCtDiagnosticEntry> passiveCtDiagnosticEntries,
        InternalLogger logger,
        CancellationToken cancellationToken) {
        if (seeds == null || seeds.Count == 0 || !options.IncludeCtDiscoveredSubdomains) {
            return Array.Empty<SubdomainDiscoveryEntry>();
        }

        var domains = seeds
            .Select(static seed => seed.Name)
            .Where(static name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (domains.Count == 0) {
            return Array.Empty<SubdomainDiscoveryEntry>();
        }

        var exactHostSeeds = new HashSet<string>(
            seeds.Where(static seed => seed.IsExactHostSeed).Select(static seed => seed.Name),
            StringComparer.OrdinalIgnoreCase);

        bool allowPassiveCtFallback = ShouldAllowPassiveCtFallback(options);

        if (options.EnableNativeCtLogSubdomainSource &&
            options.EnableNativeCtSharedIngestion &&
            domains.Count > 1) {
            logger.WriteVerbose("Using shared native CT ingestion for {0} domain(s).", domains.Count);
            IReadOnlyList<SubdomainDiscoveryEntry> nativeSharedDiscovered = await DiscoverCtSubdomainsNativeSharedAsync(
                domains,
                exactHostSeeds,
                options,
                warnings,
                nativeCtLogDiagnostics,
                nativeCtLogDiagnosticEntries,
                logger,
                cancellationToken).ConfigureAwait(false);

            if (nativeSharedDiscovered.Count == 0 && allowPassiveCtFallback) {
                warnings.Add("Native CT shared ingestion returned no subdomains; falling back to passive CT APIs.");
                logger.WriteVerbose(
                    "Shared native CT ingestion returned 0 subdomains for {0} domain(s). Falling back to passive CT APIs.",
                    domains.Count);
                IReadOnlyList<SubdomainDiscoveryEntry> passiveDiscovered = await DiscoverCtSubdomainsPassiveAsync(
                    domains,
                    options,
                    warnings,
                    passiveCtDiagnosticEntries,
                    logger,
                    cancellationToken).ConfigureAwait(false);
                if (passiveDiscovered.Count > 0) {
                    var mergedFallback = new Dictionary<string, SubdomainDiscoveryEntry>(StringComparer.OrdinalIgnoreCase);
                    foreach (var entry in nativeSharedDiscovered) {
                        MergeCtSubdomainEntry(mergedFallback, entry);
                    }
                    foreach (var entry in passiveDiscovered) {
                        MergeCtSubdomainEntry(mergedFallback, entry);
                    }
                    return mergedFallback.Values
                        .OrderBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
                        .ToList();
                }
            }

            return nativeSharedDiscovered;
        }

        var discovered = new Dictionary<string, SubdomainDiscoveryEntry>(StringComparer.OrdinalIgnoreCase);
        var warningLock = new object();
        var diagnosticsLock = new object();
        var diagnosticEntriesLock = new object();
        var passiveDiagnosticsLock = new object();
        var discoveredLock = new object();
        var passiveRunWarningKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var discoveredByDomain = new ConcurrentDictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var maxParallelism = ResolvePassiveCtNetworkParallelism(
            options.DiscoveryParallelism,
            options.PassiveCtParallelism,
            domains.Count);
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
                    var discoveredForDomain = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    var analysis = new SubdomainsAnalysis {
                        DnsConfiguration = new DnsConfiguration {
                            DnsEndpoint = options.DnsEndpoint
                        },
                        VerifyStillResolves = options.VerifyCtDiscoveredSubdomains,
                        DetectSensitiveSubdomains = false,
                        ScanSensitiveSubdomainTxt = false,
                        DetectAiInfrastructureExposure = false,
                        PassiveCtRequestTimeout = options.PassiveCtRequestTimeout,
                        PassiveCtRetryCount = options.PassiveCtRetryCount,
                        PassiveCtRetryBaseDelay = options.PassiveCtRetryBaseDelay,
                        PassiveCtRetryMaxDelay = options.PassiveCtRetryMaxDelay,
                        PassiveCtSourceCooldown = options.PassiveCtSourceCooldown,
                        EnableNativeCtLogSource = options.EnableNativeCtLogSubdomainSource,
                        NativeCtLogOnly = options.NativeCtLogOnly || !allowPassiveCtFallback,
                        NativeCtLogListUrl = options.NativeCtLogListUrl,
                        NativeCtMaxLogs = options.NativeCtMaxLogs,
                        NativeCtMaxEntriesPerLog = options.NativeCtMaxEntriesPerLog,
                        NativeCtEntryBatchSize = options.NativeCtEntryBatchSize,
                        NativeCtInitialBackfillEntriesPerLog = options.NativeCtInitialBackfillEntriesPerLog,
                        NativeCtCursorStatePath = nativeCtCursorStatePath,
                        NativeCtIncludePendingLogs = options.NativeCtIncludePendingLogs,
                        NativeCtIncludeRetiredLogs = options.NativeCtIncludeRetiredLogs,
                        NativeCtRequestDelay = options.NativeCtRequestDelay,
                        NativeCtRequestTimeout = options.NativeCtRequestTimeout,
                        NativeCtRetryCount = options.NativeCtRetryCount,
                        NativeCtRetryBaseDelay = options.NativeCtRetryBaseDelay,
                        NativeCtRetryMaxDelay = options.NativeCtRetryMaxDelay,
                        NativeCtCircuitBreakerFailureThreshold = options.NativeCtCircuitBreakerFailureThreshold,
                        NativeCtCircuitBreakerDuration = options.NativeCtCircuitBreakerDuration,
                        NativeCtEnableCatchUpMode = options.NativeCtEnableCatchUpMode,
                        NativeCtCatchUpLagThreshold = options.NativeCtCatchUpLagThreshold,
                        NativeCtCatchUpMaxEntriesPerLog = options.NativeCtCatchUpMaxEntriesPerLog,
                        NativeCtCatchUpBatchSize = options.NativeCtCatchUpBatchSize,
                        NativeCtExactMatchOnly = exactHostSeeds.Contains(domain),
                        NativeCtPrioritizeLatestExactMatch = exactHostSeeds.Contains(domain),
                        NativeCtStopAfterMatchedObservations = exactHostSeeds.Contains(domain) ? 1 : 0
                    };
                    if (options.NativeCtLogUrls != null && options.NativeCtLogUrls.Count > 0) {
                        foreach (var logUrl in options.NativeCtLogUrls) {
                            if (!string.IsNullOrWhiteSpace(logUrl)) {
                                analysis.NativeCtLogUrls.Add(logUrl.Trim());
                            }
                        }
                    }
                    if (options.NativeCtPreferredLogUrlPrefixes != null && options.NativeCtPreferredLogUrlPrefixes.Count > 0) {
                        foreach (var prefix in options.NativeCtPreferredLogUrlPrefixes) {
                            if (!string.IsNullOrWhiteSpace(prefix)) {
                                analysis.NativeCtPreferredLogUrlPrefixes.Add(prefix.Trim());
                            }
                        }
                    }
                    if (options.NativeCtExcludedLogUrlPrefixes != null && options.NativeCtExcludedLogUrlPrefixes.Count > 0) {
                        foreach (var prefix in options.NativeCtExcludedLogUrlPrefixes) {
                            if (!string.IsNullOrWhiteSpace(prefix)) {
                                analysis.NativeCtExcludedLogUrlPrefixes.Add(prefix.Trim());
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
                    if (analysis.PassiveCtWarnings != null && analysis.PassiveCtWarnings.Count > 0) {
                        lock (warningLock) {
                            foreach (string warning in analysis.PassiveCtWarnings) {
                                string? formattedWarning = FormatPassiveCtWarningForCaptureRun(
                                    domain,
                                    warning,
                                    passiveRunWarningKeys);
                                if (formattedWarning is { Length: > 0 }) {
                                    warnings.Add(formattedWarning);
                                }
                            }
                        }
                    }
                    if (analysis.NativeCtLogDiagnostics != null && analysis.NativeCtLogDiagnostics.Count > 0) {
                        lock (diagnosticsLock) {
                            foreach (var diagnostic in analysis.NativeCtLogDiagnostics) {
                                if (!string.IsNullOrWhiteSpace(diagnostic)) {
                                    nativeCtLogDiagnostics.Add(diagnostic);
                                }
                            }
                        }
                    }
                    if (analysis.NativeCtLogDiagnosticEntries != null && analysis.NativeCtLogDiagnosticEntries.Count > 0) {
                        lock (diagnosticEntriesLock) {
                            foreach (var diagnosticEntry in analysis.NativeCtLogDiagnosticEntries) {
                                if (diagnosticEntry != null) {
                                    nativeCtLogDiagnosticEntries.Add(CloneNativeCtLogDiagnosticEntry(diagnosticEntry));
                                }
                            }
                        }
                    }
                    if (analysis.PassiveCtDiagnosticEntries != null && analysis.PassiveCtDiagnosticEntries.Count > 0) {
                        lock (passiveDiagnosticsLock) {
                            foreach (PassiveCtDiagnosticEntry diagnosticEntry in analysis.PassiveCtDiagnosticEntries) {
                                if (diagnosticEntry != null) {
                                    passiveCtDiagnosticEntries.Add(ClonePassiveCtDiagnosticEntry(diagnosticEntry));
                                }
                            }
                        }
                    }
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
                            MergeCtSubdomainEntry(discovered, candidate);
                        }
                        discoveredForDomain.Add(candidate.Name);
                    }
                    discoveredByDomain[domain] = discoveredForDomain.Count;
                } catch (Exception ex) {
                    discoveredByDomain[domain] = 0;
                    lock (warningLock) {
                        warnings.Add($"CT subdomain discovery failed for {domain}: {ex.Message}");
                    }
                } finally {
                    gate.Release();
                }
            }, cancellationToken));
        }

        await Task.WhenAll(tasks).ConfigureAwait(false);
        if (options.EnableNativeCtLogSubdomainSource && allowPassiveCtFallback) {
            var fallbackDomains = new List<string>(domains.Count);
            foreach (var domain in domains) {
                if (!discoveredByDomain.TryGetValue(domain, out var discoveredCount) || discoveredCount <= 0) {
                    fallbackDomains.Add(domain);
                }
            }

            if (fallbackDomains.Count > 0) {
                warnings.Add(
                    "Native CT ingestion returned no subdomains for " +
                    fallbackDomains.Count.ToString(CultureInfo.InvariantCulture) +
                    " domain(s); attempting passive CT fallback.");
                logger.WriteVerbose(
                    "Native CT returned no subdomains for {0} domain(s). Falling back to passive CT APIs for those domains.",
                    fallbackDomains.Count);
                IReadOnlyList<SubdomainDiscoveryEntry> passiveDiscovered = await DiscoverCtSubdomainsPassiveAsync(
                    fallbackDomains,
                    options,
                    warnings,
                    passiveCtDiagnosticEntries,
                    logger,
                    cancellationToken).ConfigureAwait(false);
                foreach (var subdomain in passiveDiscovered) {
                    MergeCtSubdomainEntry(discovered, subdomain);
                }
            }
        }

        return discovered.Values
            .OrderBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static async Task<IReadOnlyList<SubdomainDiscoveryEntry>> DiscoverCtSubdomainsNativeSharedAsync(
        IReadOnlyList<string> domains,
        IReadOnlyCollection<string> exactHostSeeds,
        CertificateInventoryCaptureOptions options,
        List<string> warnings,
        List<string> nativeCtLogDiagnostics,
        List<NativeCtLogDiagnosticEntry> nativeCtLogDiagnosticEntries,
        InternalLogger logger,
        CancellationToken cancellationToken) {
        var nativeCtCursorStatePath = options.NativeCtCursorStatePath;
        if (string.IsNullOrWhiteSpace(nativeCtCursorStatePath)) {
            nativeCtCursorStatePath = System.IO.Path.Combine(options.CacheDirectory, "inventory", "ct-native-cursor.json");
        }

        var source = new NativeCtLogSubdomainDiscovery();
        var effectiveMaxRows = ComputeNativeSharedMaxRows(
            domains.Count,
            options.MaxCtRowsPerDomain,
            options.NativeCtSharedMaxRowsTotal);
        var effectiveMaxSubdomains = ComputeNativeSharedMaxSubdomains(
            domains.Count,
            options.MaxCtSubdomainsPerDomain,
            options.NativeCtSharedMaxSubdomainsTotal);
        var sourceOptions = new NativeCtLogSubdomainDiscoveryOptions {
            BaseDomain = domains[0],
            MaxCtRowsToProcess = effectiveMaxRows,
            MaxSubdomains = effectiveMaxSubdomains,
            LogListUrl = options.NativeCtLogListUrl,
            ExplicitLogUrls = options.NativeCtLogUrls.ToList(),
            PreferredLogUrlPrefixes = options.NativeCtPreferredLogUrlPrefixes.ToList(),
            ExcludedLogUrlPrefixes = options.NativeCtExcludedLogUrlPrefixes.ToList(),
            MaxLogsToProcess = options.NativeCtMaxLogs,
            MaxConcurrentLogs = options.DiscoveryParallelism <= 0
                ? 1
                : (options.NativeCtMaxLogs > 0
                    ? Math.Min(options.DiscoveryParallelism, options.NativeCtMaxLogs)
                    : options.DiscoveryParallelism),
            MaxEntriesPerLog = options.NativeCtMaxEntriesPerLog,
            EntryBatchSize = options.NativeCtEntryBatchSize,
            InitialBackfillEntriesPerLog = options.NativeCtInitialBackfillEntriesPerLog,
            CursorStatePath = nativeCtCursorStatePath,
            IncludePendingLogs = options.NativeCtIncludePendingLogs,
            IncludeRetiredLogs = options.NativeCtIncludeRetiredLogs,
            RequestDelay = options.NativeCtRequestDelay,
            RequestTimeout = options.NativeCtRequestTimeout,
            RetryCount = options.NativeCtRetryCount,
            RetryBaseDelay = options.NativeCtRetryBaseDelay,
            RetryMaxDelay = options.NativeCtRetryMaxDelay,
            CircuitBreakerFailureThreshold = options.NativeCtCircuitBreakerFailureThreshold,
            CircuitBreakerDuration = options.NativeCtCircuitBreakerDuration,
            EnableCatchUpMode = options.NativeCtEnableCatchUpMode,
            CatchUpLagThreshold = options.NativeCtCatchUpLagThreshold,
            CatchUpMaxEntriesPerLog = options.NativeCtCatchUpMaxEntriesPerLog,
            CatchUpBatchSize = options.NativeCtCatchUpBatchSize,
            ExactMatchDomains = exactHostSeeds?
                .Where(static name => !string.IsNullOrWhiteSpace(name))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList() ?? new List<string>()
        };

        var batchResult = await source.DiscoverForDomainsAsync(domains, sourceOptions, logger, cancellationToken).ConfigureAwait(false);
        foreach (var warning in batchResult.Warnings) {
            warnings.Add(warning);
        }
        foreach (var status in batchResult.LogStatuses) {
            var entry = BuildNativeCtLogDiagnosticEntry(status, domains);
            if (entry == null) {
                continue;
            }

            nativeCtLogDiagnosticEntries.Add(entry);
            var line = FormatNativeCtLogDiagnostic(entry);
            if (!string.IsNullOrWhiteSpace(line)) {
                nativeCtLogDiagnostics.Add(line!);
            }
        }

        if (!batchResult.SourceSucceeded && !batchResult.ResultsCapped) {
            warnings.Add("Native CT shared ingestion did not return successful CT log responses.");
        }
        if (batchResult.ResultsCapped) {
            warnings.Add("Native CT shared ingestion reached configured caps.");
        }

        var discovered = new Dictionary<string, SubdomainDiscoveryEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var domain in domains) {
            if (!batchResult.SubdomainsByDomain.TryGetValue(domain, out var entries)) {
                continue;
            }

            foreach (var pair in entries) {
                MergeCtSubdomainEntry(discovered, CreateNativeCtDiscoveredEntry(pair.Key, pair.Value));
            }
        }

        if (!options.VerifyCtDiscoveredSubdomains || discovered.Count == 0) {
            return discovered.Values
                .OrderBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        var verifyCap = ComputeVerifyCap(domains.Count, options.MaxCtSubdomainsPerDomain, discovered.Count);
        var namesToVerify = discovered
            .Keys
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .Take(verifyCap)
            .ToList();
        if (verifyCap < discovered.Count) {
            warnings.Add($"CT subdomain DNS verification capped at {verifyCap} host(s) during shared native ingestion.");
        }

        var resolved = await VerifyDiscoveredSubdomainsResolveAsync(namesToVerify, options, cancellationToken).ConfigureAwait(false);
        var namesVerified = new HashSet<string>(namesToVerify, StringComparer.OrdinalIgnoreCase);
        var resolvedEntries = new List<SubdomainDiscoveryEntry>(discovered.Count);
        foreach (var pair in discovered.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)) {
            SubdomainDiscoveryEntry entry = pair.Value;
            bool wasVerified = namesVerified.Contains(pair.Key);
            bool resolvedNow = resolved.Contains(pair.Key);
            SubdomainResolutionStatus resolutionStatus = resolvedNow
                ? SubdomainResolutionStatus.Resolves
                : (wasVerified ? SubdomainResolutionStatus.DoesNotResolve : entry.ResolutionStatus);
            if (resolutionStatus == SubdomainResolutionStatus.DoesNotResolve) {
                continue;
            }

            resolvedEntries.Add(new SubdomainDiscoveryEntry {
                Name = entry.Name,
                FirstSeenUtc = entry.FirstSeenUtc,
                LastSeenUtc = entry.LastSeenUtc,
                LatestCertificateCtEntryTimestampUtc = entry.LatestCertificateCtEntryTimestampUtc,
                LatestCertificateSubject = entry.LatestCertificateSubject,
                LatestCertificateIssuer = entry.LatestCertificateIssuer,
                LatestCertificateSerialNumber = entry.LatestCertificateSerialNumber,
                LatestCertificateNotBeforeUtc = entry.LatestCertificateNotBeforeUtc,
                LatestCertificateNotAfterUtc = entry.LatestCertificateNotAfterUtc,
                CtSources = entry.CtSources,
                CertificateObservationCount = entry.CertificateObservationCount,
                ResolutionStatus = resolutionStatus,
                ARecords = entry.ARecords,
                AaaaRecords = entry.AaaaRecords,
                SensitiveRisk = entry.SensitiveRisk,
                SensitiveSignals = entry.SensitiveSignals,
                AiSignals = entry.AiSignals
            });
        }

        return resolvedEntries
            .OrderBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static async Task<IReadOnlyList<SubdomainDiscoveryEntry>> DiscoverCtSubdomainsPassiveAsync(
        IReadOnlyList<string> domains,
        CertificateInventoryCaptureOptions options,
        List<string> warnings,
        List<PassiveCtDiagnosticEntry> passiveCtDiagnosticEntries,
        InternalLogger logger,
        CancellationToken cancellationToken,
        DnsEndpoint? dnsEndpointOverride = null,
        bool allowSystemDnsRetry = true) {
        var discovered = new Dictionary<string, SubdomainDiscoveryEntry>(StringComparer.OrdinalIgnoreCase);
        var warningLock = new object();
        var passiveDiagnosticEntriesLock = new object();
        var discoveredLock = new object();
        var passiveRunWarningKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var latestPassiveDiagnosticsBySource = new ConcurrentDictionary<string, PassiveCtDiagnosticEntry>(StringComparer.OrdinalIgnoreCase);
        var passiveSuspensionReason = string.Empty;
        var passiveSuppressionWarningsLogged = 0;
        var analyzedDomains = 0;
        var suspendRemainingPassiveQueries = 0;
        var maxParallelism = Math.Max(1, options.DiscoveryParallelism);
        var effectiveDnsEndpoint = dnsEndpointOverride ?? options.DnsEndpoint;
        using var gate = new SemaphoreSlim(maxParallelism, maxParallelism);
        var tasks = new List<Task>(domains.Count);
        foreach (var domain in domains) {
            if (Volatile.Read(ref suspendRemainingPassiveQueries) != 0) {
                break;
            }

            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            Interlocked.Increment(ref analyzedDomains);
            tasks.Add(Task.Run(async () => {
                try {
                    if (Volatile.Read(ref suspendRemainingPassiveQueries) != 0) {
                        return;
                    }

                    var analysis = new SubdomainsAnalysis {
                        DnsConfiguration = new DnsConfiguration {
                            DnsEndpoint = effectiveDnsEndpoint
                        },
                        VerifyStillResolves = options.VerifyCtDiscoveredSubdomains,
                        DetectSensitiveSubdomains = false,
                        ScanSensitiveSubdomainTxt = false,
                        DetectAiInfrastructureExposure = false,
                        PassiveCtRequestTimeout = options.PassiveCtRequestTimeout,
                        PassiveCtRetryCount = options.PassiveCtRetryCount,
                        PassiveCtRetryBaseDelay = options.PassiveCtRetryBaseDelay,
                        PassiveCtRetryMaxDelay = options.PassiveCtRetryMaxDelay,
                        PassiveCtSourceCooldown = options.PassiveCtSourceCooldown,
                        EnableNativeCtLogSource = false,
                        NativeCtLogOnly = false
                    };
                    if (options.MaxCtRowsPerDomain > 0) {
                        analysis.MaxCtRowsToProcess = options.MaxCtRowsPerDomain;
                    }
                    if (options.MaxCtSubdomainsPerDomain > 0) {
                        analysis.MaxSubdomains = options.MaxCtSubdomainsPerDomain;
                        analysis.MaxResolutionChecks = options.MaxCtSubdomainsPerDomain;
                    }

                    await analysis.AnalyzeAsync(domain, logger, cancellationToken).ConfigureAwait(false);
                    if (analysis.PassiveCtWarnings != null && analysis.PassiveCtWarnings.Count > 0) {
                        lock (warningLock) {
                            foreach (string warning in analysis.PassiveCtWarnings) {
                                string? formattedWarning = FormatPassiveCtWarningForCaptureRun(
                                    domain,
                                    warning,
                                    passiveRunWarningKeys);
                                if (formattedWarning is { Length: > 0 }) {
                                    warnings.Add(formattedWarning);
                                }
                            }
                        }
                    }
                    if (analysis.PassiveCtDiagnosticEntries != null && analysis.PassiveCtDiagnosticEntries.Count > 0) {
                        foreach (PassiveCtDiagnosticEntry diagnosticEntry in analysis.PassiveCtDiagnosticEntries) {
                            if (diagnosticEntry == null || string.IsNullOrWhiteSpace(diagnosticEntry.SourceName)) {
                                continue;
                            }

                            PassiveCtDiagnosticEntry cloned = ClonePassiveCtDiagnosticEntry(diagnosticEntry);
                            lock (passiveDiagnosticEntriesLock) {
                                passiveCtDiagnosticEntries.Add(cloned);
                            }

                            latestPassiveDiagnosticsBySource.AddOrUpdate(
                                cloned.SourceName,
                                cloned,
                                (_, existing) => PreferPassiveCtDiagnosticForRun(existing, cloned));
                        }

                        if (TryBuildPassiveCtRunSuppressionReason(latestPassiveDiagnosticsBySource.Values, out string suspensionReason) &&
                            Interlocked.Exchange(ref suspendRemainingPassiveQueries, 1) == 0) {
                            passiveSuspensionReason = suspensionReason;
                            if (Interlocked.Exchange(ref passiveSuppressionWarningsLogged, 1) == 0) {
                                string warning =
                                    "Passive CT fallback sources are cooling down for the remainder of this run; " +
                                    suspensionReason;
                                lock (warningLock) {
                                    warnings.Add(warning);
                                }

                                logger.WriteVerbose("{0}", warning);
                            }
                        }
                    }
                    if (!analysis.QuerySucceeded && !string.IsNullOrWhiteSpace(analysis.FailureReason)) {
                        lock (warningLock) {
                            warnings.Add($"Passive CT fallback failed for {domain}: {analysis.FailureReason}");
                        }
                    } else if (analysis.ResultsCapped) {
                        lock (warningLock) {
                            warnings.Add($"Passive CT fallback results were capped for {domain}.");
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
                            MergeCtSubdomainEntry(discovered, candidate);
                        }
                    }
                } catch (Exception ex) {
                    lock (warningLock) {
                        warnings.Add($"Passive CT fallback failed for {domain}: {ex.Message}");
                    }
                } finally {
                    gate.Release();
                }
            }, cancellationToken));
        }

        await Task.WhenAll(tasks).ConfigureAwait(false);
        int skippedDomains = Math.Max(0, domains.Count - Volatile.Read(ref analyzedDomains));
        if (skippedDomains > 0 && Volatile.Read(ref suspendRemainingPassiveQueries) != 0) {
            string warning =
                "Passive CT fallback skipped " +
                skippedDomains.ToString(CultureInfo.InvariantCulture) +
                " remaining domain(s) after shared source cooldown was detected" +
                (string.IsNullOrWhiteSpace(passiveSuspensionReason) ? "." : ": " + passiveSuspensionReason);
            lock (warningLock) {
                warnings.Add(warning);
            }

            logger.WriteVerbose("{0}", warning);
        }

        bool passiveRunSuppressed = Volatile.Read(ref suspendRemainingPassiveQueries) != 0;
        if (ShouldRetryPassiveCtVerificationOnSystemDns(
                allowSystemDnsRetry,
                options.VerifyCtDiscoveredSubdomains,
                effectiveDnsEndpoint,
                discovered.Count,
                passiveRunSuppressed)) {
            warnings.Add(
                "Passive CT fallback returned no resolvable subdomains on DNS endpoint '" +
                effectiveDnsEndpoint +
                "'. Retrying passive CT verification on 'System' DNS.");
            logger.WriteVerbose(
                "Passive CT fallback returned 0 resolvable subdomains on DNS endpoint '{0}'. Retrying with 'System' DNS endpoint.",
                effectiveDnsEndpoint);

            IReadOnlyList<SubdomainDiscoveryEntry> systemResolved = await DiscoverCtSubdomainsPassiveAsync(
                domains,
                options,
                warnings,
                passiveCtDiagnosticEntries,
                logger,
                cancellationToken,
                DnsEndpoint.System,
                allowSystemDnsRetry: false).ConfigureAwait(false);

            foreach (var entry in systemResolved) {
                MergeCtSubdomainEntry(discovered, entry);
            }
        } else if (allowSystemDnsRetry &&
                   discovered.Count == 0 &&
                   options.VerifyCtDiscoveredSubdomains &&
                   effectiveDnsEndpoint != DnsEndpoint.System &&
                   passiveRunSuppressed) {
            warnings.Add(
                "Passive CT fallback DNS retry on 'System' was skipped because shared source cooldown already suppressed the run.");
            logger.WriteVerbose(
                "Passive CT fallback DNS retry on 'System' skipped because shared source cooldown already suppressed the run.");
        }

        return discovered.Values
            .OrderBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    internal static bool ShouldRetryPassiveCtVerificationOnSystemDns(
        bool allowSystemDnsRetry,
        bool verifyCtDiscoveredSubdomains,
        DnsEndpoint effectiveDnsEndpoint,
        int discoveredCount,
        bool passiveRunSuppressed) {
        return allowSystemDnsRetry &&
               discoveredCount == 0 &&
               verifyCtDiscoveredSubdomains &&
               effectiveDnsEndpoint != DnsEndpoint.System &&
               !passiveRunSuppressed;
    }

    internal static string? FormatPassiveCtWarningForCaptureRun(
        string domain,
        string? warning,
        ISet<string> emittedRunLevelWarningKeys) {
        if (string.IsNullOrWhiteSpace(warning)) {
            return null;
        }

        string trimmedWarning = warning!.Trim();
        if (TryNormalizePassiveCtRunLevelWarning(trimmedWarning, out string normalizedKey)) {
            if (!emittedRunLevelWarningKeys.Add(normalizedKey)) {
                return null;
            }

            return trimmedWarning;
        }

        return $"Passive CT fallback for {domain}: {trimmedWarning}";
    }

    internal static bool TryNormalizePassiveCtRunLevelWarning(
        string? warning,
        out string normalizedKey) {
        normalizedKey = string.Empty;
        if (string.IsNullOrWhiteSpace(warning)) {
            return false;
        }

        string trimmedWarning = warning!.Trim();
        if (trimmedWarning.Equals(
                "Passive CT sources were temporarily unavailable or rate-limited; check later or let the next monitoring cycle retry.",
                StringComparison.OrdinalIgnoreCase)) {
            normalizedKey = "sources:shared-unavailable";
            return true;
        }

        if (!trimmedWarning.StartsWith("Passive CT source '", StringComparison.OrdinalIgnoreCase)) {
            return false;
        }

        const string prefix = "Passive CT source '";
        int sourceNameStart = prefix.Length;
        int sourceNameEnd = trimmedWarning.IndexOf('\'', sourceNameStart);
        if (sourceNameEnd <= sourceNameStart) {
            return false;
        }

        string sourceName = trimmedWarning.Substring(sourceNameStart, sourceNameEnd - sourceNameStart);
        if (trimmedWarning.IndexOf(" is cooling down until ", StringComparison.OrdinalIgnoreCase) >= 0) {
            normalizedKey = "source:" + sourceName + ":cooldown";
            return true;
        }

        if (trimmedWarning.IndexOf(" is temporarily unavailable", StringComparison.OrdinalIgnoreCase) >= 0) {
            normalizedKey = "source:" + sourceName + ":unavailable";
            return true;
        }

        return false;
    }

    private static SubdomainDiscoveryEntry CreateNativeCtDiscoveredEntry(
        string name,
        NativeCtSubdomainObservation observation) {
        return new SubdomainDiscoveryEntry {
            Name = name,
            FirstSeenUtc = observation?.FirstSeenUtc,
            LastSeenUtc = observation?.LastSeenUtc,
            LatestCertificateCtEntryTimestampUtc = observation?.LatestCertificateCtEntryTimestampUtc,
            LatestCertificateThumbprint = observation?.LatestCertificateThumbprint,
            LatestCertificateSubject = observation?.LatestCertificateSubject,
            LatestCertificateIssuer = observation?.LatestCertificateIssuer,
            LatestCertificateSerialNumber = observation?.LatestCertificateSerialNumber,
            LatestCertificateNotBeforeUtc = observation?.LatestCertificateNotBeforeUtc,
            LatestCertificateNotAfterUtc = observation?.LatestCertificateNotAfterUtc,
            LatestCertificateSubjectAlternativeNames = observation?.LatestCertificateSubjectAlternativeNames ?? Array.Empty<string>(),
            LatestCertificateIsSelfSigned = observation?.LatestCertificateIsSelfSigned,
            LatestCertificateWeakKey = observation?.LatestCertificateWeakKey,
            LatestCertificateSha1Signature = observation?.LatestCertificateSha1Signature,
            LatestCertificateHasServerAuthentication = observation?.LatestCertificateHasServerAuthentication,
            LatestCertificateHasClientAuthentication = observation?.LatestCertificateHasClientAuthentication,
            LatestCertificateHasSecureEmail = observation?.LatestCertificateHasSecureEmail,
            LatestCertificateAuthenticationProfile = observation?.LatestCertificateAuthenticationProfile,
            CtSources = new[] { "native-ct" },
            CertificateObservationCount = Math.Max(0, observation?.CertificateObservationCount ?? 0),
            ResolutionStatus = SubdomainResolutionStatus.Unknown
        };
    }

    private static PassiveCtDiagnosticEntry PreferPassiveCtDiagnosticForRun(
        PassiveCtDiagnosticEntry existing,
        PassiveCtDiagnosticEntry candidate) {
        if (existing == null) {
            return candidate;
        }

        if (candidate == null) {
            return existing;
        }

        DateTimeOffset existingCooldownUntilUtc = existing.CooldownUntilUtc ?? DateTimeOffset.MinValue;
        DateTimeOffset candidateCooldownUntilUtc = candidate.CooldownUntilUtc ?? DateTimeOffset.MinValue;
        if (candidateCooldownUntilUtc > existingCooldownUntilUtc) {
            return candidate;
        }

        if (candidateCooldownUntilUtc < existingCooldownUntilUtc) {
            return existing;
        }

        bool existingBlocksRun = IsPassiveCtSourceRunBlocked(existing);
        bool candidateBlocksRun = IsPassiveCtSourceRunBlocked(candidate);
        if (candidateBlocksRun && !existingBlocksRun) {
            return candidate;
        }

        return existing;
    }

    internal static int ResolvePassiveCtNetworkParallelism(
        int configuredDiscoveryParallelism,
        int configuredPassiveCtParallelism,
        int workItemCount) {
        int discoveryParallelism = Math.Max(1, configuredDiscoveryParallelism);
        int passiveParallelism = Math.Max(1, configuredPassiveCtParallelism);
        int boundedParallelism = Math.Min(discoveryParallelism, passiveParallelism);
        return Math.Min(Math.Max(1, workItemCount), boundedParallelism);
    }

    private static bool TryBuildPassiveCtRunSuppressionReason(
        IEnumerable<PassiveCtDiagnosticEntry> diagnostics,
        out string reason) {
        reason = string.Empty;
        var suppressionDiagnostics = new List<PassiveCtDiagnosticEntry>();
        if (diagnostics != null) {
            suppressionDiagnostics.AddRange(
                diagnostics.Where(static diagnostic =>
                    diagnostic != null &&
                    !string.IsNullOrWhiteSpace(diagnostic.SourceName)));
        }

        suppressionDiagnostics.AddRange(
            PassiveCtSourceClient.ExportSharedCooldownDiagnostics(new[] { "crt.sh", "certspotter" }));
        if (suppressionDiagnostics.Count == 0) {
            return false;
        }

        var latestBySource = suppressionDiagnostics
            .GroupBy(static diagnostic => diagnostic.SourceName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                static group => group.Key,
                static group => group.Aggregate(PreferPassiveCtDiagnosticForRun),
                StringComparer.OrdinalIgnoreCase);

        if (!latestBySource.TryGetValue("crt.sh", out PassiveCtDiagnosticEntry? crtSh) ||
            !IsPassiveCtSourceRunBlocked(crtSh)) {
            return false;
        }

        if (!latestBySource.TryGetValue("certspotter", out PassiveCtDiagnosticEntry? certSpotter) ||
            !IsPassiveCtSourceRunBlocked(certSpotter)) {
            return false;
        }

        reason =
            "crt.sh " + DescribePassiveCtDiagnostic(crtSh) +
            "; certspotter " + DescribePassiveCtDiagnostic(certSpotter);
        return true;
    }

    private static bool IsPassiveCtSourceRunBlocked(PassiveCtDiagnosticEntry diagnostic) {
        if (diagnostic == null || !diagnostic.RetrySuggested) {
            return false;
        }

        if (diagnostic.CooldownUntilUtc.HasValue && diagnostic.CooldownUntilUtc.Value > DateTimeOffset.UtcNow) {
            return true;
        }

        return string.Equals(diagnostic.State, "CoolingDown", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(diagnostic.State, "BudgetExhausted", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(diagnostic.State, "RateLimited", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(diagnostic.State, "TemporarilyUnavailable", StringComparison.OrdinalIgnoreCase);
    }

    private static string DescribePassiveCtDiagnostic(PassiveCtDiagnosticEntry diagnostic) {
        if (diagnostic == null) {
            return "is unavailable";
        }

        string state = string.IsNullOrWhiteSpace(diagnostic.State) ? "unavailable" : diagnostic.State;
        if (string.Equals(state, "BudgetExhausted", StringComparison.OrdinalIgnoreCase)) {
            return "request budget is exhausted for this run";
        }
        if (diagnostic.CooldownUntilUtc.HasValue) {
            return "is " +
                   state +
                   " until " +
                   diagnostic.CooldownUntilUtc.Value.ToString("u", CultureInfo.InvariantCulture).Trim();
        }

        return "is " + state;
    }

    private static void MergeCtSubdomainEntry(
        IDictionary<string, SubdomainDiscoveryEntry> byName,
        SubdomainDiscoveryEntry candidate) {
        if (candidate == null || string.IsNullOrWhiteSpace(candidate.Name)) {
            return;
        }

        var name = candidate.Name.Trim();
        if (!byName.TryGetValue(name, out var existing)) {
            byName[name] = CloneSubdomainEntry(candidate);
            return;
        }

        var existingLatestTs = existing.LatestCertificateCtEntryTimestampUtc;
        var candidateLatestTs = candidate.LatestCertificateCtEntryTimestampUtc;
        var preferCandidateCert = !existingLatestTs.HasValue ||
            (candidateLatestTs.HasValue && candidateLatestTs.Value >= existingLatestTs.Value);

        var mergedFirstSeenUtc = MinTimestamp(existing.FirstSeenUtc, candidate.FirstSeenUtc);
        var mergedLastSeenUtc = MaxTimestamp(existing.LastSeenUtc, candidate.LastSeenUtc);
        var mergedLatestTs = MaxTimestamp(existingLatestTs, candidateLatestTs);
        var mergedSources = existing.CtSources
            .Concat(candidate.CtSources ?? Array.Empty<string>())
            .Where(source => !string.IsNullOrWhiteSpace(source))
            .Select(source => source.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(source => source, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var mergedResolution = MergeResolution(existing.ResolutionStatus, candidate.ResolutionStatus);
        var mergedARecords = existing.ARecords
            .Concat(candidate.ARecords ?? Array.Empty<string>())
            .Where(record => !string.IsNullOrWhiteSpace(record))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(record => record, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var mergedAaaaRecords = existing.AaaaRecords
            .Concat(candidate.AaaaRecords ?? Array.Empty<string>())
            .Where(record => !string.IsNullOrWhiteSpace(record))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(record => record, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var mergedSensitiveSignals = existing.SensitiveSignals
            .Concat(candidate.SensitiveSignals ?? Array.Empty<string>())
            .Where(signal => !string.IsNullOrWhiteSpace(signal))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(signal => signal, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var mergedAiSignals = existing.AiSignals
            .Concat(candidate.AiSignals ?? Array.Empty<string>())
            .Where(signal => !string.IsNullOrWhiteSpace(signal))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(signal => signal, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var mergedCertificate = MergeLatestCertificateMetadata(
            preferCandidateCert ? candidate : existing,
            preferCandidateCert ? existing : candidate);

        byName[name] = new SubdomainDiscoveryEntry {
            Name = name,
            FirstSeenUtc = mergedFirstSeenUtc,
            LastSeenUtc = mergedLastSeenUtc,
            LatestCertificateCtEntryTimestampUtc = mergedLatestTs,
            LatestCertificateThumbprint = mergedCertificate.LatestCertificateThumbprint,
            LatestCertificateSubject = mergedCertificate.LatestCertificateSubject,
            LatestCertificateIssuer = mergedCertificate.LatestCertificateIssuer,
            LatestCertificateSerialNumber = mergedCertificate.LatestCertificateSerialNumber,
            LatestCertificateNotBeforeUtc = mergedCertificate.LatestCertificateNotBeforeUtc,
            LatestCertificateNotAfterUtc = mergedCertificate.LatestCertificateNotAfterUtc,
            LatestCertificateSubjectAlternativeNames = mergedCertificate.LatestCertificateSubjectAlternativeNames,
            LatestCertificateIsSelfSigned = mergedCertificate.LatestCertificateIsSelfSigned,
            LatestCertificateWeakKey = mergedCertificate.LatestCertificateWeakKey,
            LatestCertificateSha1Signature = mergedCertificate.LatestCertificateSha1Signature,
            LatestCertificateHasServerAuthentication = mergedCertificate.LatestCertificateHasServerAuthentication,
            LatestCertificateHasClientAuthentication = mergedCertificate.LatestCertificateHasClientAuthentication,
            LatestCertificateHasSecureEmail = mergedCertificate.LatestCertificateHasSecureEmail,
            LatestCertificateAuthenticationProfile = mergedCertificate.LatestCertificateAuthenticationProfile,
            CtSources = mergedSources,
            CertificateObservationCount = existing.CertificateObservationCount + candidate.CertificateObservationCount,
            ResolutionStatus = mergedResolution,
            ARecords = mergedARecords,
            AaaaRecords = mergedAaaaRecords,
            SensitiveRisk = existing.SensitiveRisk >= candidate.SensitiveRisk ? existing.SensitiveRisk : candidate.SensitiveRisk,
            SensitiveSignals = mergedSensitiveSignals,
            AiSignals = mergedAiSignals
        };
    }

    private static SubdomainDiscoveryEntry MergeLatestCertificateMetadata(
        SubdomainDiscoveryEntry primary,
        SubdomainDiscoveryEntry secondary) {
        if (!HasLatestCertificateMetadata(primary)) {
            return CloneLatestCertificateMetadata(secondary);
        }

        if (!HasLatestCertificateMetadata(secondary)) {
            return CloneLatestCertificateMetadata(primary);
        }

        if (!RefersToSameLatestCertificate(primary, secondary)) {
            return CloneLatestCertificateMetadata(primary);
        }

        return new SubdomainDiscoveryEntry {
            LatestCertificateThumbprint = FirstNonEmpty(primary.LatestCertificateThumbprint, secondary.LatestCertificateThumbprint),
            LatestCertificateSubject = FirstNonEmpty(primary.LatestCertificateSubject, secondary.LatestCertificateSubject),
            LatestCertificateIssuer = FirstNonEmpty(primary.LatestCertificateIssuer, secondary.LatestCertificateIssuer),
            LatestCertificateSerialNumber = FirstNonEmpty(primary.LatestCertificateSerialNumber, secondary.LatestCertificateSerialNumber),
            LatestCertificateNotBeforeUtc = FirstTimestamp(primary.LatestCertificateNotBeforeUtc, secondary.LatestCertificateNotBeforeUtc),
            LatestCertificateNotAfterUtc = FirstTimestamp(primary.LatestCertificateNotAfterUtc, secondary.LatestCertificateNotAfterUtc),
            LatestCertificateSubjectAlternativeNames = primary.LatestCertificateSubjectAlternativeNames?.Count > 0
                ? primary.LatestCertificateSubjectAlternativeNames
                : secondary.LatestCertificateSubjectAlternativeNames,
            LatestCertificateIsSelfSigned = primary.LatestCertificateIsSelfSigned ?? secondary.LatestCertificateIsSelfSigned,
            LatestCertificateWeakKey = primary.LatestCertificateWeakKey ?? secondary.LatestCertificateWeakKey,
            LatestCertificateSha1Signature = primary.LatestCertificateSha1Signature ?? secondary.LatestCertificateSha1Signature,
            LatestCertificateHasServerAuthentication = primary.LatestCertificateHasServerAuthentication ?? secondary.LatestCertificateHasServerAuthentication,
            LatestCertificateHasClientAuthentication = primary.LatestCertificateHasClientAuthentication ?? secondary.LatestCertificateHasClientAuthentication,
            LatestCertificateHasSecureEmail = primary.LatestCertificateHasSecureEmail ?? secondary.LatestCertificateHasSecureEmail,
            LatestCertificateAuthenticationProfile = FirstNonEmpty(primary.LatestCertificateAuthenticationProfile, secondary.LatestCertificateAuthenticationProfile)
        };
    }

    private static bool HasLatestCertificateMetadata(SubdomainDiscoveryEntry entry) {
        if (entry == null) {
            return false;
        }

        return !string.IsNullOrWhiteSpace(entry.LatestCertificateThumbprint) ||
               !string.IsNullOrWhiteSpace(entry.LatestCertificateSubject) ||
               !string.IsNullOrWhiteSpace(entry.LatestCertificateIssuer) ||
               !string.IsNullOrWhiteSpace(entry.LatestCertificateSerialNumber) ||
               entry.LatestCertificateNotBeforeUtc.HasValue ||
               entry.LatestCertificateNotAfterUtc.HasValue ||
               (entry.LatestCertificateSubjectAlternativeNames?.Count ?? 0) > 0 ||
               entry.LatestCertificateIsSelfSigned.HasValue ||
               entry.LatestCertificateWeakKey.HasValue ||
               entry.LatestCertificateSha1Signature.HasValue ||
               entry.LatestCertificateHasServerAuthentication.HasValue ||
               entry.LatestCertificateHasClientAuthentication.HasValue ||
               entry.LatestCertificateHasSecureEmail.HasValue ||
               !string.IsNullOrWhiteSpace(entry.LatestCertificateAuthenticationProfile);
    }

    private static bool RefersToSameLatestCertificate(
        SubdomainDiscoveryEntry first,
        SubdomainDiscoveryEntry second) {
        var firstThumbprint = NormalizeLatestCertificateToken(first.LatestCertificateThumbprint, upperInvariant: true);
        var secondThumbprint = NormalizeLatestCertificateToken(second.LatestCertificateThumbprint, upperInvariant: true);
        if (!string.IsNullOrWhiteSpace(firstThumbprint) &&
            !string.IsNullOrWhiteSpace(secondThumbprint)) {
            return string.Equals(firstThumbprint, secondThumbprint, StringComparison.OrdinalIgnoreCase);
        }

        return TryBuildLatestCertificateIdentity(first, out string? firstIdentity) &&
               TryBuildLatestCertificateIdentity(second, out string? secondIdentity) &&
               string.Equals(firstIdentity, secondIdentity, StringComparison.Ordinal);
    }

    private static bool TryBuildLatestCertificateIdentity(
        SubdomainDiscoveryEntry? entry,
        out string? identity) {
        identity = null;
        if (entry == null) {
            return false;
        }

        string serialNumber = NormalizeLatestCertificateToken(entry.LatestCertificateSerialNumber, upperInvariant: true) ?? string.Empty;
        string subject = NormalizeLatestCertificateText(entry.LatestCertificateSubject) ?? string.Empty;
        string issuer = NormalizeLatestCertificateText(entry.LatestCertificateIssuer) ?? string.Empty;
        string notBefore = entry.LatestCertificateNotBeforeUtc?.UtcDateTime.ToString("O") ?? string.Empty;
        string notAfter = entry.LatestCertificateNotAfterUtc?.UtcDateTime.ToString("O") ?? string.Empty;
        if (string.IsNullOrWhiteSpace(subject) ||
            string.IsNullOrWhiteSpace(issuer) ||
            (string.IsNullOrWhiteSpace(serialNumber) &&
             string.IsNullOrWhiteSpace(notBefore) &&
             string.IsNullOrWhiteSpace(notAfter))) {
            return false;
        }

        identity = serialNumber + "|" + issuer + "|" + subject + "|" + notBefore + "|" + notAfter;
        return true;
    }

    private static string? NormalizeLatestCertificateToken(string? value, bool upperInvariant) {
        if (value == null) {
            return null;
        }

        var normalized = value.Trim();
        if (normalized.Length == 0) {
            return null;
        }

        return upperInvariant ? normalized.ToUpperInvariant() : normalized.ToLowerInvariant();
    }

    private static string? NormalizeLatestCertificateText(string? value) {
        if (value == null) {
            return null;
        }

        var normalized = value.Trim();
        return normalized.Length == 0 ? null : normalized;
    }

    private static SubdomainDiscoveryEntry CloneLatestCertificateMetadata(SubdomainDiscoveryEntry? entry) {
        if (entry == null) {
            return new SubdomainDiscoveryEntry();
        }

        return new SubdomainDiscoveryEntry {
            LatestCertificateThumbprint = entry.LatestCertificateThumbprint,
            LatestCertificateSubject = entry.LatestCertificateSubject,
            LatestCertificateIssuer = entry.LatestCertificateIssuer,
            LatestCertificateSerialNumber = entry.LatestCertificateSerialNumber,
            LatestCertificateNotBeforeUtc = entry.LatestCertificateNotBeforeUtc,
            LatestCertificateNotAfterUtc = entry.LatestCertificateNotAfterUtc,
            LatestCertificateSubjectAlternativeNames = entry.LatestCertificateSubjectAlternativeNames == null
                ? Array.Empty<string>()
                : entry.LatestCertificateSubjectAlternativeNames.ToList(),
            LatestCertificateIsSelfSigned = entry.LatestCertificateIsSelfSigned,
            LatestCertificateWeakKey = entry.LatestCertificateWeakKey,
            LatestCertificateSha1Signature = entry.LatestCertificateSha1Signature,
            LatestCertificateHasServerAuthentication = entry.LatestCertificateHasServerAuthentication,
            LatestCertificateHasClientAuthentication = entry.LatestCertificateHasClientAuthentication,
            LatestCertificateHasSecureEmail = entry.LatestCertificateHasSecureEmail,
            LatestCertificateAuthenticationProfile = entry.LatestCertificateAuthenticationProfile
        };
    }

    private static SubdomainDiscoveryEntry CloneSubdomainEntry(SubdomainDiscoveryEntry entry) {
        if (entry == null) {
            throw new ArgumentNullException(nameof(entry));
        }

        return new SubdomainDiscoveryEntry {
            Name = entry.Name,
            FirstSeenUtc = entry.FirstSeenUtc,
            LastSeenUtc = entry.LastSeenUtc,
            LatestCertificateCtEntryTimestampUtc = entry.LatestCertificateCtEntryTimestampUtc,
            LatestCertificateThumbprint = entry.LatestCertificateThumbprint,
            LatestCertificateSubject = entry.LatestCertificateSubject,
            LatestCertificateIssuer = entry.LatestCertificateIssuer,
            LatestCertificateSerialNumber = entry.LatestCertificateSerialNumber,
            LatestCertificateNotBeforeUtc = entry.LatestCertificateNotBeforeUtc,
            LatestCertificateNotAfterUtc = entry.LatestCertificateNotAfterUtc,
            LatestCertificateSubjectAlternativeNames = entry.LatestCertificateSubjectAlternativeNames == null ? Array.Empty<string>() : entry.LatestCertificateSubjectAlternativeNames.ToList(),
            LatestCertificateIsSelfSigned = entry.LatestCertificateIsSelfSigned,
            LatestCertificateWeakKey = entry.LatestCertificateWeakKey,
            LatestCertificateSha1Signature = entry.LatestCertificateSha1Signature,
            LatestCertificateHasServerAuthentication = entry.LatestCertificateHasServerAuthentication,
            LatestCertificateHasClientAuthentication = entry.LatestCertificateHasClientAuthentication,
            LatestCertificateHasSecureEmail = entry.LatestCertificateHasSecureEmail,
            LatestCertificateAuthenticationProfile = entry.LatestCertificateAuthenticationProfile,
            CtSources = entry.CtSources == null ? Array.Empty<string>() : entry.CtSources.ToList(),
            CertificateObservationCount = entry.CertificateObservationCount,
            ResolutionStatus = entry.ResolutionStatus,
            ARecords = entry.ARecords == null ? Array.Empty<string>() : entry.ARecords.ToList(),
            AaaaRecords = entry.AaaaRecords == null ? Array.Empty<string>() : entry.AaaaRecords.ToList(),
            SensitiveRisk = entry.SensitiveRisk,
            SensitiveSignals = entry.SensitiveSignals == null ? Array.Empty<string>() : entry.SensitiveSignals.ToList(),
            AiSignals = entry.AiSignals == null ? Array.Empty<string>() : entry.AiSignals.ToList()
        };
    }

    private static SubdomainResolutionStatus MergeResolution(
        SubdomainResolutionStatus existing,
        SubdomainResolutionStatus candidate) {
        if (existing == SubdomainResolutionStatus.Resolves || candidate == SubdomainResolutionStatus.Resolves) {
            return SubdomainResolutionStatus.Resolves;
        }
        if (existing == SubdomainResolutionStatus.DoesNotResolve || candidate == SubdomainResolutionStatus.DoesNotResolve) {
            return SubdomainResolutionStatus.DoesNotResolve;
        }
        if (existing == SubdomainResolutionStatus.QueryFailed || candidate == SubdomainResolutionStatus.QueryFailed) {
            return SubdomainResolutionStatus.QueryFailed;
        }
        return SubdomainResolutionStatus.Unknown;
    }

    private static DateTimeOffset? MinTimestamp(DateTimeOffset? left, DateTimeOffset? right) {
        if (!left.HasValue) {
            return right;
        }
        if (!right.HasValue) {
            return left;
        }

        return left.Value <= right.Value ? left : right;
    }

    private static DateTimeOffset? MaxTimestamp(DateTimeOffset? left, DateTimeOffset? right) {
        if (!left.HasValue) {
            return right;
        }
        if (!right.HasValue) {
            return left;
        }

        return left.Value >= right.Value ? left : right;
    }

    private static DateTimeOffset? FirstTimestamp(DateTimeOffset? first, DateTimeOffset? second) {
        if (first.HasValue) {
            return first;
        }
        return second;
    }

    private static string? FirstNonEmpty(string? first, string? second) {
        if (!string.IsNullOrWhiteSpace(first)) {
            return first;
        }
        return string.IsNullOrWhiteSpace(second) ? null : second;
    }

    internal static int ComputeNativeSharedMaxRows(
        int domainCount,
        int maxCtRowsPerDomain,
        int nativeCtSharedMaxRowsTotal) {
        if (domainCount <= 0) {
            return ResolveNativeSharedAggregateLimit(maxCtRowsPerDomain, nativeCtSharedMaxRowsTotal);
        }

        if (maxCtRowsPerDomain <= 0) {
            return ResolveNativeSharedAggregateLimit(0, nativeCtSharedMaxRowsTotal);
        }

        var multiplier = Math.Min(25, domainCount);
        var candidate = (long)maxCtRowsPerDomain * multiplier;
        if (candidate < maxCtRowsPerDomain) {
            candidate = maxCtRowsPerDomain;
        }
        return ResolveNativeSharedAggregateLimit(candidate, nativeCtSharedMaxRowsTotal);
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

    internal static int ComputeNativeSharedMaxSubdomains(
        int domainCount,
        int maxCtSubdomainsPerDomain,
        int nativeCtSharedMaxSubdomainsTotal) {
        if (domainCount <= 0) {
            return ResolveNativeSharedAggregateLimit(maxCtSubdomainsPerDomain, nativeCtSharedMaxSubdomainsTotal);
        }

        if (maxCtSubdomainsPerDomain <= 0) {
            return ResolveNativeSharedAggregateLimit(0, nativeCtSharedMaxSubdomainsTotal);
        }

        var candidate = (long)maxCtSubdomainsPerDomain * Math.Max(1, domainCount);
        if (candidate < maxCtSubdomainsPerDomain) {
            candidate = maxCtSubdomainsPerDomain;
        }
        return ResolveNativeSharedAggregateLimit(candidate, nativeCtSharedMaxSubdomainsTotal);
    }

    private static int ResolveNativeSharedAggregateLimit(long candidate, int configuredLimit) {
        long resolved = candidate;
        if (configuredLimit > 0 && (resolved <= 0 || resolved > configuredLimit)) {
            resolved = configuredLimit;
        }

        if (resolved <= 0) {
            return 0;
        }

        if (resolved > int.MaxValue) {
            return int.MaxValue;
        }

        return (int)resolved;
    }

    private static NativeCtLogDiagnosticEntry? BuildNativeCtLogDiagnosticEntry(NativeCtLogIngestionStatus status, IReadOnlyList<string> domains) {
        if (status == null || string.IsNullOrWhiteSpace(status.LogUrl)) {
            return null;
        }

        return new NativeCtLogDiagnosticEntry {
            Scope = status.SharedIngestion
                ? "shared:" + string.Join(",", domains.OrderBy(domain => domain, StringComparer.OrdinalIgnoreCase))
                : (string.IsNullOrWhiteSpace(status.DomainScope) ? "domain:unknown" : "domain:" + status.DomainScope),
            SharedIngestion = status.SharedIngestion,
            IsRetired = status.IsRetired,
            State = status.SkippedByCircuitBreaker ? "CircuitOpen" : (status.Succeeded ? "Succeeded" : "Failed"),
            LogUrl = status.LogUrl,
            TreeSize = status.TreeSize,
            LastProcessedIndex = status.LastProcessedIndex,
            LagBefore = status.EstimatedLagBefore,
            LagAfter = status.EstimatedLagAfter,
            CircuitOpenUntilUtc = status.CircuitOpenUntilUtc,
            Failure = string.IsNullOrWhiteSpace(status.Failure)
                ? null
                : status.Failure!.Replace('\r', ' ').Replace('\n', ' ').Trim()
        };
    }

    private static string? FormatNativeCtLogDiagnostic(NativeCtLogDiagnosticEntry entry) {
        if (entry == null || string.IsNullOrWhiteSpace(entry.LogUrl)) {
            return null;
        }

        var scope = string.IsNullOrWhiteSpace(entry.Scope) ? "domain:unknown" : entry.Scope;
        var state = string.IsNullOrWhiteSpace(entry.State) ? "Unknown" : entry.State;
        var treeSize = entry.TreeSize.HasValue ? entry.TreeSize.Value.ToString(CultureInfo.InvariantCulture) : "-";
        var lastProcessed = entry.LastProcessedIndex.HasValue ? entry.LastProcessedIndex.Value.ToString(CultureInfo.InvariantCulture) : "-";
        var lagBefore = entry.LagBefore.HasValue ? entry.LagBefore.Value.ToString(CultureInfo.InvariantCulture) : "-";
        var lagAfter = entry.LagAfter.HasValue ? entry.LagAfter.Value.ToString(CultureInfo.InvariantCulture) : "-";
        var circuitUntil = entry.CircuitOpenUntilUtc.HasValue
            ? entry.CircuitOpenUntilUtc.Value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture)
            : "-";
        var failure = string.IsNullOrWhiteSpace(entry.Failure) ? "-" : entry.Failure!;
        return $"scope={scope}; state={state}; log={entry.LogUrl}; tree={treeSize}; last={lastProcessed}; lagBefore={lagBefore}; lagAfter={lagAfter}; circuitUntil={circuitUntil}; failure={failure}";
    }

    private static NativeCtLogDiagnosticEntry CloneNativeCtLogDiagnosticEntry(NativeCtLogDiagnosticEntry entry) {
        return new NativeCtLogDiagnosticEntry {
            Scope = entry.Scope,
            SharedIngestion = entry.SharedIngestion,
            IsRetired = entry.IsRetired,
            State = entry.State,
            LogUrl = entry.LogUrl,
            TreeSize = entry.TreeSize,
            LastProcessedIndex = entry.LastProcessedIndex,
            LagBefore = entry.LagBefore,
            LagAfter = entry.LagAfter,
            CircuitOpenUntilUtc = entry.CircuitOpenUntilUtc,
            Failure = entry.Failure
        };
    }

    private static PassiveCtDiagnosticEntry ClonePassiveCtDiagnosticEntry(PassiveCtDiagnosticEntry entry) {
        return new PassiveCtDiagnosticEntry {
            Scope = entry.Scope,
            QueryKind = entry.QueryKind,
            SourceName = entry.SourceName,
            RequestUrl = entry.RequestUrl,
            State = entry.State,
            RetrySuggested = entry.RetrySuggested,
            CooldownUntilUtc = entry.CooldownUntilUtc,
            RetryAfterSeconds = entry.RetryAfterSeconds,
            Failure = entry.Failure
        };
    }

    private static bool ShouldAllowPassiveCtFallback(CertificateInventoryCaptureOptions options) {
        if (options == null) {
            return false;
        }

        if (options.NativeCtLogOnly) {
            return false;
        }

        return options.EnablePassiveCtFallback;
    }

}
