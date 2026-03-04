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
    private static async Task<IReadOnlyList<string>> DiscoverCtSubdomainsAsync(
        IReadOnlyList<string> domains,
        CertificateInventoryCaptureOptions options,
        List<string> warnings,
        List<string> nativeCtLogDiagnostics,
        List<NativeCtLogDiagnosticEntry> nativeCtLogDiagnosticEntries,
        InternalLogger logger,
        CancellationToken cancellationToken) {
        if (domains == null || domains.Count == 0 || !options.IncludeCtDiscoveredSubdomains) {
            return Array.Empty<string>();
        }

        if (options.EnableNativeCtLogSubdomainSource &&
            options.EnableNativeCtSharedIngestion &&
            domains.Count > 1) {
            logger.WriteVerbose("Using shared native CT ingestion for {0} domain(s).", domains.Count);
            IReadOnlyList<string> nativeSharedDiscovered = await DiscoverCtSubdomainsNativeSharedAsync(
                domains,
                options,
                warnings,
                nativeCtLogDiagnostics,
                nativeCtLogDiagnosticEntries,
                logger,
                cancellationToken).ConfigureAwait(false);

            if (nativeSharedDiscovered.Count == 0 && !options.NativeCtLogOnly) {
                warnings.Add("Native CT shared ingestion returned no subdomains; falling back to passive CT APIs.");
                logger.WriteVerbose(
                    "Shared native CT ingestion returned 0 subdomains for {0} domain(s). Falling back to passive CT APIs.",
                    domains.Count);
                IReadOnlyList<string> passiveDiscovered = await DiscoverCtSubdomainsPassiveAsync(
                    domains,
                    options,
                    warnings,
                    logger,
                    cancellationToken).ConfigureAwait(false);
                if (passiveDiscovered.Count > 0) {
                    return passiveDiscovered;
                }
            }

            return nativeSharedDiscovered;
        }

        var discovered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var warningLock = new object();
        var diagnosticsLock = new object();
        var diagnosticEntriesLock = new object();
        var discoveredLock = new object();
        var discoveredByDomain = new ConcurrentDictionary<string, int>(StringComparer.OrdinalIgnoreCase);
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
                    var discoveredForDomain = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
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
                        NativeCtRequestDelay = options.NativeCtRequestDelay,
                        NativeCtRetryCount = options.NativeCtRetryCount,
                        NativeCtRetryBaseDelay = options.NativeCtRetryBaseDelay,
                        NativeCtRetryMaxDelay = options.NativeCtRetryMaxDelay,
                        NativeCtCircuitBreakerFailureThreshold = options.NativeCtCircuitBreakerFailureThreshold,
                        NativeCtCircuitBreakerDuration = options.NativeCtCircuitBreakerDuration,
                        NativeCtEnableCatchUpMode = options.NativeCtEnableCatchUpMode,
                        NativeCtCatchUpLagThreshold = options.NativeCtCatchUpLagThreshold,
                        NativeCtCatchUpMaxEntriesPerLog = options.NativeCtCatchUpMaxEntriesPerLog,
                        NativeCtCatchUpBatchSize = options.NativeCtCatchUpBatchSize
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
        if (options.EnableNativeCtLogSubdomainSource && !options.NativeCtLogOnly) {
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
                IReadOnlyList<string> passiveDiscovered = await DiscoverCtSubdomainsPassiveAsync(
                    fallbackDomains,
                    options,
                    warnings,
                    logger,
                    cancellationToken).ConfigureAwait(false);
                foreach (var subdomain in passiveDiscovered) {
                    discovered.Add(subdomain);
                }
            }
        }

        return discovered.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static async Task<IReadOnlyList<string>> DiscoverCtSubdomainsNativeSharedAsync(
        IReadOnlyList<string> domains,
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
            RequestDelay = options.NativeCtRequestDelay,
            RetryCount = options.NativeCtRetryCount,
            RetryBaseDelay = options.NativeCtRetryBaseDelay,
            RetryMaxDelay = options.NativeCtRetryMaxDelay,
            CircuitBreakerFailureThreshold = options.NativeCtCircuitBreakerFailureThreshold,
            CircuitBreakerDuration = options.NativeCtCircuitBreakerDuration,
            EnableCatchUpMode = options.NativeCtEnableCatchUpMode,
            CatchUpLagThreshold = options.NativeCtCatchUpLagThreshold,
            CatchUpMaxEntriesPerLog = options.NativeCtCatchUpMaxEntriesPerLog,
            CatchUpBatchSize = options.NativeCtCatchUpBatchSize
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

    private static async Task<IReadOnlyList<string>> DiscoverCtSubdomainsPassiveAsync(
        IReadOnlyList<string> domains,
        CertificateInventoryCaptureOptions options,
        List<string> warnings,
        InternalLogger logger,
        CancellationToken cancellationToken,
        DnsEndpoint? dnsEndpointOverride = null,
        bool allowSystemDnsRetry = true) {
        var discovered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var warningLock = new object();
        var discoveredLock = new object();
        var maxParallelism = Math.Max(1, options.DiscoveryParallelism);
        var effectiveDnsEndpoint = dnsEndpointOverride ?? options.DnsEndpoint;
        using var gate = new SemaphoreSlim(maxParallelism, maxParallelism);
        var tasks = new List<Task>(domains.Count);
        foreach (var domain in domains) {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            tasks.Add(Task.Run(async () => {
                try {
                    var analysis = new SubdomainsAnalysis {
                        DnsConfiguration = new DnsConfiguration {
                            DnsEndpoint = effectiveDnsEndpoint
                        },
                        VerifyStillResolves = options.VerifyCtDiscoveredSubdomains,
                        DetectSensitiveSubdomains = false,
                        ScanSensitiveSubdomainTxt = false,
                        DetectAiInfrastructureExposure = false,
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
                            discovered.Add(candidate.Name);
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
        if (allowSystemDnsRetry &&
            discovered.Count == 0 &&
            options.VerifyCtDiscoveredSubdomains &&
            effectiveDnsEndpoint != DnsEndpoint.System) {
            warnings.Add(
                "Passive CT fallback returned no resolvable subdomains on DNS endpoint '" +
                effectiveDnsEndpoint +
                "'. Retrying passive CT verification on 'System' DNS.");
            logger.WriteVerbose(
                "Passive CT fallback returned 0 resolvable subdomains on DNS endpoint '{0}'. Retrying with 'System' DNS endpoint.",
                effectiveDnsEndpoint);

            IReadOnlyList<string> systemResolved = await DiscoverCtSubdomainsPassiveAsync(
                domains,
                options,
                warnings,
                logger,
                cancellationToken,
                DnsEndpoint.System,
                allowSystemDnsRetry: false).ConfigureAwait(false);

            foreach (var name in systemResolved) {
                discovered.Add(name);
            }
        }

        return discovered.OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToList();
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

    private static NativeCtLogDiagnosticEntry? BuildNativeCtLogDiagnosticEntry(NativeCtLogIngestionStatus status, IReadOnlyList<string> domains) {
        if (status == null || string.IsNullOrWhiteSpace(status.LogUrl)) {
            return null;
        }

        return new NativeCtLogDiagnosticEntry {
            Scope = status.SharedIngestion
                ? "shared:" + string.Join(",", domains.OrderBy(domain => domain, StringComparer.OrdinalIgnoreCase))
                : (string.IsNullOrWhiteSpace(status.DomainScope) ? "domain:unknown" : "domain:" + status.DomainScope),
            SharedIngestion = status.SharedIngestion,
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

}
