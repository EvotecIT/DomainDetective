using DomainDetective.Helpers;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

internal sealed partial class NativeCtLogSubdomainDiscovery {
    public async Task<NativeCtLogSubdomainDiscoveryResult> DiscoverAsync(
        NativeCtLogSubdomainDiscoveryOptions options,
        InternalLogger? logger,
        CancellationToken cancellationToken) {
        if (options == null) {
            throw new ArgumentNullException(nameof(options));
        }

        var result = new NativeCtLogSubdomainDiscoveryResult();
        var baseDomain = DomainHelper.ValidateIdn(options.BaseDomain);
        var logDescriptors = await ResolveLogUrlsAsync(options, cancellationToken, applyCap: false).ConfigureAwait(false);
        if (logDescriptors.Count == 0) {
            result.Warnings.Add("Native CT: no log URLs resolved.");
            return result;
        }

        var cursor = NativeCtCursorState.Load(options.CursorStatePath);
        logDescriptors = PrioritizeLogDescriptorsByHealth(logDescriptors, cursor, options, DateTimeOffset.UtcNow);
        var stoppedAfterMatchedObservationTarget = false;
        var consumedLogBudget = 0;
        foreach (var logDescriptor in logDescriptors) {
            var logUrl = logDescriptor.Url;
            cancellationToken.ThrowIfCancellationRequested();
            if (HasConsumedLogBudget(options.MaxLogsToProcess, consumedLogBudget)) {
                break;
            }
            result.LogsAttempted++;
            var key = NativeCtCursorState.BuildKey(baseDomain, logUrl);
            var logHealthKey = NativeCtCursorState.BuildLogHealthKey(logUrl);
            var status = new NativeCtLogIngestionStatus {
                LogUrl = logUrl,
                CursorKey = key,
                DomainScope = baseDomain,
                SharedIngestion = false,
                IsRetired = logDescriptor.IsRetired
            };
            result.LogStatuses.Add(status);

            try {
                if (cursor.IsCircuitOpen(logHealthKey, DateTimeOffset.UtcNow, out var openUntilUtc)) {
                    result.Warnings.Add($"Native CT log skipped (circuit open) for {logUrl} until {openUntilUtc:O}");
                    status.SkippedByCircuitBreaker = true;
                    status.CircuitOpenUntilUtc = openUntilUtc;
                    continue;
                }

                consumedLogBudget++;
                var sth = await GetSignedTreeHeadAsync(logUrl, options, cancellationToken).ConfigureAwait(false);
                status.TreeSize = sth.TreeSize;
                var start = ComputeStartIndex(sth.TreeSize, cursor.GetLastProcessedIndex(key), options.InitialBackfillEntriesPerLog);
                // Persist the initial backfill floor without acknowledging the first selected entry.
                // Otherwise a growing tree moves the window after a capped or empty first batch.
                if (start > 0 && !cursor.GetLastProcessedIndex(key).HasValue) cursor.SetLastProcessedIndex(key, start - 1);
                status.StartIndex = start;
                status.EstimatedLagBefore = start >= sth.TreeSize ? 0 : (sth.TreeSize - start);
                if (start >= sth.TreeSize) {
                    cursor.SetLastProcessedIndex(key, sth.TreeSize - 1);
                    cursor.RecordSuccess(key, DateTimeOffset.UtcNow);
                    status.EndIndex = sth.TreeSize - 1;
                    status.LastProcessedIndex = sth.TreeSize - 1;
                    status.EstimatedLagAfter = 0;
                    status.Succeeded = true;
                    result.LogsSucceeded++;
                    continue;
                }

                var lag = Math.Max(0, sth.TreeSize - start);
                long end = sth.TreeSize - 1;
                var maxEntriesPerLog = ComputeEffectiveMaxEntriesPerLog(options, lag);
                status.EffectiveMaxEntriesPerLog = maxEntriesPerLog;
                if (maxEntriesPerLog > 0) {
                    var maxEnd = start + Math.Max(0, maxEntriesPerLog - 1);
                    if (maxEnd < end) {
                        end = maxEnd;
                    }
                }
                status.EndIndex = end;

                var batchSize = ComputeEffectiveBatchSize(options, lag);
                status.EffectiveBatchSize = batchSize;

                var lastProcessed = start - 1;
                for (long batchStart = start; batchStart <= end; ) {
                    cancellationToken.ThrowIfCancellationRequested();

                    var batchEnd = batchStart + batchSize - 1;
                    if (batchEnd > end) {
                        batchEnd = end;
                    }

                    var entries = await GetEntriesAsync(logUrl, batchStart, batchEnd, options, cancellationToken).ConfigureAwait(false);
                    if (entries.Count == 0) {
                        break;
                    }

                    try {
                        for (int i = 0; i < entries.Count; i++) {
                            cancellationToken.ThrowIfCancellationRequested();

                            if (options.MaxCtRowsToProcess > 0 && result.CertificateObservationCount >= options.MaxCtRowsToProcess) {
                                result.ResultsCapped = true;
                                break;
                            }

                            if (TryProcessEntry(entries[i], baseDomain, options.ExactMatchOnly, options.MaxSubdomains, result, logger, out var matchedObservationCount)) {
                                if (matchedObservationCount > 0) {
                                    result.CertificateObservationCount += matchedObservationCount;
                                    if (options.StopAfterMatchedObservations > 0 &&
                                        result.CertificateObservationCount >= options.StopAfterMatchedObservations) {
                                        stoppedAfterMatchedObservationTarget = true;
                                    }
                                }
                                lastProcessed = batchStart + i;
                            } else {
                                result.ResultsCapped = true;
                                break;
                            }
                        }
                    } finally {
                        if (lastProcessed >= start) {
                            cursor.SetLastProcessedIndex(key, lastProcessed);
                        }
                    }

                    if (result.ResultsCapped) {
                        break;
                    }
                    if (stoppedAfterMatchedObservationTarget) {
                        break;
                    }

                    batchStart += entries.Count;
                }

                logger?.WriteVerbose(
                    "Native CT processed log {0}: observations={1}, subdomains={2}",
                    logUrl,
                    result.CertificateObservationCount,
                    result.Subdomains.Count);
                cursor.RecordSuccess(key, DateTimeOffset.UtcNow);
                cursor.RecordSuccess(logHealthKey, DateTimeOffset.UtcNow);
                status.LastProcessedIndex = cursor.GetLastProcessedIndex(key);
                status.EstimatedLagAfter = status.TreeSize.HasValue
                    ? ComputeRemainingLag(status.TreeSize.Value, status.LastProcessedIndex)
                    : null;
                status.Succeeded = true;
                result.LogsSucceeded++;

                if (result.ResultsCapped) {
                    break;
                }
                if (stoppedAfterMatchedObservationTarget) {
                    break;
                }
            } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                throw;
            } catch (Exception ex) {
                (int failureThreshold, TimeSpan circuitDuration) = ResolveCircuitBreakerPolicy(ex, options, logDescriptor);
                cursor.RecordFailure(
                    key,
                    DateTimeOffset.UtcNow,
                    ex.Message,
                    failureThreshold,
                    circuitDuration);
                cursor.RecordFailure(
                    logHealthKey,
                    DateTimeOffset.UtcNow,
                    ex.Message,
                    failureThreshold,
                    circuitDuration);
                result.Warnings.Add($"Native CT log failed for {logUrl}: {ex.Message}");
                logger?.WriteVerbose("Native CT log failed for {0}: {1}", logUrl, ex.Message);
                status.Failure = ex.Message;
                status.LastProcessedIndex = cursor.GetLastProcessedIndex(key);
                status.EstimatedLagAfter = status.TreeSize.HasValue
                    ? ComputeRemainingLag(status.TreeSize.Value, status.LastProcessedIndex)
                    : null;
                if (cursor.IsCircuitOpen(logHealthKey, DateTimeOffset.UtcNow, out var openUntilUtc)) {
                    status.CircuitOpenUntilUtc = openUntilUtc;
                }
            }
        }

        if (stoppedAfterMatchedObservationTarget) {
            result.Warnings.Add(
                "Native CT exact-host lookup stopped after reaching the configured matched-observation target.");
        }

        // A canceled invocation cannot deliver its local observations. Keep its prior checkpoint
        // unchanged so a subsequent invocation can replay every abandoned observation.
        cancellationToken.ThrowIfCancellationRequested();
        cursor.Save(options.CursorStatePath);
        return result;
    }

    public async Task<NativeCtLogSubdomainDiscoveryBatchResult> DiscoverForDomainsAsync(
        IReadOnlyList<string> domains,
        NativeCtLogSubdomainDiscoveryOptions options,
        InternalLogger? logger,
        CancellationToken cancellationToken) {
        if (domains == null || domains.Count == 0) {
            throw new ArgumentNullException(nameof(domains));
        }
        if (options == null) {
            throw new ArgumentNullException(nameof(options));
        }

        var normalizedDomains = domains
            .Where(domain => !string.IsNullOrWhiteSpace(domain))
            .Select(DomainHelper.ValidateIdn)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (normalizedDomains.Count == 0) {
            throw new ArgumentException("At least one domain is required.", nameof(domains));
        }

        var domainSet = new HashSet<string>(normalizedDomains, StringComparer.OrdinalIgnoreCase);
        var exactMatchDomainSet = new HashSet<string>(
            options.ExactMatchDomains
                .Where(domain => !string.IsNullOrWhiteSpace(domain))
                .Select(DomainHelper.ValidateIdn),
            StringComparer.OrdinalIgnoreCase);
        var result = new NativeCtLogSubdomainDiscoveryBatchResult();
        foreach (var domain in normalizedDomains) {
            result.SubdomainsByDomain[domain] = new Dictionary<string, NativeCtSubdomainObservation>(StringComparer.OrdinalIgnoreCase);
        }

        var logDescriptors = await ResolveLogUrlsAsync(options, cancellationToken, applyCap: false).ConfigureAwait(false);
        if (logDescriptors.Count == 0) {
            result.Warnings.Add("Native CT: no log URLs resolved.");
            return result;
        }

        var cursor = NativeCtCursorState.Load(options.CursorStatePath);
        logDescriptors = PrioritizeLogDescriptorsByHealth(logDescriptors, cursor, options, DateTimeOffset.UtcNow);
        var state = new SharedBatchProcessingState();
        var consumedLogBudget = 0;
        var processingItems = new List<SharedLogProcessingWorkItem>();
        foreach (var logDescriptor in logDescriptors) {
            var logUrl = logDescriptor.Url;
            cancellationToken.ThrowIfCancellationRequested();
            if (HasConsumedLogBudget(options.MaxLogsToProcess, consumedLogBudget)) {
                break;
            }

            result.LogsAttempted++;
            var key = NativeCtCursorState.BuildSharedKey(logUrl, normalizedDomains);
            var logHealthKey = NativeCtCursorState.BuildLogHealthKey(logUrl);
            var status = new NativeCtLogIngestionStatus {
                LogUrl = logUrl,
                CursorKey = key,
                SharedIngestion = true,
                IsRetired = logDescriptor.IsRetired
            };
            result.LogStatuses.Add(status);

            if (cursor.IsCircuitOpen(logHealthKey, DateTimeOffset.UtcNow, out var openUntilUtc)) {
                result.Warnings.Add($"Native CT shared log skipped (circuit open) for {logUrl} until {openUntilUtc:O}");
                status.SkippedByCircuitBreaker = true;
                status.CircuitOpenUntilUtc = openUntilUtc;
                continue;
            }

            consumedLogBudget++;
            processingItems.Add(new SharedLogProcessingWorkItem {
                Descriptor = logDescriptor,
                Status = status,
                CursorKey = key,
                LogHealthKey = logHealthKey
            });
        }

        int maxConcurrentLogs = Math.Min(
            processingItems.Count,
            Math.Max(1, options.MaxConcurrentLogs > 0 ? options.MaxConcurrentLogs : 1));
        int nextLog = -1;
        async Task ProcessLogsAsync() {
            while (true) {
                cancellationToken.ThrowIfCancellationRequested();
                int index = Interlocked.Increment(ref nextLog);
                if (index >= processingItems.Count) return;
                await ProcessSharedLogAsync(processingItems[index], domainSet, exactMatchDomainSet,
                    options, cursor, result, state, logger, cancellationToken).ConfigureAwait(false);
            }
        }
        // WhenAll drains every active worker before cancellation escapes. Only a returned result
        // may commit its progress: a canceled result has no consumer to receive its observations.
        await Task.WhenAll(Enumerable.Range(0, Math.Max(1, maxConcurrentLogs))
            .Select(_ => ProcessLogsAsync())).ConfigureAwait(false);

        if (state.StoppedAfterMatchedObservationTarget) {
            result.Warnings.Add(
                "Native CT exact-host lookup stopped after reaching the configured matched-observation target.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        cursor.Save(options.CursorStatePath);
        return result;
    }

    private async Task ProcessSharedLogAsync(
        SharedLogProcessingWorkItem workItem,
        HashSet<string> domainSet,
        HashSet<string> exactMatchDomainSet,
        NativeCtLogSubdomainDiscoveryOptions options,
        NativeCtCursorState cursor,
        NativeCtLogSubdomainDiscoveryBatchResult result,
        SharedBatchProcessingState state,
        InternalLogger? logger,
        CancellationToken cancellationToken) {
        NativeCtLogIngestionStatus status = workItem.Status;
        string logUrl = workItem.Descriptor.Url;

        try {
            var sth = await GetSignedTreeHeadAsync(logUrl, options, cancellationToken).ConfigureAwait(false);
            status.TreeSize = sth.TreeSize;

            var start = ComputeStartIndex(sth.TreeSize, cursor.GetLastProcessedIndex(workItem.CursorKey), options.InitialBackfillEntriesPerLog);
            if (start > 0 && !cursor.GetLastProcessedIndex(workItem.CursorKey).HasValue) cursor.SetLastProcessedIndex(workItem.CursorKey, start - 1);
            status.StartIndex = start;
            status.EstimatedLagBefore = start >= sth.TreeSize ? 0 : (sth.TreeSize - start);
            if (start >= sth.TreeSize) {
                cursor.SetLastProcessedIndex(workItem.CursorKey, sth.TreeSize - 1);
                cursor.RecordSuccess(workItem.CursorKey, DateTimeOffset.UtcNow);
                cursor.RecordSuccess(workItem.LogHealthKey, DateTimeOffset.UtcNow);
                status.EndIndex = sth.TreeSize - 1;
                status.LastProcessedIndex = sth.TreeSize - 1;
                status.EstimatedLagAfter = 0;
                status.Succeeded = true;
                lock (state.Sync) { result.LogsSucceeded++; }
                return;
            }

            var lag = Math.Max(0, sth.TreeSize - start);
            long end = sth.TreeSize - 1;
            int maxEntriesPerLog = ComputeEffectiveMaxEntriesPerLog(options, lag);
            status.EffectiveMaxEntriesPerLog = maxEntriesPerLog;
            if (maxEntriesPerLog > 0) {
                var maxEnd = start + Math.Max(0, maxEntriesPerLog - 1);
                if (maxEnd < end) {
                    end = maxEnd;
                }
            }
            status.EndIndex = end;

            int batchSize = ComputeEffectiveBatchSize(options, lag);
            status.EffectiveBatchSize = batchSize;

            var lastProcessed = start - 1;
            for (long batchStart = start; batchStart <= end; ) {
                cancellationToken.ThrowIfCancellationRequested();

                lock (state.Sync) {
                    if (result.ResultsCapped || state.StoppedAfterMatchedObservationTarget) {
                        break;
                    }
                }

                var batchEnd = batchStart + batchSize - 1;
                if (batchEnd > end) {
                    batchEnd = end;
                }

                var entries = await GetEntriesAsync(logUrl, batchStart, batchEnd, options, cancellationToken).ConfigureAwait(false);
                if (entries.Count == 0) {
                    break;
                }

                var shouldStop = false;
                try {
                    for (int i = 0; i < entries.Count; i++) {
                        cancellationToken.ThrowIfCancellationRequested();

                        lock (state.Sync) {
                            if (result.ResultsCapped || state.StoppedAfterMatchedObservationTarget) {
                                shouldStop = true;
                            } else if (options.MaxCtRowsToProcess > 0 &&
                                       result.CertificateObservationCount >= options.MaxCtRowsToProcess) {
                                result.ResultsCapped = true;
                                shouldStop = true;
                            } else if (TryProcessEntryForDomains(
                                           entries[i],
                                           domainSet,
                                           exactMatchDomainSet,
                                           options.MaxSubdomains,
                                           result,
                                           logger,
                                           out int matchedObservationCount)) {
                                lastProcessed = batchStart + i;
                                if (matchedObservationCount > 0) {
                                    result.CertificateObservationCount += matchedObservationCount;
                                    if (options.StopAfterMatchedObservations > 0 &&
                                        result.CertificateObservationCount >= options.StopAfterMatchedObservations) {
                                        state.StoppedAfterMatchedObservationTarget = true;
                                        shouldStop = true;
                                    }
                                }
                            } else {
                                result.ResultsCapped = true;
                                shouldStop = true;
                            }
                        }

                        if (shouldStop) {
                            break;
                        }
                    }
                } finally {
                    if (lastProcessed >= start) {
                        cursor.SetLastProcessedIndex(workItem.CursorKey, lastProcessed);
                    }
                }

                if (shouldStop) {
                    break;
                }

                batchStart += entries.Count;
            }

            int observationCountSnapshot;
            lock (state.Sync) {
                observationCountSnapshot = result.CertificateObservationCount;
            }

            logger?.WriteVerbose(
                "Native CT shared processed log {0}: observations={1}",
                logUrl,
                observationCountSnapshot);
            cursor.RecordSuccess(workItem.CursorKey, DateTimeOffset.UtcNow);
            cursor.RecordSuccess(workItem.LogHealthKey, DateTimeOffset.UtcNow);
            status.LastProcessedIndex = cursor.GetLastProcessedIndex(workItem.CursorKey);
            status.EstimatedLagAfter = status.TreeSize.HasValue
                ? ComputeRemainingLag(status.TreeSize.Value, status.LastProcessedIndex)
                : null;
            status.Succeeded = true;
            lock (state.Sync) { result.LogsSucceeded++; }
        } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
            throw;
        } catch (Exception ex) {
            (int failureThreshold, TimeSpan circuitDuration) = ResolveCircuitBreakerPolicy(ex, options, workItem.Descriptor);
            cursor.RecordFailure(
                workItem.CursorKey,
                DateTimeOffset.UtcNow,
                ex.Message,
                failureThreshold,
                circuitDuration);
            cursor.RecordFailure(
                workItem.LogHealthKey,
                DateTimeOffset.UtcNow,
                ex.Message,
                failureThreshold,
                circuitDuration);
            lock (state.Sync) {
                result.Warnings.Add($"Native CT shared log failed for {logUrl}: {ex.Message}");
            }
            logger?.WriteVerbose("Native CT shared log failed for {0}: {1}", logUrl, ex.Message);
            status.Failure = ex.Message;
            status.LastProcessedIndex = cursor.GetLastProcessedIndex(workItem.CursorKey);
            status.EstimatedLagAfter = status.TreeSize.HasValue
                ? ComputeRemainingLag(status.TreeSize.Value, status.LastProcessedIndex)
                : null;
            if (cursor.IsCircuitOpen(workItem.LogHealthKey, DateTimeOffset.UtcNow, out var openUntilUtc)) {
                status.CircuitOpenUntilUtc = openUntilUtc;
            }
        }
    }

}
