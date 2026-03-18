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

internal sealed class NativeCtLogSubdomainDiscoveryOptions {
    public string BaseDomain { get; set; } = string.Empty;
    public bool ExactMatchOnly { get; set; }
    public IReadOnlyCollection<string> ExactMatchDomains { get; set; } = Array.Empty<string>();
    public bool PrioritizeLatestExactMatch { get; set; }
    public int StopAfterMatchedObservations { get; set; }
    public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(15);
    public int MaxCtRowsToProcess { get; set; } = 10000;
    public int MaxSubdomains { get; set; } = 10000;
    public string LogListUrl { get; set; } = "https://www.gstatic.com/ct/log_list/v3/log_list.json";
    public IReadOnlyList<string> ExplicitLogUrls { get; set; } = Array.Empty<string>();
    public IReadOnlyList<string> PreferredLogUrlPrefixes { get; set; } = Array.Empty<string>();
    public IReadOnlyList<string> ExcludedLogUrlPrefixes { get; set; } = Array.Empty<string>();
    public int MaxLogsToProcess { get; set; } = 12;
    public int MaxEntriesPerLog { get; set; } = 2000;
    public int EntryBatchSize { get; set; } = 256;
    public int InitialBackfillEntriesPerLog { get; set; } = 2000;
    public string? CursorStatePath { get; set; }
    public bool IncludePendingLogs { get; set; }
    public bool IncludeRetiredLogs { get; set; } = true;
    public TimeSpan RequestDelay { get; set; } = TimeSpan.Zero;
    public int RetryCount { get; set; } = 3;
    public TimeSpan RetryBaseDelay { get; set; } = TimeSpan.FromMilliseconds(500);
    public TimeSpan RetryMaxDelay { get; set; } = TimeSpan.FromSeconds(10);
    public int CircuitBreakerFailureThreshold { get; set; } = 3;
    public TimeSpan CircuitBreakerDuration { get; set; } = TimeSpan.FromMinutes(10);
    public bool EnableCatchUpMode { get; set; } = true;
    public int CatchUpLagThreshold { get; set; } = 50_000;
    public int CatchUpMaxEntriesPerLog { get; set; } = 20_000;
    public int CatchUpBatchSize { get; set; } = 1_024;
}

internal sealed class NativeCtLogSubdomainDiscoveryResult {
    public int CertificateObservationCount { get; set; }
    public bool ResultsCapped { get; set; }
    public DateTimeOffset? FirstSeenUtc { get; set; }
    public DateTimeOffset? LastSeenUtc { get; set; }
    public Dictionary<string, int> IssuerCounts { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, NativeCtSubdomainObservation> Subdomains { get; } = new(StringComparer.OrdinalIgnoreCase);
    public int LogsAttempted { get; set; }
    public int LogsSucceeded { get; set; }
    public List<string> Warnings { get; } = new();
    public List<NativeCtLogIngestionStatus> LogStatuses { get; } = new();
    public bool SourceSucceeded => LogsSucceeded > 0;
}

internal sealed class NativeCtLogSubdomainDiscoveryBatchResult {
    public int CertificateObservationCount { get; set; }
    public bool ResultsCapped { get; set; }
    public int LogsAttempted { get; set; }
    public int LogsSucceeded { get; set; }
    public List<string> Warnings { get; } = new();
    public List<NativeCtLogIngestionStatus> LogStatuses { get; } = new();
    public Dictionary<string, Dictionary<string, NativeCtSubdomainObservation>> SubdomainsByDomain { get; }
        = new(StringComparer.OrdinalIgnoreCase);
    public bool SourceSucceeded => LogsSucceeded > 0;
}

internal sealed class NativeCtSubdomainObservation {
    public DateTimeOffset? FirstSeenUtc { get; set; }
    public DateTimeOffset? LastSeenUtc { get; set; }
    public DateTimeOffset? LatestCertificateCtEntryTimestampUtc { get; set; }
    public string? LatestCertificateSubject { get; set; }
    public string? LatestCertificateIssuer { get; set; }
    public string? LatestCertificateSerialNumber { get; set; }
    public DateTimeOffset? LatestCertificateNotBeforeUtc { get; set; }
    public DateTimeOffset? LatestCertificateNotAfterUtc { get; set; }
    public int CertificateObservationCount { get; set; }
}

internal sealed class NativeCtLogIngestionStatus {
    public string LogUrl { get; set; } = string.Empty;
    public string CursorKey { get; set; } = string.Empty;
    public string? DomainScope { get; set; }
    public bool SharedIngestion { get; set; }
    public bool IsRetired { get; set; }
    public bool SkippedByCircuitBreaker { get; set; }
    public bool Succeeded { get; set; }
    public string? Failure { get; set; }
    public DateTimeOffset? CircuitOpenUntilUtc { get; set; }
    public long? TreeSize { get; set; }
    public long? StartIndex { get; set; }
    public long? EndIndex { get; set; }
    public long? LastProcessedIndex { get; set; }
    public long? EstimatedLagBefore { get; set; }
    public long? EstimatedLagAfter { get; set; }
    public int? EffectiveMaxEntriesPerLog { get; set; }
    public int? EffectiveBatchSize { get; set; }
}

internal sealed partial class NativeCtLogSubdomainDiscovery {
    private sealed class ResolvedCtLogDescriptor {
        public string Url { get; init; } = string.Empty;
        public DateTimeOffset? TemporalStartUtc { get; init; }
        public DateTimeOffset? TemporalEndUtc { get; init; }
        public bool IsRetired { get; init; }
        public int SourceOrder { get; init; }
    }

    private const int X509EntryType = 0;
    private const int PrecertEntryType = 1;
    private const string SubjectAlternativeNameOid = "2.5.29.17";
    private const string HistoricalAllLogsListUrl = "https://www.gstatic.com/ct/log_list/v2/all_logs_list.json";
    private const string KnownBogusCtLogUrlPrefix = "https://ct.example.com/bogus/";

    public Func<string, CancellationToken, Task<string>>? QueryOverride { get; set; }

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
                result.LogsSucceeded++;
                var start = ComputeStartIndex(sth.TreeSize, cursor.GetLastProcessedIndex(key), options.InitialBackfillEntriesPerLog);
                status.StartIndex = start;
                status.EstimatedLagBefore = start >= sth.TreeSize ? 0 : (sth.TreeSize - start);
                if (start >= sth.TreeSize) {
                    cursor.SetLastProcessedIndex(key, sth.TreeSize - 1);
                    cursor.RecordSuccess(key, DateTimeOffset.UtcNow);
                    status.EndIndex = sth.TreeSize - 1;
                    status.LastProcessedIndex = sth.TreeSize - 1;
                    status.EstimatedLagAfter = 0;
                    status.Succeeded = true;
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
                            lastProcessed = batchStart + i;
                            break;
                        }
                    }

                    if (lastProcessed >= start) {
                        cursor.SetLastProcessedIndex(key, lastProcessed);
                    }

                    if (result.ResultsCapped) {
                        break;
                    }
                    if (stoppedAfterMatchedObservationTarget) {
                        break;
                    }

                    batchStart = batchEnd + 1;
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

                if (result.ResultsCapped) {
                    break;
                }
                if (stoppedAfterMatchedObservationTarget) {
                    break;
                }
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
        var stoppedAfterMatchedObservationTarget = false;
        var consumedLogBudget = 0;
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

            try {
                if (cursor.IsCircuitOpen(logHealthKey, DateTimeOffset.UtcNow, out var openUntilUtc)) {
                    result.Warnings.Add($"Native CT shared log skipped (circuit open) for {logUrl} until {openUntilUtc:O}");
                    status.SkippedByCircuitBreaker = true;
                    status.CircuitOpenUntilUtc = openUntilUtc;
                    continue;
                }

                consumedLogBudget++;
                var sth = await GetSignedTreeHeadAsync(logUrl, options, cancellationToken).ConfigureAwait(false);
                status.TreeSize = sth.TreeSize;
                result.LogsSucceeded++;
                var start = ComputeStartIndex(sth.TreeSize, cursor.GetLastProcessedIndex(key), options.InitialBackfillEntriesPerLog);
                status.StartIndex = start;
                status.EstimatedLagBefore = start >= sth.TreeSize ? 0 : (sth.TreeSize - start);
                if (start >= sth.TreeSize) {
                    cursor.SetLastProcessedIndex(key, sth.TreeSize - 1);
                    cursor.RecordSuccess(key, DateTimeOffset.UtcNow);
                    status.EndIndex = sth.TreeSize - 1;
                    status.LastProcessedIndex = sth.TreeSize - 1;
                    status.EstimatedLagAfter = 0;
                    status.Succeeded = true;
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

                    for (int i = 0; i < entries.Count; i++) {
                        cancellationToken.ThrowIfCancellationRequested();

                        if (options.MaxCtRowsToProcess > 0 && result.CertificateObservationCount >= options.MaxCtRowsToProcess) {
                            result.ResultsCapped = true;
                            break;
                        }

                        if (TryProcessEntryForDomains(entries[i], domainSet, exactMatchDomainSet, options.MaxSubdomains, result, logger, out var matchedObservationCount)) {
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
                            lastProcessed = batchStart + i;
                            break;
                        }
                    }

                    if (lastProcessed >= start) {
                        cursor.SetLastProcessedIndex(key, lastProcessed);
                    }

                    if (result.ResultsCapped) {
                        break;
                    }
                    if (stoppedAfterMatchedObservationTarget) {
                        break;
                    }

                    batchStart = batchEnd + 1;
                }

                logger?.WriteVerbose(
                    "Native CT shared processed log {0}: observations={1}",
                    logUrl,
                    result.CertificateObservationCount);
                cursor.RecordSuccess(key, DateTimeOffset.UtcNow);
                cursor.RecordSuccess(logHealthKey, DateTimeOffset.UtcNow);
                status.LastProcessedIndex = cursor.GetLastProcessedIndex(key);
                status.EstimatedLagAfter = status.TreeSize.HasValue
                    ? ComputeRemainingLag(status.TreeSize.Value, status.LastProcessedIndex)
                    : null;
                status.Succeeded = true;

                if (result.ResultsCapped) {
                    break;
                }
                if (stoppedAfterMatchedObservationTarget) {
                    break;
                }
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
                result.Warnings.Add($"Native CT shared log failed for {logUrl}: {ex.Message}");
                logger?.WriteVerbose("Native CT shared log failed for {0}: {1}", logUrl, ex.Message);
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

        cursor.Save(options.CursorStatePath);
        return result;
    }

    private async Task<IReadOnlyList<ResolvedCtLogDescriptor>> ResolveLogUrlsAsync(
        NativeCtLogSubdomainDiscoveryOptions options,
        CancellationToken cancellationToken,
        bool applyCap) {
        var descriptors = new Dictionary<string, ResolvedCtLogDescriptor>(StringComparer.OrdinalIgnoreCase);
        var sourceOrder = 0;
        if (options.ExplicitLogUrls != null && options.ExplicitLogUrls.Count > 0) {
            foreach (var raw in options.ExplicitLogUrls) {
                var normalized = NormalizeLogUrl(raw);
                if (normalized != null) {
                    AddResolvedLogDescriptor(descriptors, normalized, null, null, isRetired: false, sourceOrder++);
                }
            }
            IReadOnlyList<ResolvedCtLogDescriptor> explicitDescriptors = ApplyLogSelectionPolicy(descriptors.Values.ToList(), options);
            return applyCap
                ? ApplyLogCap(explicitDescriptors, options.MaxLogsToProcess, options.PrioritizeLatestExactMatch)
                : BuildExtendedProcessingOrder(explicitDescriptors, options.MaxLogsToProcess, options.PrioritizeLatestExactMatch);
        }

        if (string.IsNullOrWhiteSpace(options.LogListUrl)) {
            return Array.Empty<ResolvedCtLogDescriptor>();
        }

        var logListUrls = new List<string> { options.LogListUrl };
        if (options.IncludeRetiredLogs &&
            !string.Equals(options.LogListUrl, HistoricalAllLogsListUrl, StringComparison.OrdinalIgnoreCase)) {
            logListUrls.Add(HistoricalAllLogsListUrl);
        }

        foreach (var logListUrl in logListUrls) {
            sourceOrder = await PopulateDescriptorsFromLogListAsync(
                logListUrl,
                options,
                descriptors,
                cancellationToken,
                sourceOrder).ConfigureAwait(false);
        }

        var resolvedDescriptors = descriptors.Values.ToList();
        var eligibleDescriptors = ApplyLogSelectionPolicy(
            FilterLogsForCurrentQuery(resolvedDescriptors, DateTimeOffset.UtcNow),
            options);
        return applyCap
            ? ApplyLogCap(eligibleDescriptors, options.MaxLogsToProcess, options.PrioritizeLatestExactMatch)
            : BuildExtendedProcessingOrder(eligibleDescriptors, options.MaxLogsToProcess, options.PrioritizeLatestExactMatch);
    }

    private static bool HasConsumedLogBudget(int maxLogsToProcess, int consumedLogBudget) {
        return maxLogsToProcess > 0 && consumedLogBudget >= maxLogsToProcess;
    }

    private static IReadOnlyList<ResolvedCtLogDescriptor> PrioritizeLogDescriptorsByHealth(
        IReadOnlyList<ResolvedCtLogDescriptor> logDescriptors,
        NativeCtCursorState cursor,
        NativeCtLogSubdomainDiscoveryOptions options,
        DateTimeOffset observedUtc) {
        if (logDescriptors == null || logDescriptors.Count <= 1 || cursor == null || options == null || options.MaxLogsToProcess <= 0) {
            return logDescriptors ?? Array.Empty<ResolvedCtLogDescriptor>();
        }

        var preferredPrefixes = NormalizeLogUrlPrefixes(options.PreferredLogUrlPrefixes);
        int selectedCount = Math.Min(options.MaxLogsToProcess, logDescriptors.Count);
        return logDescriptors
            .Select((descriptor, index) => new {
                Descriptor = descriptor,
                Index = index,
                SelectedBoost = index < selectedCount ? 0 : 1,
                HealthPriority = ClassifyLogHealthPriority(cursor, descriptor.Url, observedUtc),
                PolicyPriority = preferredPrefixes.Count > 0 && MatchesAnyPrefix(descriptor.Url, preferredPrefixes) ? 0 : 1,
                LastSuccessUtc = GetLastSuccessUtc(cursor, descriptor.Url),
                CircuitOpenUntilUtc = GetCircuitOpenUntilUtc(cursor, descriptor.Url)
            })
            .OrderBy(static row => row.HealthPriority)
            .ThenBy(static row => row.PolicyPriority)
            .ThenBy(static row => row.SelectedBoost)
            .ThenByDescending(static row => row.LastSuccessUtc ?? DateTimeOffset.MinValue)
            .ThenBy(static row => row.CircuitOpenUntilUtc ?? DateTimeOffset.MaxValue)
            .ThenBy(static row => row.Index)
            .Select(static row => row.Descriptor)
            .ToList();
    }

    private static IReadOnlyList<ResolvedCtLogDescriptor> ApplyLogSelectionPolicy(
        IReadOnlyList<ResolvedCtLogDescriptor> logDescriptors,
        NativeCtLogSubdomainDiscoveryOptions options) {
        if (logDescriptors == null || logDescriptors.Count == 0) {
            return Array.Empty<ResolvedCtLogDescriptor>();
        }

        var excludedPrefixes = NormalizeLogUrlPrefixes(options.ExcludedLogUrlPrefixes);
        var preferredPrefixes = NormalizeLogUrlPrefixes(options.PreferredLogUrlPrefixes);

        IEnumerable<ResolvedCtLogDescriptor> filtered = logDescriptors;
        if (excludedPrefixes.Count > 0) {
            filtered = filtered.Where(descriptor => !MatchesAnyPrefix(descriptor.Url, excludedPrefixes));
        }

        return filtered
            .Select((descriptor, index) => new {
                Descriptor = descriptor,
                Index = index,
                Preferred = preferredPrefixes.Count > 0 && MatchesAnyPrefix(descriptor.Url, preferredPrefixes)
            })
            .OrderBy(static row => row.Preferred ? 0 : 1)
            .ThenBy(static row => row.Index)
            .Select(static row => row.Descriptor)
            .ToList();
    }

    private static List<string> NormalizeLogUrlPrefixes(IReadOnlyList<string>? rawPrefixes) {
        if (rawPrefixes == null || rawPrefixes.Count == 0) {
            return new List<string>();
        }

        var normalized = new List<string>(rawPrefixes.Count);
        foreach (var rawPrefix in rawPrefixes) {
            var prefix = NormalizeLogUrl(rawPrefix);
            if (!string.IsNullOrWhiteSpace(prefix) &&
                !normalized.Contains(prefix, StringComparer.OrdinalIgnoreCase)) {
                normalized.Add(prefix!);
            }
        }

        return normalized;
    }

    private static bool MatchesAnyPrefix(string logUrl, IReadOnlyList<string> prefixes) {
        if (string.IsNullOrWhiteSpace(logUrl) || prefixes == null || prefixes.Count == 0) {
            return false;
        }

        foreach (var prefix in prefixes) {
            if (!string.IsNullOrWhiteSpace(prefix) &&
                logUrl.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) {
                return true;
            }
        }

        return false;
    }

    private static IReadOnlyList<ResolvedCtLogDescriptor> BuildExtendedProcessingOrder(
        IReadOnlyList<ResolvedCtLogDescriptor> logs,
        int maxLogsToProcess,
        bool prioritizeLatestExactMatch) {
        IReadOnlyList<ResolvedCtLogDescriptor> prioritized = ApplyLogCap(logs, maxLogsToProcess, prioritizeLatestExactMatch);
        IReadOnlyList<ResolvedCtLogDescriptor> uncapped = ApplyLogCap(logs, 0, prioritizeLatestExactMatch);
        if (prioritized.Count == 0) {
            return uncapped;
        }

        var ordered = new List<ResolvedCtLogDescriptor>(uncapped.Count);
        var selectedUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (ResolvedCtLogDescriptor descriptor in prioritized) {
            if (selectedUrls.Add(descriptor.Url)) {
                ordered.Add(descriptor);
            }
        }

        foreach (ResolvedCtLogDescriptor descriptor in uncapped) {
            if (selectedUrls.Add(descriptor.Url)) {
                ordered.Add(descriptor);
            }
        }

        return ordered;
    }

    private static int ClassifyLogHealthPriority(
        NativeCtCursorState cursor,
        string logUrl,
        DateTimeOffset observedUtc) {
        if (!cursor.TryGetLogHealthSnapshot(logUrl, out NativeCtCursorEntrySnapshot snapshot)) {
            return 1;
        }

        if (snapshot.CircuitOpenUntilUtc.HasValue && snapshot.CircuitOpenUntilUtc.Value > observedUtc) {
            return 4;
        }

        if (snapshot.LastSuccessUtc.HasValue &&
            (!snapshot.LastAttemptUtc.HasValue || snapshot.LastSuccessUtc.Value >= snapshot.LastAttemptUtc.Value)) {
            return 0;
        }

        if (!snapshot.LastAttemptUtc.HasValue) {
            return 1;
        }

        return IsLikelyPermanentNativeCtFailure(snapshot.LastError)
            ? 3
            : 2;
    }

    private static DateTimeOffset? GetLastSuccessUtc(NativeCtCursorState cursor, string logUrl) {
        return cursor.TryGetLogHealthSnapshot(logUrl, out NativeCtCursorEntrySnapshot snapshot)
            ? snapshot.LastSuccessUtc
            : null;
    }

    private static DateTimeOffset? GetCircuitOpenUntilUtc(NativeCtCursorState cursor, string logUrl) {
        return cursor.TryGetLogHealthSnapshot(logUrl, out NativeCtCursorEntrySnapshot snapshot)
            ? snapshot.CircuitOpenUntilUtc
            : null;
    }

    private async Task<int> PopulateDescriptorsFromLogListAsync(
        string logListUrl,
        NativeCtLogSubdomainDiscoveryOptions options,
        IDictionary<string, ResolvedCtLogDescriptor> descriptors,
        CancellationToken cancellationToken,
        int sourceOrder) {
        if (string.IsNullOrWhiteSpace(logListUrl)) {
            return sourceOrder;
        }

        var json = await FetchJsonWithRetryAsync(logListUrl, options, cancellationToken).ConfigureAwait(false);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object) {
            return sourceOrder;
        }

        if (root.TryGetProperty("operators", out var operatorsElement) && operatorsElement.ValueKind == JsonValueKind.Array) {
            foreach (var op in operatorsElement.EnumerateArray()) {
                if (op.ValueKind != JsonValueKind.Object) {
                    continue;
                }
                if (!op.TryGetProperty("logs", out var logsElement) || logsElement.ValueKind != JsonValueKind.Array) {
                    continue;
                }
                foreach (var log in logsElement.EnumerateArray()) {
                    TryAddLogFromListItem(log, options, descriptors, ref sourceOrder);
                }
            }
            return sourceOrder;
        }

        if (root.TryGetProperty("logs", out var legacyLogs) && legacyLogs.ValueKind == JsonValueKind.Array) {
            foreach (var log in legacyLogs.EnumerateArray()) {
                TryAddLogFromListItem(log, options, descriptors, ref sourceOrder);
            }
        }

        return sourceOrder;
    }

    internal static IReadOnlyList<string> ApplyLogCap(
        IReadOnlyList<(string Url, DateTimeOffset? TemporalStartUtc, DateTimeOffset? TemporalEndUtc)> logs,
        int maxLogsToProcess) {
        return ApplyLogCap(logs, maxLogsToProcess, prioritizeLatestExactMatch: false);
    }

    internal static IReadOnlyList<string> ApplyLogCap(
        IReadOnlyList<(string Url, DateTimeOffset? TemporalStartUtc, DateTimeOffset? TemporalEndUtc)> logs,
        int maxLogsToProcess,
        bool prioritizeLatestExactMatch) {
        if (logs == null || logs.Count == 0) {
            return Array.Empty<string>();
        }

        var descriptors = new List<ResolvedCtLogDescriptor>(logs.Count);
        for (var i = 0; i < logs.Count; i++) {
            var log = logs[i];
            if (string.IsNullOrWhiteSpace(log.Url)) {
                continue;
            }

            descriptors.Add(new ResolvedCtLogDescriptor {
                Url = log.Url,
                TemporalStartUtc = log.TemporalStartUtc,
                TemporalEndUtc = log.TemporalEndUtc,
                SourceOrder = i
            });
        }

        return ApplyLogCap(descriptors, maxLogsToProcess, prioritizeLatestExactMatch)
            .Select(static descriptor => descriptor.Url)
            .ToList();
    }

    private static IReadOnlyList<ResolvedCtLogDescriptor> ApplyLogCap(
        IReadOnlyList<ResolvedCtLogDescriptor> logs,
        int maxLogsToProcess,
        bool prioritizeLatestExactMatch) {
        IReadOnlyList<ResolvedCtLogDescriptor> normalizedLogs = logs
            .Where(static log => log != null && !string.IsNullOrWhiteSpace(log.Url))
            .ToList();
        if (normalizedLogs.Count == 0) {
            return Array.Empty<ResolvedCtLogDescriptor>();
        }

        bool containsRetiredLogs = normalizedLogs.Any(static log => log.IsRetired);
        if (!containsRetiredLogs) {
            return ApplyLogCapWithoutRetiredBias(normalizedLogs, maxLogsToProcess, prioritizeLatestExactMatch);
        }

        var currentLogs = normalizedLogs
            .Where(static log => !log.IsRetired)
            .ToList();
        var retiredLogs = normalizedLogs
            .Where(static log => log.IsRetired)
            .ToList();

        if (retiredLogs.Count == 0) {
            return ApplyLogCapWithoutRetiredBias(currentLogs, maxLogsToProcess, prioritizeLatestExactMatch);
        }

        if (maxLogsToProcess <= 0 || normalizedLogs.Count <= maxLogsToProcess) {
            var orderedCurrent = ApplyLogCapWithoutRetiredBias(currentLogs, 0, prioritizeLatestExactMatch);
            var orderedRetired = ApplyLogCapWithoutRetiredBias(retiredLogs, 0, prioritizeLatestExactMatch: true);
            return orderedCurrent.Concat(orderedRetired).ToList();
        }

        int retiredBudget = Math.Min(retiredLogs.Count, ComputeHistoricalRetiredLogBudget(maxLogsToProcess));
        int currentBudget = Math.Max(0, maxLogsToProcess - retiredBudget);

        var selected = new List<ResolvedCtLogDescriptor>(maxLogsToProcess);
        var selectedUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (ResolvedCtLogDescriptor descriptor in ApplyLogCapWithoutRetiredBias(
                     currentLogs,
                     currentBudget,
                     prioritizeLatestExactMatch: true))
        {
            if (selected.Count >= maxLogsToProcess) {
                break;
            }

            if (selectedUrls.Add(descriptor.Url)) {
                selected.Add(descriptor);
            }
        }

        foreach (ResolvedCtLogDescriptor descriptor in ApplyLogCapWithoutRetiredBias(
                     retiredLogs,
                     retiredBudget,
                     prioritizeLatestExactMatch: true))
        {
            if (selected.Count >= maxLogsToProcess) {
                break;
            }

            if (selectedUrls.Add(descriptor.Url)) {
                selected.Add(descriptor);
            }
        }

        if (selected.Count < maxLogsToProcess) {
            foreach (ResolvedCtLogDescriptor descriptor in ApplyLogCapWithoutRetiredBias(
                         retiredLogs,
                         0,
                         prioritizeLatestExactMatch: true))
            {
                if (selected.Count >= maxLogsToProcess) {
                    break;
                }

                if (selectedUrls.Add(descriptor.Url)) {
                    selected.Add(descriptor);
                }
            }
        }

        return selected;
    }

    private static IReadOnlyList<ResolvedCtLogDescriptor> FilterLogsForCurrentQuery(
        IReadOnlyList<ResolvedCtLogDescriptor> logs,
        DateTimeOffset observedUtc) {
        if (logs == null || logs.Count == 0) {
            return Array.Empty<ResolvedCtLogDescriptor>();
        }

        var eligible = logs
            .Where(log => log != null && !IsFutureLog(log, observedUtc))
            .ToList();

        return eligible;
    }

    private static bool IsFutureLog(ResolvedCtLogDescriptor log, DateTimeOffset observedUtc) {
        if (log == null || !log.TemporalStartUtc.HasValue) {
            return false;
        }

        return log.TemporalStartUtc.Value > observedUtc;
    }

    private static IReadOnlyList<ResolvedCtLogDescriptor> ApplyLogCapWithoutRetiredBias(
        IReadOnlyList<ResolvedCtLogDescriptor> logs,
        int maxLogsToProcess,
        bool prioritizeLatestExactMatch) {
        var ordered = logs
            .OrderBy(static log => log.SourceOrder)
            .ThenBy(static log => log.Url, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var dated = ordered
            .Where(static log => log.TemporalStartUtc.HasValue || log.TemporalEndUtc.HasValue)
            .OrderBy(static log => log.TemporalStartUtc ?? log.TemporalEndUtc ?? DateTimeOffset.MinValue)
            .ThenBy(static log => log.TemporalEndUtc ?? DateTimeOffset.MaxValue)
            .ThenBy(static log => log.Url, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var undated = ordered
            .Where(static log => !log.TemporalStartUtc.HasValue && !log.TemporalEndUtc.HasValue)
            .ToList();

        if (maxLogsToProcess <= 0 || ordered.Count <= maxLogsToProcess) {
            return prioritizeLatestExactMatch
                ? BuildLatestFirstProcessingOrder(dated, undated)
                : BuildDistributedProcessingOrder(dated, undated);
        }

        var selected = new List<ResolvedCtLogDescriptor>(maxLogsToProcess);
        var selectedUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (dated.Count > 0) {
            foreach (var index in SelectEvenlyDistributedIndices(dated.Count, Math.Min(maxLogsToProcess, dated.Count))) {
                var descriptor = dated[index];
                if (selectedUrls.Add(descriptor.Url)) {
                    selected.Add(descriptor);
                }
            }
        }

        foreach (var descriptor in ordered) {
            if (selected.Count >= maxLogsToProcess) {
                break;
            }

            if (selectedUrls.Add(descriptor.Url)) {
                selected.Add(descriptor);
            }
        }

        var selectedDated = selected
            .Where(static log => log.TemporalStartUtc.HasValue || log.TemporalEndUtc.HasValue)
            .OrderBy(static log => log.TemporalStartUtc ?? log.TemporalEndUtc ?? DateTimeOffset.MinValue)
            .ThenBy(static log => log.TemporalEndUtc ?? DateTimeOffset.MaxValue)
            .ThenBy(static log => log.Url, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var selectedUndated = selected
            .Where(static log => !log.TemporalStartUtc.HasValue && !log.TemporalEndUtc.HasValue)
            .OrderBy(static log => log.SourceOrder)
            .ThenBy(static log => log.Url, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return prioritizeLatestExactMatch
            ? BuildLatestFirstProcessingOrder(selectedDated, selectedUndated)
            : BuildDistributedProcessingOrder(selectedDated, selectedUndated);
    }

    private static int ComputeHistoricalRetiredLogBudget(int maxLogsToProcess) {
        if (maxLogsToProcess <= 1) {
            return 0;
        }

        return Math.Max(1, maxLogsToProcess / 6);
    }

    private static IReadOnlyList<ResolvedCtLogDescriptor> BuildDistributedProcessingOrder(
        IReadOnlyList<ResolvedCtLogDescriptor> dated,
        IReadOnlyList<ResolvedCtLogDescriptor> undated) {
        var output = new List<ResolvedCtLogDescriptor>((dated?.Count ?? 0) + (undated?.Count ?? 0));
        if (dated != null && dated.Count > 0) {
            var left = 0;
            var right = dated.Count - 1;
            while (left <= right) {
                output.Add(dated[left]);
                if (right != left) {
                    output.Add(dated[right]);
                }
                left++;
                right--;
            }
        }

        if (undated != null && undated.Count > 0) {
            output.AddRange(undated);
        }

        return output;
    }

    private static IReadOnlyList<ResolvedCtLogDescriptor> BuildLatestFirstProcessingOrder(
        IReadOnlyList<ResolvedCtLogDescriptor> dated,
        IReadOnlyList<ResolvedCtLogDescriptor> undated) {
        var output = new List<ResolvedCtLogDescriptor>((dated?.Count ?? 0) + (undated?.Count ?? 0));
        if (dated != null && dated.Count > 0) {
            output.AddRange(dated
                .OrderByDescending(static log => log.TemporalEndUtc ?? log.TemporalStartUtc ?? DateTimeOffset.MinValue)
                .ThenByDescending(static log => log.TemporalStartUtc ?? DateTimeOffset.MinValue)
                .ThenBy(static log => log.SourceOrder)
                .ThenBy(static log => log.Url, StringComparer.OrdinalIgnoreCase));
        }

        if (undated != null && undated.Count > 0) {
            output.AddRange(undated
                .OrderBy(static log => log.SourceOrder)
                .ThenBy(static log => log.Url, StringComparer.OrdinalIgnoreCase));
        }

        return output;
    }

    private static void TryAddLogFromListItem(
        JsonElement log,
        NativeCtLogSubdomainDiscoveryOptions options,
        IDictionary<string, ResolvedCtLogDescriptor> descriptors,
        ref int sourceOrder) {
        if (log.ValueKind != JsonValueKind.Object) {
            return;
        }
        if (!ShouldIncludeLog(log, options.IncludePendingLogs, options.IncludeRetiredLogs)) {
            return;
        }
        var description = GetString(log, "description");
        var url = GetString(log, "url");
        var normalized = NormalizeLogUrl(url);
        if (normalized != null &&
            !IsKnownBogusLog(normalized, description)) {
            TryGetTemporalInterval(log, out var temporalStartUtc, out var temporalEndUtc);
            AddResolvedLogDescriptor(
                descriptors,
                normalized,
                temporalStartUtc,
                temporalEndUtc,
                IsRetiredLog(log),
                sourceOrder++);
        }
    }

    private static void AddResolvedLogDescriptor(
        IDictionary<string, ResolvedCtLogDescriptor> descriptors,
        string url,
        DateTimeOffset? temporalStartUtc,
        DateTimeOffset? temporalEndUtc,
        bool isRetired,
        int sourceOrder) {
        if (string.IsNullOrWhiteSpace(url)) {
            return;
        }

        if (descriptors.TryGetValue(url, out var existing)) {
            descriptors[url] = new ResolvedCtLogDescriptor {
                Url = url,
                TemporalStartUtc = existing.TemporalStartUtc ?? temporalStartUtc,
                TemporalEndUtc = existing.TemporalEndUtc ?? temporalEndUtc,
                IsRetired = existing.IsRetired || isRetired,
                SourceOrder = Math.Min(existing.SourceOrder, sourceOrder)
            };
            return;
        }

        descriptors[url] = new ResolvedCtLogDescriptor {
            Url = url,
            TemporalStartUtc = temporalStartUtc,
            TemporalEndUtc = temporalEndUtc,
            IsRetired = isRetired,
            SourceOrder = sourceOrder
        };
    }

    private static void TryGetTemporalInterval(
        JsonElement log,
        out DateTimeOffset? temporalStartUtc,
        out DateTimeOffset? temporalEndUtc) {
        temporalStartUtc = null;
        temporalEndUtc = null;
        if (!log.TryGetProperty("temporal_interval", out var temporalInterval) || temporalInterval.ValueKind != JsonValueKind.Object) {
            return;
        }

        temporalStartUtc = ParseCtLogIntervalTimestamp(
            GetString(temporalInterval, "start_inclusive") ??
            GetString(temporalInterval, "start"));
        temporalEndUtc = ParseCtLogIntervalTimestamp(
            GetString(temporalInterval, "end_exclusive") ??
            GetString(temporalInterval, "end_inclusive") ??
            GetString(temporalInterval, "end"));
    }

    private static DateTimeOffset? ParseCtLogIntervalTimestamp(string? value) {
        if (string.IsNullOrWhiteSpace(value)) {
            return null;
        }

        return DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
            ? parsed
            : null;
    }

    private static IReadOnlyList<int> SelectEvenlyDistributedIndices(int totalCount, int selectionCount) {
        if (totalCount <= 0 || selectionCount <= 0) {
            return Array.Empty<int>();
        }

        if (selectionCount >= totalCount) {
            return Enumerable.Range(0, totalCount).ToList();
        }

        if (selectionCount == 1) {
            return new[] { totalCount - 1 };
        }

        var selected = new List<int>(selectionCount);
        for (var i = 0; i < selectionCount; i++) {
            var index = (int)Math.Round(i * (totalCount - 1d) / (selectionCount - 1d), MidpointRounding.AwayFromZero);
            if (selected.Count == 0 || selected[selected.Count - 1] != index) {
                selected.Add(index);
            }
        }

        var cursor = 0;
        while (selected.Count < selectionCount && cursor < totalCount) {
            if (!selected.Contains(cursor)) {
                selected.Add(cursor);
            }
            cursor++;
        }

        selected.Sort();
        return selected;
    }

    private static bool ShouldIncludeLog(JsonElement log, bool includePendingLogs, bool includeRetiredLogs) {
        if (!log.TryGetProperty("state", out var state) || state.ValueKind != JsonValueKind.Object) {
            return true;
        }

        if (state.TryGetProperty("rejected", out _)) {
            return false;
        }
        if (state.TryGetProperty("retired", out _)) {
            return includeRetiredLogs;
        }
        if (state.TryGetProperty("usable", out _)) {
            return true;
        }
        if (state.TryGetProperty("qualified", out _)) {
            return true;
        }
        if (state.TryGetProperty("readonly", out _)) {
            return true;
        }
        if (state.TryGetProperty("pending", out _)) {
            return includePendingLogs;
        }

        return true;
    }

    private static bool IsRetiredLog(JsonElement log) {
        if (!log.TryGetProperty("state", out var state) || state.ValueKind != JsonValueKind.Object) {
            return false;
        }

        return state.TryGetProperty("retired", out _);
    }

    private static bool IsKnownBogusLog(string normalizedUrl, string? description) {
        if (string.IsNullOrWhiteSpace(normalizedUrl)) {
            return false;
        }

        if (normalizedUrl.StartsWith(KnownBogusCtLogUrlPrefix, StringComparison.OrdinalIgnoreCase)) {
            return true;
        }

        return !string.IsNullOrWhiteSpace(description) &&
               description!.Contains("Bogus RFC6962 log", StringComparison.OrdinalIgnoreCase);
    }

    private static (int FailureThreshold, TimeSpan CircuitDuration) ResolveCircuitBreakerPolicy(
        Exception exception,
        NativeCtLogSubdomainDiscoveryOptions options,
        ResolvedCtLogDescriptor logDescriptor) {
        int defaultThreshold = Math.Max(1, options.CircuitBreakerFailureThreshold);
        TimeSpan defaultDuration = options.CircuitBreakerDuration <= TimeSpan.Zero
            ? TimeSpan.FromMinutes(10)
            : options.CircuitBreakerDuration;
        string? errorMessage = exception?.Message;
        bool retiredLog = logDescriptor != null && logDescriptor.IsRetired;
        if (IsNameResolutionFailure(errorMessage)) {
            return (1, ClampCircuitDuration(retiredLog
                ? TimeSpan.FromHours(24)
                : TimeSpan.FromHours(6), defaultDuration));
        }

        if (IsPermanentHttpLogFailure(exception)) {
            return (1, ClampCircuitDuration(retiredLog
                ? TimeSpan.FromHours(24)
                : TimeSpan.FromHours(6), defaultDuration));
        }

        return (defaultThreshold, defaultDuration);
    }

    private static TimeSpan ClampCircuitDuration(TimeSpan candidate, TimeSpan minimum) {
        return candidate < minimum ? minimum : candidate;
    }

    internal static bool IsNameResolutionFailure(string? errorMessage) {
        if (string.IsNullOrWhiteSpace(errorMessage)) {
            return false;
        }

        return errorMessage.Contains("No such host is known", StringComparison.OrdinalIgnoreCase) ||
               errorMessage.Contains("no data of the requested type was found", StringComparison.OrdinalIgnoreCase);
    }

    internal static bool IsPermanentHttpLogFailure(Exception? exception) {
        if (exception == null) {
            return false;
        }

        HttpRequestException? httpRequestException = FindHttpRequestException(exception);
        if (httpRequestException != null) {
            int? statusCode = TryGetHttpStatusCode(httpRequestException);
            if (statusCode == 404 || statusCode == 410) {
                return true;
            }
        }

        string? message = exception.Message;
        if (string.IsNullOrWhiteSpace(message)) {
            return false;
        }

        // Best-effort fallback for runtimes that bubble an HttpRequestException without a populated
        // StatusCode. This English message format is locale-sensitive, so the typed status-code path
        // above remains the primary signal when it is available.
        return message.Contains("Response status code does not indicate success: 404", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("Response status code does not indicate success: 410", StringComparison.OrdinalIgnoreCase);
    }

    internal static bool IsLikelyPermanentNativeCtFailure(string? errorMessage) {
        if (string.IsNullOrWhiteSpace(errorMessage)) {
            return false;
        }

        return IsNameResolutionFailure(errorMessage) ||
               errorMessage.Contains("Response status code does not indicate success: 404", StringComparison.OrdinalIgnoreCase) ||
               errorMessage.Contains("Response status code does not indicate success: 410", StringComparison.OrdinalIgnoreCase);
    }

    private static HttpRequestException? FindHttpRequestException(Exception? exception) {
        for (Exception? current = exception; current != null; current = current.InnerException) {
            if (current is HttpRequestException httpRequestException) {
                return httpRequestException;
            }
        }

        return null;
    }

    private static string? NormalizeLogUrl(string? rawUrl) {
        if (string.IsNullOrWhiteSpace(rawUrl)) {
            return null;
        }

        var value = rawUrl!.Trim();
        if (!value.StartsWith("https://", StringComparison.OrdinalIgnoreCase) &&
            !value.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) {
            value = "https://" + value;
        }

        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)) {
            return null;
        }

        var normalized = uri.ToString();
        if (!normalized.EndsWith("/", StringComparison.Ordinal)) {
            normalized += "/";
        }
        return normalized;
    }

    private async Task<CtSignedTreeHead> GetSignedTreeHeadAsync(string logUrl, NativeCtLogSubdomainDiscoveryOptions options, CancellationToken cancellationToken) {
        var url = CombineLogUrl(logUrl, "ct/v1/get-sth");
        var json = await FetchJsonWithRetryAsync(url, options, cancellationToken).ConfigureAwait(false);
        await DelayIfRequestedAsync(options.RequestDelay, cancellationToken).ConfigureAwait(false);

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object) {
            throw new InvalidOperationException("Native CT: get-sth response is not an object.");
        }

        var treeSize = GetLong(root, "tree_size");
        if (!treeSize.HasValue || treeSize.Value < 0) {
            throw new InvalidOperationException("Native CT: get-sth missing tree_size.");
        }

        return new CtSignedTreeHead(treeSize.Value);
    }

    private async Task<IReadOnlyList<CtEntryPayload>> GetEntriesAsync(
        string logUrl,
        long start,
        long end,
        NativeCtLogSubdomainDiscoveryOptions options,
        CancellationToken cancellationToken) {
        if (start > end) {
            return Array.Empty<CtEntryPayload>();
        }

        var url = CombineLogUrl(logUrl, $"ct/v1/get-entries?start={start}&end={end}");
        var json = await FetchJsonWithRetryAsync(url, options, cancellationToken).ConfigureAwait(false);
        await DelayIfRequestedAsync(options.RequestDelay, cancellationToken).ConfigureAwait(false);

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object) {
            return Array.Empty<CtEntryPayload>();
        }
        if (!root.TryGetProperty("entries", out var entries) || entries.ValueKind != JsonValueKind.Array) {
            return Array.Empty<CtEntryPayload>();
        }

        var list = new List<CtEntryPayload>();
        foreach (var item in entries.EnumerateArray()) {
            if (item.ValueKind != JsonValueKind.Object) {
                continue;
            }

            var leafInput = GetString(item, "leaf_input");
            if (string.IsNullOrWhiteSpace(leafInput)) {
                continue;
            }

            var extraData = GetString(item, "extra_data") ?? string.Empty;
            list.Add(new CtEntryPayload(leafInput!, extraData));
        }

        return list;
    }

    private async Task<string> FetchJsonAsync(
        string url,
        TimeSpan requestTimeout,
        CancellationToken cancellationToken) {
        using var timeoutCts = requestTimeout > TimeSpan.Zero && requestTimeout != Timeout.InfiniteTimeSpan
            ? new CancellationTokenSource(requestTimeout)
            : null;
        using var linkedCts = timeoutCts != null
            ? CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token)
            : null;
        var effectiveToken = linkedCts?.Token ?? cancellationToken;

        if (QueryOverride != null) {
            try {
                return await QueryOverride(url, effectiveToken).ConfigureAwait(false);
            } catch (OperationCanceledException) when (timeoutCts != null && timeoutCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested) {
                throw new TimeoutException($"Native CT request timed out after {requestTimeout} for {url}.");
            }
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        HttpResponseMessage response;
        try {
            response = await SharedHttpClient.Instance.SendAsync(request, effectiveToken).ConfigureAwait(false);
        } catch (OperationCanceledException) when (timeoutCts != null && timeoutCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested) {
            throw new TimeoutException($"Native CT request timed out after {requestTimeout} for {url}.");
        }
        using (response) {
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        }
    }

    private async Task<string> FetchJsonWithRetryAsync(
        string url,
        NativeCtLogSubdomainDiscoveryOptions options,
        CancellationToken cancellationToken) {
        var retryCount = options.RetryCount < 0 ? 0 : options.RetryCount;
        var baseDelay = options.RetryBaseDelay < TimeSpan.Zero ? TimeSpan.Zero : options.RetryBaseDelay;
        var maxDelay = options.RetryMaxDelay <= TimeSpan.Zero ? TimeSpan.FromSeconds(10) : options.RetryMaxDelay;
        var requestTimeout = options.RequestTimeout <= TimeSpan.Zero ? TimeSpan.FromSeconds(15) : options.RequestTimeout;
        if (maxDelay < baseDelay) {
            maxDelay = baseDelay;
        }

        Exception? lastException = null;
        for (int attempt = 0; attempt <= retryCount; attempt++) {
            cancellationToken.ThrowIfCancellationRequested();

            try {
                return await FetchJsonAsync(url, requestTimeout, cancellationToken).ConfigureAwait(false);
            } catch (Exception ex) when (IsTransientCtException(ex, out var retryAfter)) {
                lastException = ex;
                if (attempt >= retryCount) {
                    break;
                }

                var delay = ComputeRetryDelay(attempt, baseDelay, maxDelay, retryAfter);
                if (delay > TimeSpan.Zero) {
                    await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                }
            }
        }

        throw lastException ?? new InvalidOperationException("CT request failed after retries.");
    }

    private static bool IsTransientCtException(Exception ex, out TimeSpan? retryAfter) {
        retryAfter = null;
        if (ex is TimeoutException) {
            return true;
        }

        if (ex is OperationCanceledException) {
            return false;
        }

        if (ex is HttpRequestException httpEx) {
            var statusCode = TryGetHttpStatusCode(httpEx);
            if (statusCode.HasValue) {
                var code = statusCode.Value;
                if (code == 408 || code == 425 || code == 429 || code == 500 || code == 502 || code == 503 || code == 504) {
                    retryAfter = TryGetRetryAfterFromMessage(httpEx.Message);
                    return true;
                }
                return false;
            }
            return true;
        }

        if (ex is IOException) {
            return true;
        }

        return false;
    }

    private static int? TryGetHttpStatusCode(HttpRequestException exception) {
        if (exception == null) {
            return null;
        }

#if NET5_0_OR_GREATER
        if (exception.StatusCode.HasValue) {
            return (int)exception.StatusCode.Value;
        }
#endif

        var statusCodeProperty = exception.GetType().GetProperty("StatusCode");
        if (statusCodeProperty == null) {
            return null;
        }

        var rawValue = statusCodeProperty.GetValue(exception, null);
        if (rawValue == null) {
            return null;
        }

        if (rawValue is int intCode) {
            return intCode;
        }
        if (rawValue is short shortCode) {
            return shortCode;
        }
        if (rawValue is byte byteCode) {
            return byteCode;
        }

        try {
            return Convert.ToInt32(rawValue, CultureInfo.InvariantCulture);
        } catch {
            return null;
        }
    }

    private static TimeSpan ComputeRetryDelay(int attempt, TimeSpan baseDelay, TimeSpan maxDelay, TimeSpan? retryAfter) {
        if (retryAfter.HasValue && retryAfter.Value > TimeSpan.Zero) {
            return retryAfter.Value > maxDelay ? maxDelay : retryAfter.Value;
        }

        if (baseDelay <= TimeSpan.Zero) {
            return TimeSpan.Zero;
        }

        double factor = Math.Pow(2, attempt);
        var milliseconds = baseDelay.TotalMilliseconds * factor;
        if (milliseconds < 0) {
            milliseconds = baseDelay.TotalMilliseconds;
        }
        if (milliseconds > maxDelay.TotalMilliseconds) {
            milliseconds = maxDelay.TotalMilliseconds;
        }
        if (milliseconds < 0) {
            milliseconds = 0;
        }
        return TimeSpan.FromMilliseconds(milliseconds);
    }

    private static TimeSpan? TryGetRetryAfterFromMessage(string? message) {
        if (string.IsNullOrWhiteSpace(message)) {
            return null;
        }

        var messageText = message!;
        const string retryAfterNeedle = "Retry-After";
        var index = messageText.IndexOf(retryAfterNeedle, StringComparison.OrdinalIgnoreCase);
        if (index < 0) {
            return null;
        }

        var tail = messageText.Substring(index + retryAfterNeedle.Length);
        var digits = new string(tail.Where(char.IsDigit).Take(4).ToArray());
        if (int.TryParse(digits, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds) && seconds > 0) {
            return TimeSpan.FromSeconds(seconds);
        }

        return null;
    }

    private static int ComputeEffectiveMaxEntriesPerLog(NativeCtLogSubdomainDiscoveryOptions options, long lag) {
        var maxEntries = options.MaxEntriesPerLog;
        if (options.EnableCatchUpMode && lag >= options.CatchUpLagThreshold && options.CatchUpMaxEntriesPerLog > 0) {
            if (maxEntries <= 0 || options.CatchUpMaxEntriesPerLog > maxEntries) {
                maxEntries = options.CatchUpMaxEntriesPerLog;
            }
        }
        return maxEntries;
    }

    private static int ComputeEffectiveBatchSize(NativeCtLogSubdomainDiscoveryOptions options, long lag) {
        var batchSize = options.EntryBatchSize <= 0 ? 256 : options.EntryBatchSize;
        if (options.EnableCatchUpMode && lag >= options.CatchUpLagThreshold && options.CatchUpBatchSize > 0) {
            if (options.CatchUpBatchSize > batchSize) {
                batchSize = options.CatchUpBatchSize;
            }
        }
        if (batchSize > 2048) {
            batchSize = 2048;
        }
        if (batchSize < 1) {
            batchSize = 1;
        }
        return batchSize;
    }

    private static long ComputeRemainingLag(long treeSize, long? lastProcessedIndex) {
        if (treeSize <= 0) {
            return 0;
        }

        long nextIndex;
        if (lastProcessedIndex.HasValue) {
            nextIndex = lastProcessedIndex.Value + 1;
            if (nextIndex < 0) {
                nextIndex = 0;
            }
        } else {
            nextIndex = 0;
        }

        if (nextIndex >= treeSize) {
            return 0;
        }

        return treeSize - nextIndex;
    }

    private static async Task DelayIfRequestedAsync(TimeSpan requestDelay, CancellationToken cancellationToken) {
        if (requestDelay <= TimeSpan.Zero) {
            return;
        }
        await Task.Delay(requestDelay, cancellationToken).ConfigureAwait(false);
    }

    private static string CombineLogUrl(string logUrl, string relative) {
        if (string.IsNullOrWhiteSpace(logUrl)) {
            throw new ArgumentNullException(nameof(logUrl));
        }
        var baseUrl = logUrl.EndsWith("/", StringComparison.Ordinal) ? logUrl : (logUrl + "/");
        return baseUrl + relative;
    }

}
