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
    public int MaxCtRowsToProcess { get; set; } = 10000;
    public int MaxSubdomains { get; set; } = 10000;
    public string LogListUrl { get; set; } = "https://www.gstatic.com/ct/log_list/v3/log_list.json";
    public IReadOnlyList<string> ExplicitLogUrls { get; set; } = Array.Empty<string>();
    public int MaxLogsToProcess { get; set; } = 12;
    public int MaxEntriesPerLog { get; set; } = 2000;
    public int EntryBatchSize { get; set; } = 256;
    public int InitialBackfillEntriesPerLog { get; set; } = 2000;
    public string? CursorStatePath { get; set; }
    public bool IncludePendingLogs { get; set; }
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
    private const int X509EntryType = 0;
    private const int PrecertEntryType = 1;
    private const string SubjectAlternativeNameOid = "2.5.29.17";

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
        var logUrls = await ResolveLogUrlsAsync(options, cancellationToken).ConfigureAwait(false);
        if (logUrls.Count == 0) {
            result.Warnings.Add("Native CT: no log URLs resolved.");
            return result;
        }

        var cursor = NativeCtCursorState.Load(options.CursorStatePath);
        foreach (var logUrl in logUrls) {
            cancellationToken.ThrowIfCancellationRequested();
            result.LogsAttempted++;
            var key = NativeCtCursorState.BuildKey(baseDomain, logUrl);
            var status = new NativeCtLogIngestionStatus {
                LogUrl = logUrl,
                CursorKey = key,
                DomainScope = baseDomain,
                SharedIngestion = false
            };
            result.LogStatuses.Add(status);

            try {
                if (cursor.IsCircuitOpen(key, DateTimeOffset.UtcNow, out var openUntilUtc)) {
                    result.Warnings.Add($"Native CT log skipped (circuit open) for {logUrl} until {openUntilUtc:O}");
                    status.SkippedByCircuitBreaker = true;
                    status.CircuitOpenUntilUtc = openUntilUtc;
                    continue;
                }

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

                        result.CertificateObservationCount++;
                        if (TryProcessEntry(entries[i], baseDomain, options.MaxSubdomains, result, logger)) {
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

                    batchStart = batchEnd + 1;
                }

                logger?.WriteVerbose(
                    "Native CT processed log {0}: observations={1}, subdomains={2}",
                    logUrl,
                    result.CertificateObservationCount,
                    result.Subdomains.Count);
                cursor.RecordSuccess(key, DateTimeOffset.UtcNow);
                status.LastProcessedIndex = cursor.GetLastProcessedIndex(key);
                status.EstimatedLagAfter = status.TreeSize.HasValue
                    ? ComputeRemainingLag(status.TreeSize.Value, status.LastProcessedIndex)
                    : null;
                status.Succeeded = true;

                if (result.ResultsCapped) {
                    break;
                }
            } catch (Exception ex) {
                cursor.RecordFailure(
                    key,
                    DateTimeOffset.UtcNow,
                    ex.Message,
                    options.CircuitBreakerFailureThreshold,
                    options.CircuitBreakerDuration);
                result.Warnings.Add($"Native CT log failed for {logUrl}: {ex.Message}");
                logger?.WriteVerbose("Native CT log failed for {0}: {1}", logUrl, ex.Message);
                status.Failure = ex.Message;
                status.LastProcessedIndex = cursor.GetLastProcessedIndex(key);
                status.EstimatedLagAfter = status.TreeSize.HasValue
                    ? ComputeRemainingLag(status.TreeSize.Value, status.LastProcessedIndex)
                    : null;
                if (cursor.IsCircuitOpen(key, DateTimeOffset.UtcNow, out var openUntilUtc)) {
                    status.CircuitOpenUntilUtc = openUntilUtc;
                }
            }
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
        var result = new NativeCtLogSubdomainDiscoveryBatchResult();
        foreach (var domain in normalizedDomains) {
            result.SubdomainsByDomain[domain] = new Dictionary<string, NativeCtSubdomainObservation>(StringComparer.OrdinalIgnoreCase);
        }

        var logUrls = await ResolveLogUrlsAsync(options, cancellationToken).ConfigureAwait(false);
        if (logUrls.Count == 0) {
            result.Warnings.Add("Native CT: no log URLs resolved.");
            return result;
        }

        var cursor = NativeCtCursorState.Load(options.CursorStatePath);
        foreach (var logUrl in logUrls) {
            cancellationToken.ThrowIfCancellationRequested();
            result.LogsAttempted++;
            var key = NativeCtCursorState.BuildSharedKey(logUrl);
            var status = new NativeCtLogIngestionStatus {
                LogUrl = logUrl,
                CursorKey = key,
                SharedIngestion = true
            };
            result.LogStatuses.Add(status);

            try {
                if (cursor.IsCircuitOpen(key, DateTimeOffset.UtcNow, out var openUntilUtc)) {
                    result.Warnings.Add($"Native CT shared log skipped (circuit open) for {logUrl} until {openUntilUtc:O}");
                    status.SkippedByCircuitBreaker = true;
                    status.CircuitOpenUntilUtc = openUntilUtc;
                    continue;
                }

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

                        result.CertificateObservationCount++;
                        if (TryProcessEntryForDomains(entries[i], domainSet, options.MaxSubdomains, result, logger)) {
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

                    batchStart = batchEnd + 1;
                }

                logger?.WriteVerbose(
                    "Native CT shared processed log {0}: observations={1}",
                    logUrl,
                    result.CertificateObservationCount);
                cursor.RecordSuccess(key, DateTimeOffset.UtcNow);
                status.LastProcessedIndex = cursor.GetLastProcessedIndex(key);
                status.EstimatedLagAfter = status.TreeSize.HasValue
                    ? ComputeRemainingLag(status.TreeSize.Value, status.LastProcessedIndex)
                    : null;
                status.Succeeded = true;

                if (result.ResultsCapped) {
                    break;
                }
            } catch (Exception ex) {
                cursor.RecordFailure(
                    key,
                    DateTimeOffset.UtcNow,
                    ex.Message,
                    options.CircuitBreakerFailureThreshold,
                    options.CircuitBreakerDuration);
                result.Warnings.Add($"Native CT shared log failed for {logUrl}: {ex.Message}");
                logger?.WriteVerbose("Native CT shared log failed for {0}: {1}", logUrl, ex.Message);
                status.Failure = ex.Message;
                status.LastProcessedIndex = cursor.GetLastProcessedIndex(key);
                status.EstimatedLagAfter = status.TreeSize.HasValue
                    ? ComputeRemainingLag(status.TreeSize.Value, status.LastProcessedIndex)
                    : null;
                if (cursor.IsCircuitOpen(key, DateTimeOffset.UtcNow, out var openUntilUtc)) {
                    status.CircuitOpenUntilUtc = openUntilUtc;
                }
            }
        }

        cursor.Save(options.CursorStatePath);
        return result;
    }

    private async Task<IReadOnlyList<string>> ResolveLogUrlsAsync(NativeCtLogSubdomainDiscoveryOptions options, CancellationToken cancellationToken) {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (options.ExplicitLogUrls != null && options.ExplicitLogUrls.Count > 0) {
            foreach (var raw in options.ExplicitLogUrls) {
                var normalized = NormalizeLogUrl(raw);
                if (normalized != null) {
                    set.Add(normalized);
                }
            }
            return ApplyLogCap(set, options.MaxLogsToProcess);
        }

        if (string.IsNullOrWhiteSpace(options.LogListUrl)) {
            return Array.Empty<string>();
        }

        var json = await FetchJsonWithRetryAsync(options.LogListUrl, options, cancellationToken).ConfigureAwait(false);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object) {
            return Array.Empty<string>();
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
                    TryAddLogFromListItem(log, options, set);
                }
            }
        } else if (root.TryGetProperty("logs", out var legacyLogs) && legacyLogs.ValueKind == JsonValueKind.Array) {
            foreach (var log in legacyLogs.EnumerateArray()) {
                TryAddLogFromListItem(log, options, set);
            }
        }

        return ApplyLogCap(set, options.MaxLogsToProcess);
    }

    private static IReadOnlyList<string> ApplyLogCap(HashSet<string> set, int maxLogsToProcess) {
        var list = set.OrderBy(url => url, StringComparer.OrdinalIgnoreCase).ToList();
        if (maxLogsToProcess <= 0 || list.Count <= maxLogsToProcess) {
            return list;
        }
        return list.Take(maxLogsToProcess).ToList();
    }

    private static void TryAddLogFromListItem(JsonElement log, NativeCtLogSubdomainDiscoveryOptions options, ISet<string> set) {
        if (log.ValueKind != JsonValueKind.Object) {
            return;
        }
        if (!ShouldIncludeLog(log, options.IncludePendingLogs)) {
            return;
        }
        var url = GetString(log, "url");
        var normalized = NormalizeLogUrl(url);
        if (normalized != null) {
            set.Add(normalized);
        }
    }

    private static bool ShouldIncludeLog(JsonElement log, bool includePendingLogs) {
        if (!log.TryGetProperty("state", out var state) || state.ValueKind != JsonValueKind.Object) {
            return true;
        }

        if (state.TryGetProperty("rejected", out _)) {
            return false;
        }
        if (state.TryGetProperty("retired", out _)) {
            return false;
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

    private async Task<string> FetchJsonAsync(string url, CancellationToken cancellationToken) {
        if (QueryOverride != null) {
            return await QueryOverride(url, cancellationToken).ConfigureAwait(false);
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        using var response = await SharedHttpClient.Instance.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync().ConfigureAwait(false);
    }

    private async Task<string> FetchJsonWithRetryAsync(
        string url,
        NativeCtLogSubdomainDiscoveryOptions options,
        CancellationToken cancellationToken) {
        var retryCount = options.RetryCount < 0 ? 0 : options.RetryCount;
        var baseDelay = options.RetryBaseDelay < TimeSpan.Zero ? TimeSpan.Zero : options.RetryBaseDelay;
        var maxDelay = options.RetryMaxDelay <= TimeSpan.Zero ? TimeSpan.FromSeconds(10) : options.RetryMaxDelay;
        if (maxDelay < baseDelay) {
            maxDelay = baseDelay;
        }

        Exception? lastException = null;
        for (int attempt = 0; attempt <= retryCount; attempt++) {
            cancellationToken.ThrowIfCancellationRequested();

            try {
                return await FetchJsonAsync(url, cancellationToken).ConfigureAwait(false);
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
