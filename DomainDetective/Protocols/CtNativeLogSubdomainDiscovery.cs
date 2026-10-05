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
    public int MaxConcurrentLogs { get; set; } = 1;
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
    public string? LatestCertificateThumbprint { get; set; }
    public string? LatestCertificateSubject { get; set; }
    public string? LatestCertificateIssuer { get; set; }
    public string? LatestCertificateSerialNumber { get; set; }
    public DateTimeOffset? LatestCertificateNotBeforeUtc { get; set; }
    public DateTimeOffset? LatestCertificateNotAfterUtc { get; set; }
    public IReadOnlyList<string> LatestCertificateSubjectAlternativeNames { get; set; } = Array.Empty<string>();
    public bool? LatestCertificateIsSelfSigned { get; set; }
    public bool? LatestCertificateWeakKey { get; set; }
    public bool? LatestCertificateSha1Signature { get; set; }
    public bool? LatestCertificateHasServerAuthentication { get; set; }
    public bool? LatestCertificateHasClientAuthentication { get; set; }
    public bool? LatestCertificateHasSecureEmail { get; set; }
    public string? LatestCertificateAuthenticationProfile { get; set; }
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

    private sealed class SharedLogProcessingWorkItem {
        public required ResolvedCtLogDescriptor Descriptor { get; init; }
        public required NativeCtLogIngestionStatus Status { get; init; }
        public required string CursorKey { get; init; }
        public required string LogHealthKey { get; init; }
    }

    private sealed class SharedBatchProcessingState {
        public object Sync { get; } = new();
        public bool StoppedAfterMatchedObservationTarget { get; set; }
    }

    private const int X509EntryType = 0;
    private const int PrecertEntryType = 1;
    private const string HistoricalAllLogsListUrl = "https://www.gstatic.com/ct/log_list/v2/all_logs_list.json";
    private const string KnownBogusCtLogUrlPrefix = "https://ct.example.com/bogus/";

    public Func<string, CancellationToken, Task<string>>? QueryOverride { get; set; }

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

        string? message = httpRequestException?.Message ?? exception.Message;
        if (string.IsNullOrWhiteSpace(message)) {
            return false;
        }

        // Best-effort fallback for runtimes that bubble an HttpRequestException without a populated
        // StatusCode. This English message format is locale-sensitive, so the typed status-code path
        // above remains the primary signal when it is available.
        return IsPermanentHttpFailureMessage(message);
    }

    internal static bool IsLikelyPermanentNativeCtFailure(string? errorMessage) {
        if (string.IsNullOrWhiteSpace(errorMessage)) {
            return false;
        }

        return IsNameResolutionFailure(errorMessage) || IsPermanentHttpFailureMessage(errorMessage);
    }

    private static bool IsPermanentHttpFailureMessage(string message) {
        // The canonical reader supplies this stable prefix on Framework as well as modern .NET.
        // Saved health state contains only the message, so retain the old runtime wording too.
        return message.Equals("HTTP 404", StringComparison.OrdinalIgnoreCase) ||
               message.Equals("HTTP 410", StringComparison.OrdinalIgnoreCase) ||
               message.StartsWith("HTTP 404 ", StringComparison.OrdinalIgnoreCase) ||
               message.StartsWith("HTTP 410 ", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("Response status code does not indicate success: 404", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("Response status code does not indicate success: 410", StringComparison.OrdinalIgnoreCase);
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
