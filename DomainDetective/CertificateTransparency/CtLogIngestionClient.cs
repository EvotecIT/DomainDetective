using DomainDetective.Helpers;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;

namespace DomainDetective;

/// <summary>
/// Reads native Certificate Transparency log entries and returns normalized certificate records.
/// </summary>
public sealed partial class CtLogIngestionClient {
    /// <summary>Maximum number of entries requested from one RFC6962 <c>get-entries</c> call.</summary>
    public const int MaxBatchSize = 8192;
    internal const int MaxResponseBodyBytes = 64 * 1024 * 1024;
    private const int StaticCtTileWidth = 256;
    private const int X509EntryType = 0;
    private const int PrecertEntryType = 1;
    private readonly HttpClient? _httpClient;
    private readonly ConcurrentDictionary<string, CachedSignedTreeHead> _signedTreeHeadCache = new();

    /// <summary>
    /// Initializes a CT log ingestion client that uses the shared DomainDetective HTTP client.
    /// </summary>
    public CtLogIngestionClient() {
    }

    /// <summary>
    /// Initializes a CT log ingestion client that uses a host-managed HTTP client.
    /// </summary>
    public CtLogIngestionClient(HttpClient httpClient) {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
    }

    /// <summary>Optional HTTP override used by tests and host applications.</summary>
    public Func<string, CancellationToken, Task<string>>? HttpGetOverride { get; set; }
    /// <summary>HTTP send override used by unit tests to inject controlled responses.</summary>
    internal Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>>? SendOverride { get; set; }
    /// <summary>
    /// Duration for which a successful signed tree head can be reused for the same log URL.
    /// </summary>
    public TimeSpan SignedTreeHeadCacheDuration { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Resolves CT logs from a v3/v2 Google-compatible log list.
    /// </summary>
    public async Task<IReadOnlyList<CtLogDescriptor>> GetLogsAsync(
        string logListUrl = "https://www.gstatic.com/ct/log_list/v3/log_list.json",
        bool includeRetired = true,
        bool includePending = false,
        bool includeUnknownState = true,
        CancellationToken cancellationToken = default) {
        if (string.IsNullOrWhiteSpace(logListUrl)) {
            throw new ArgumentException("Log list URL cannot be null or whitespace.", nameof(logListUrl));
        }

        string json = await FetchJsonAsync(logListUrl, TimeSpan.FromSeconds(30), cancellationToken).ConfigureAwait(false);
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Object ||
            !document.RootElement.TryGetProperty("operators", out JsonElement operators) ||
            operators.ValueKind != JsonValueKind.Array) {
            return Array.Empty<CtLogDescriptor>();
        }

        var output = new Dictionary<string, CtLogDescriptor>(StringComparer.OrdinalIgnoreCase);
        foreach (JsonElement op in operators.EnumerateArray()) {
            string? operatorName = GetString(op, "name");
            AppendLogListEntries(output, op, "logs", operatorName, CtLogApiKind.Rfc6962, includeRetired, includePending, includeUnknownState);
            AppendLogListEntries(output, op, "tiled_logs", operatorName, CtLogApiKind.StaticCt, includeRetired, includePending, includeUnknownState);
        }

        return output.Values
            .OrderBy(static item => item.IsRetired)
            .ThenBy(static item => item.Description, StringComparer.OrdinalIgnoreCase)
            .ThenBy(static item => item.Url, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Reads and decodes one CT log entry batch.
    /// </summary>
    public async Task<CtLogIngestionBatch> ReadBatchAsync(
        CtLogIngestionBatchRequest request,
        CancellationToken cancellationToken = default) {
        if (request == null) {
            throw new ArgumentNullException(nameof(request));
        }

        string logUrl = NormalizeLogUrl(request.LogUrl) ??
            throw new ArgumentException("Log URL must be an absolute URL.", nameof(request));
        if (request.ApiKind == CtLogApiKind.StaticCt) {
            return await ReadStaticBatchAsync(request, logUrl, cancellationToken).ConfigureAwait(false);
        }

        long start = Math.Max(0, request.StartIndex);
        int batchSize = Math.Max(1, Math.Min(request.BatchSize, MaxBatchSize));
        TimeSpan timeout = request.RequestTimeout > TimeSpan.Zero ? request.RequestTimeout : TimeSpan.FromSeconds(30);
        CtCertificateRecordDetailLevel certificateDetailLevel = request.CertificateDetailLevel;
        CtSignedTreeHead? verifiedHead = request.RequireIntegrityVerification
            ? await GetVerifiedSignedTreeHeadAsync(DescribeRequest(request), request.PreviousTreeHead, timeout, cancellationToken).ConfigureAwait(false)
            : null;
        long treeSize = verifiedHead?.TreeSize ?? (request.KnownTreeSize is long knownTreeSize && knownTreeSize >= 0
            ? knownTreeSize
            : (await GetSignedTreeHeadAsync(logUrl, timeout, cancellationToken).ConfigureAwait(false)).TreeSize);
        if (treeSize <= 0 || start >= treeSize) {
            return new CtLogIngestionBatch {
                LogUrl = logUrl,
                VerifiedTreeHead = verifiedHead,
                TreeSize = treeSize,
                StartIndex = start,
                EndIndex = start - 1
            };
        }

        long end = Math.Min(treeSize - 1, start + batchSize - 1);
        IReadOnlyList<RawCtEntryPayload> payloads = await GetEntriesAsync(logUrl, start, end, timeout, cancellationToken).ConfigureAwait(false);
        if (verifiedHead != null) await VerifyRfcRangeAsync(logUrl, start, payloads, verifiedHead, timeout, cancellationToken).ConfigureAwait(false);
        long actualEnd = payloads.Count > 0 ? start + payloads.Count - 1 : start - 1;
        var entries = new List<CtLogIngestionEntry>(payloads.Count);
        var diagnostics = new List<string>();
        for (int i = 0; i < payloads.Count; i++) {
            cancellationToken.ThrowIfCancellationRequested();
            long entryIndex = start + i;
            if (!TryDecodeCertificate(payloads[i], out DateTimeOffset? timestampUtc, out CtLogEntryType entryType, out byte[]? certificateDer, out string? diagnostic)) {
                if (request.RequireCompleteDecoding) throw new CtEntryDecodingException(logUrl, entryIndex, payloads[i], diagnostic ?? "Unknown entry encoding.");
                if (!string.IsNullOrWhiteSpace(diagnostic)) {
                    diagnostics.Add($"Entry {entryIndex}: {diagnostic}");
                }

                continue;
            }

            if (request.RequireIntegrityVerification || request.RequireCompleteDecoding) {
                try {
                    await VerifyCertificateBindingAsync(payloads[i], certificateDer!, null, null, timeout, cancellationToken).ConfigureAwait(false);
                } catch (Exception ex) when (ex is not OperationCanceledException && !ExceptionHelper.IsFatal(ex)) {
                    throw new CtEntryDecodingException(logUrl, entryIndex, payloads[i], ex.Message, ex);
                }
            }
            try {
                entries.Add(new CtLogIngestionEntry {
                    LogUrl = logUrl,
                    EntryIndex = entryIndex,
                    TreeSize = treeSize,
                    EntryTimestampUtc = timestampUtc,
                    EntryType = entryType,
                    Certificate = CtCertificateRecord.FromDer(
                        CtProviderProfiles.NativeCtProviderId,
                        certificateDer!,
                        providerCertificateId: $"{logUrl}#{entryIndex}",
                        entryTimestampUtc: timestampUtc,
                        isPrecertificate: entryType == CtLogEntryType.Precertificate,
                        detailLevel: certificateDetailLevel)
                });
            } catch (Exception ex) when (ex is not OperationCanceledException && !ExceptionHelper.IsFatal(ex)) {
                if (request.RequireCompleteDecoding) throw new CtEntryDecodingException(logUrl, entryIndex, payloads[i], ex.Message, ex);
                diagnostics.Add($"Entry {entryIndex}: certificate decode failed: {ex.Message}");
            }
        }

        return new CtLogIngestionBatch {
            LogUrl = logUrl,
            VerifiedTreeHead = verifiedHead,
            TreeSize = treeSize,
            StartIndex = start,
            EndIndex = actualEnd,
            Entries = entries,
            Diagnostics = diagnostics
        };
    }

    /// <summary>
    /// Reads the current signed tree head for a CT log.
    /// </summary>
    public async Task<CtSignedTreeHead> GetSignedTreeHeadAsync(string logUrl, TimeSpan timeout, CancellationToken cancellationToken = default) {
        logUrl = NormalizeLogUrl(logUrl) ??
            throw new ArgumentException("Log URL must be an absolute URL.", nameof(logUrl));

        if (TryGetCachedSignedTreeHead(logUrl, out CtSignedTreeHead cachedTreeHead)) {
            return cachedTreeHead;
        }

        string json = await FetchJsonAsync(CombineLogUrl(logUrl, "ct/v1/get-sth"), timeout, cancellationToken).ConfigureAwait(false);
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Object ||
            !TryGetInt64(document.RootElement, "tree_size", out long treeSize)) {
            throw new InvalidOperationException("CT get-sth response did not include tree_size.");
        }

        var signedTreeHead = new CtSignedTreeHead(treeSize, DateTimeOffset.UtcNow);
        CacheSignedTreeHead(logUrl, signedTreeHead);
        return signedTreeHead;
    }

    /// <summary>
    /// Reads the current signed tree head for a described CT log.
    /// </summary>
    public Task<CtSignedTreeHead> GetSignedTreeHeadAsync(CtLogDescriptor log, TimeSpan timeout, CancellationToken cancellationToken = default) {
        if (log == null) {
            throw new ArgumentNullException(nameof(log));
        }

        string? monitoringUrl = log.MonitoringUrl ?? log.Url;
        return log.ApiKind == CtLogApiKind.StaticCt
            ? GetStaticSignedTreeHeadAsync(
                monitoringUrl,
                GetStaticCheckpointExpectedOrigin(log.Url, monitoringUrl, log.SubmissionUrl),
                timeout,
                cancellationToken)
            : GetSignedTreeHeadAsync(log.Url, timeout, cancellationToken);
    }

    /// <summary>
    /// Reads the current signed tree head size for a CT log.
    /// </summary>
    public async Task<long> GetTreeSizeAsync(string logUrl, TimeSpan timeout, CancellationToken cancellationToken = default) {
        CtSignedTreeHead signedTreeHead = await GetSignedTreeHeadAsync(logUrl, timeout, cancellationToken).ConfigureAwait(false);
        return signedTreeHead.TreeSize;
    }

    /// <summary>
    /// Reads the current signed tree head size for a described CT log.
    /// </summary>
    public async Task<long> GetTreeSizeAsync(CtLogDescriptor log, TimeSpan timeout, CancellationToken cancellationToken = default) {
        CtSignedTreeHead signedTreeHead = await GetSignedTreeHeadAsync(log, timeout, cancellationToken).ConfigureAwait(false);
        return signedTreeHead.TreeSize;
    }

    /// <summary>
    /// Reads raw entry payloads from one CT log range.
    /// </summary>
    public async Task<IReadOnlyList<RawCtEntryPayload>> GetEntriesAsync(
        string logUrl,
        long start,
        long end,
        TimeSpan timeout,
        CancellationToken cancellationToken) {
        logUrl = NormalizeLogUrl(logUrl) ??
            throw new ArgumentException("Log URL must be an absolute URL.", nameof(logUrl));
        if (end < start) {
            return Array.Empty<RawCtEntryPayload>();
        }

        string json = await FetchJsonAsync(CombineLogUrl(logUrl, $"ct/v1/get-entries?start={start}&end={end}"), timeout, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Object ||
            !document.RootElement.TryGetProperty("entries", out JsonElement entries) ||
            entries.ValueKind != JsonValueKind.Array) {
            throw new InvalidOperationException("CT get-entries response did not contain an entries array.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        int returnedCount = entries.GetArrayLength();
        if (returnedCount > 0 && returnedCount - 1L > end - start)
            throw new InvalidOperationException("CT get-entries returned more entries than requested.");
        var output = new List<RawCtEntryPayload>(returnedCount);
        foreach (JsonElement item in entries.EnumerateArray()) {
            cancellationToken.ThrowIfCancellationRequested();
            if (item.ValueKind != JsonValueKind.Object) {
                output.Add(new RawCtEntryPayload(string.Empty, string.Empty));
                continue;
            }

            string? leafInput = GetString(item, "leaf_input");
            if (string.IsNullOrWhiteSpace(leafInput)) {
                output.Add(new RawCtEntryPayload(string.Empty, GetString(item, "extra_data") ?? string.Empty));
                continue;
            }

            output.Add(new RawCtEntryPayload(leafInput!, GetString(item, "extra_data") ?? string.Empty));
        }

        return output;
    }

    private bool TryGetCachedSignedTreeHead(string logUrl, out CtSignedTreeHead signedTreeHead) {
        signedTreeHead = default!;
        TimeSpan cacheDuration = SignedTreeHeadCacheDuration;
        if (cacheDuration <= TimeSpan.Zero) {
            return false;
        }

        if (!_signedTreeHeadCache.TryGetValue(logUrl, out CachedSignedTreeHead? cached)) {
            return false;
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (cached.ExpiresAtUtc <= now) {
            _signedTreeHeadCache.TryRemove(logUrl, out _);
            return false;
        }

        signedTreeHead = cached.Value;
        return true;
    }

    private void CacheSignedTreeHead(string logUrl, CtSignedTreeHead signedTreeHead) {
        TimeSpan cacheDuration = SignedTreeHeadCacheDuration;
        if (cacheDuration <= TimeSpan.Zero) {
            _signedTreeHeadCache.TryRemove(logUrl, out _);
            return;
        }

        _signedTreeHeadCache[logUrl] = new CachedSignedTreeHead(
            signedTreeHead,
            signedTreeHead.ObservedAtUtc.Add(cacheDuration));
    }

    private async Task<string> FetchJsonAsync(string url, TimeSpan timeout, CancellationToken cancellationToken) {
        return await FetchTextAsync(url, timeout, cancellationToken).ConfigureAwait(false);
    }

    private async Task<string> FetchTextAsync(string url, TimeSpan timeout, CancellationToken cancellationToken) {
        using var timeoutCts = timeout > TimeSpan.Zero && timeout != Timeout.InfiniteTimeSpan
            ? new CancellationTokenSource(timeout)
            : null;
        using var linkedCts = timeoutCts != null
            ? CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token)
            : null;
        CancellationToken effectiveToken = linkedCts?.Token ?? cancellationToken;

        if (HttpGetOverride != null) {
            return await HttpGetOverride(url, effectiveToken).ConfigureAwait(false);
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        using HttpResponseMessage response = SendOverride != null
            ? await SendOverride(request, effectiveToken).ConfigureAwait(false)
            : await GetHttpClient().SendAsync(request, HttpCompletionOption.ResponseHeadersRead, effectiveToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) {
            throw CreateRequestFailure(response);
        }

        byte[] bytes = await ReadContentBytesWithLimitAsync(response.Content, MaxResponseBodyBytes, effectiveToken).ConfigureAwait(false);
        Encoding encoding = GetResponseEncoding(response.Content.Headers.ContentType?.CharSet);
        return encoding.GetString(bytes);
    }

    private async Task<byte[]> FetchBytesAsync(string url, TimeSpan timeout, CancellationToken cancellationToken) {
        using var timeoutCts = timeout > TimeSpan.Zero && timeout != Timeout.InfiniteTimeSpan
            ? new CancellationTokenSource(timeout)
            : null;
        using var linkedCts = timeoutCts != null
            ? CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token)
            : null;
        CancellationToken effectiveToken = linkedCts?.Token ?? cancellationToken;

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.AcceptEncoding.Add(new StringWithQualityHeaderValue("gzip"));
        request.Headers.AcceptEncoding.Add(new StringWithQualityHeaderValue("identity"));
        using HttpResponseMessage response = SendOverride != null
            ? await SendOverride(request, effectiveToken).ConfigureAwait(false)
            : await GetHttpClient().SendAsync(request, HttpCompletionOption.ResponseHeadersRead, effectiveToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) {
            throw CreateRequestFailure(response);
        }

        byte[] bytes = await ReadContentBytesWithLimitAsync(response.Content, MaxResponseBodyBytes, effectiveToken).ConfigureAwait(false);
        if (response.Content.Headers.ContentEncoding.Any(static value => string.Equals(value, "gzip", StringComparison.OrdinalIgnoreCase))) {
            using var compressed = new MemoryStream(bytes);
            using var gzip = new GZipStream(compressed, CompressionMode.Decompress);
            return await ReadStreamBytesWithLimitAsync(gzip, MaxResponseBodyBytes, effectiveToken).ConfigureAwait(false);
        }

        return bytes;
    }

    private HttpClient GetHttpClient() => _httpClient ?? SharedHttpClient.Instance;

    private static async Task<byte[]> ReadContentBytesWithLimitAsync(
        HttpContent content,
        int maxBytes,
        CancellationToken cancellationToken) {
        if (content.Headers.ContentLength is long contentLength && contentLength > maxBytes) {
            throw new HttpRequestException($"HTTP response body exceeded the {maxBytes} byte limit.");
        }

        using Stream stream = await content.ReadAsStreamAsync().ConfigureAwait(false);
        return await ReadStreamBytesWithLimitAsync(stream, maxBytes, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]> ReadStreamBytesWithLimitAsync(
        Stream stream,
        int maxBytes,
        CancellationToken cancellationToken) {
        var buffer = new byte[81920];
        using var output = new MemoryStream();
        while (true) {
            int read = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
            if (read == 0) {
                return output.ToArray();
            }

            if (output.Length + read > maxBytes) {
                throw new HttpRequestException($"HTTP response body exceeded the {maxBytes} byte limit.");
            }

            output.Write(buffer, 0, read);
        }
    }

    private static Encoding GetResponseEncoding(string? charset) {
        if (!string.IsNullOrWhiteSpace(charset)) {
            string charsetValue = charset!;
            try {
                return Encoding.GetEncoding(charsetValue.Trim('"'));
            } catch (ArgumentException) {
            }
        }

        return Encoding.UTF8;
    }

    internal static HttpRequestException CreateRequestFailure(HttpResponseMessage response) {
        if (response == null) {
            throw new ArgumentNullException(nameof(response));
        }

        string message = response.ReasonPhrase is { Length: > 0 } reasonPhrase
            ? "HTTP " + (int)response.StatusCode + " " + reasonPhrase
            : "HTTP " + (int)response.StatusCode;
        TimeSpan retryAfter = ComputeRetryAfterDelay(response);

#if NET5_0_OR_GREATER
        var exception = new HttpRequestException(message, null, response.StatusCode);
#else
        var exception = new HttpRequestException(message);
#endif
        if (retryAfter > TimeSpan.Zero) {
            message += " (Retry-After " + (long)Math.Ceiling(retryAfter.TotalSeconds) + "s)";
            exception = CreateRetriableRequestException(message, response.StatusCode);
            exception.Data["RetryAfter"] = retryAfter;
        }

        return exception;
    }

    internal static TimeSpan ComputeRetryAfterDelay(HttpResponseMessage response) {
        if (response == null) {
            throw new ArgumentNullException(nameof(response));
        }

        if (response.Headers.RetryAfter == null) {
            return TimeSpan.Zero;
        }

        if (response.Headers.RetryAfter.Delta.HasValue &&
            response.Headers.RetryAfter.Delta.Value > TimeSpan.Zero) {
            return response.Headers.RetryAfter.Delta.Value;
        }

        if (response.Headers.RetryAfter.Date.HasValue) {
            TimeSpan delta = response.Headers.RetryAfter.Date.Value - DateTimeOffset.UtcNow;
            if (delta > TimeSpan.Zero) {
                return delta;
            }
        }

        return TimeSpan.Zero;
    }

    private static HttpRequestException CreateRetriableRequestException(string message, HttpStatusCode statusCode) {
#if NET5_0_OR_GREATER
        return new HttpRequestException(message, null, statusCode);
#else
        return new HttpRequestException(message);
#endif
    }

    private static bool IsStaticPartialTileFallbackFailure(HttpRequestException exception) {
#if NET5_0_OR_GREATER
        return exception.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Gone;
#else
        return exception.Message.Contains("HTTP 404", StringComparison.Ordinal) ||
               exception.Message.Contains("HTTP 410", StringComparison.Ordinal);
#endif
    }

    private static string CombineLogUrl(string logUrl, string relative) {
        string baseUrl = logUrl.EndsWith("/", StringComparison.Ordinal) ? logUrl : logUrl + "/";
        return baseUrl + relative;
    }

    private static void AppendLogListEntries(
        Dictionary<string, CtLogDescriptor> output,
        JsonElement op,
        string propertyName,
        string? operatorName,
        CtLogApiKind apiKind,
        bool includeRetired,
        bool includePending,
        bool includeUnknownState) {
        if (!op.TryGetProperty(propertyName, out JsonElement logs) || logs.ValueKind != JsonValueKind.Array) {
            return;
        }

        foreach (JsonElement log in logs.EnumerateArray()) {
            if (!ShouldIncludeLog(log, includeRetired, includePending, includeUnknownState)) {
                continue;
            }

            string? submissionUrl = NormalizeLogUrl(
                GetString(log, "submission_url") ??
                GetString(log, "submissionUrl") ??
                GetString(log, "url"));
            string? monitoringUrl = apiKind == CtLogApiKind.StaticCt
                ? NormalizeLogUrl(
                    GetString(log, "monitoring_url") ??
                    GetString(log, "monitoringUrl") ??
                    GetString(log, "tile_url") ??
                    GetString(log, "tileUrl") ??
                    GetString(log, "url"))
                : null;

            string? identityUrl = submissionUrl ?? monitoringUrl;
            if (identityUrl == null || (apiKind == CtLogApiKind.StaticCt && monitoringUrl == null)) {
                continue;
            }

            TryGetTemporalInterval(log, out DateTimeOffset? startUtc, out DateTimeOffset? endUtc);
            output[identityUrl] = new CtLogDescriptor {
                Url = identityUrl,
                LogId = GetString(log, "log_id") ?? GetString(log, "logId"),
                PublicKey = GetString(log, "key"),
                MaximumMergeDelaySeconds = TryGetInt32(log, "mmd", out int mmd) ? mmd : null,
                ApiKind = apiKind,
                MonitoringUrl = monitoringUrl,
                SubmissionUrl = submissionUrl,
                OperatorName = operatorName,
                Description = GetString(log, "description"),
                State = GetLogState(log),
                IsRetired = IsRetiredLog(log),
                TemporalStartUtc = startUtc,
                TemporalEndUtc = endUtc
            };
        }
    }

    private static string? NormalizeLogUrl(string? rawUrl) {
        if (string.IsNullOrWhiteSpace(rawUrl)) {
            return null;
        }

        string value = rawUrl!.Trim();
        if (!value.StartsWith("https://", StringComparison.OrdinalIgnoreCase) &&
            !value.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) {
            value = "https://" + value;
        }

        if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri)) {
            return null;
        }

        string normalized = uri.ToString();
        return normalized.EndsWith("/", StringComparison.Ordinal) ? normalized : normalized + "/";
    }

    private static bool ShouldIncludeLog(JsonElement log, bool includeRetired, bool includePending, bool includeUnknownState) {
        if (!TryGetLogStateElement(log, out _)) {
            return includeUnknownState;
        }

        string? normalizedState = GetLogState(log);
        if (string.Equals(normalizedState, "rejected", StringComparison.OrdinalIgnoreCase)) {
            return false;
        }

        if (string.Equals(normalizedState, "retired", StringComparison.OrdinalIgnoreCase)) {
            return includeRetired;
        }

        if (string.Equals(normalizedState, "pending", StringComparison.OrdinalIgnoreCase)) {
            return includePending;
        }

        return true;
    }

    private static bool IsRetiredLog(JsonElement log) {
        return string.Equals(GetLogState(log), "retired", StringComparison.OrdinalIgnoreCase);
    }

    private static string? GetLogState(JsonElement log) {
        if (!TryGetLogStateElement(log, out JsonElement state)) {
            return null;
        }

        if (state.ValueKind == JsonValueKind.String) {
            return state.GetString();
        }

        if (state.ValueKind != JsonValueKind.Object) {
            return state.ToString();
        }

        foreach (string name in new[] { "usable", "qualified", "pending", "retired", "rejected", "readonly" }) {
            if (state.TryGetProperty(name, out _)) {
                return name;
            }
        }

        return state.EnumerateObject().FirstOrDefault().Name;
    }

    private static bool TryGetLogStateElement(JsonElement log, out JsonElement state)
        => log.TryGetProperty("state", out state) &&
           state.ValueKind is JsonValueKind.Object or JsonValueKind.String;

    private static void TryGetTemporalInterval(JsonElement log, out DateTimeOffset? temporalStartUtc, out DateTimeOffset? temporalEndUtc) {
        temporalStartUtc = null;
        temporalEndUtc = null;
        if (!log.TryGetProperty("temporal_interval", out JsonElement interval) || interval.ValueKind != JsonValueKind.Object) {
            return;
        }

        temporalStartUtc = ParseTimestamp(GetString(interval, "start_inclusive") ?? GetString(interval, "start"));
        temporalEndUtc = ParseTimestamp(GetString(interval, "end_exclusive") ?? GetString(interval, "end_inclusive") ?? GetString(interval, "end"));
    }

    private static DateTimeOffset? ParseTimestamp(string? value) {
        return DateTimeOffset.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out DateTimeOffset parsed)
            ? parsed
            : null;
    }

    private static string? GetString(JsonElement obj, string propertyName) {
        if (obj.ValueKind != JsonValueKind.Object || !obj.TryGetProperty(propertyName, out JsonElement value)) {
            return null;
        }

        return value.ValueKind == JsonValueKind.String ? value.GetString() : value.ToString();
    }

    private static bool TryGetInt32(JsonElement obj, string propertyName, out int value) {
        value = 0;
        if (obj.ValueKind != JsonValueKind.Object || !obj.TryGetProperty(propertyName, out JsonElement element)) {
            return false;
        }

        return element.ValueKind == JsonValueKind.Number
            ? element.TryGetInt32(out value)
            : element.ValueKind == JsonValueKind.String &&
              int.TryParse(element.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    private static bool TryGetInt64(JsonElement obj, string propertyName, out long value) {
        value = 0;
        if (obj.ValueKind != JsonValueKind.Object || !obj.TryGetProperty(propertyName, out JsonElement element)) {
            return false;
        }

        return element.ValueKind == JsonValueKind.Number
            ? element.TryGetInt64(out value)
            : element.ValueKind == JsonValueKind.String &&
              long.TryParse(element.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    private sealed record CachedSignedTreeHead(CtSignedTreeHead Value, DateTimeOffset ExpiresAtUtc);


}
