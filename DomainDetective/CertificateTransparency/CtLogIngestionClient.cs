using DomainDetective.Helpers;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;

namespace DomainDetective;

/// <summary>
/// Signed tree head metadata for one CT log at a point in time.
/// </summary>
/// <param name="TreeSize">Current tree size reported by the CT log.</param>
/// <param name="ObservedAtUtc">UTC time when the tree head was read or refreshed locally.</param>
public sealed record CtSignedTreeHead(
    long TreeSize,
    DateTimeOffset ObservedAtUtc);

/// <summary>
/// Raw RFC6962 entry payload as returned by <c>get-entries</c>.
/// </summary>
/// <param name="LeafInputBase64">Base64-encoded Merkle leaf.</param>
/// <param name="ExtraDataBase64">Base64-encoded extra data payload.</param>
public sealed record RawCtEntryPayload(
    string LeafInputBase64,
    string ExtraDataBase64);

/// <summary>
/// Certificate Transparency entry type encoded in the Merkle tree leaf.
/// </summary>
public enum CtLogEntryType {
    /// <summary>Unknown or unsupported CT entry type.</summary>
    Unknown = -1,
    /// <summary>X.509 certificate entry.</summary>
    X509 = 0,
    /// <summary>Precertificate entry.</summary>
    Precertificate = 1
}

/// <summary>
/// Describes one CT log endpoint.
/// </summary>
public sealed class CtLogDescriptor {
    /// <summary>Base CT log URL.</summary>
    public string Url { get; init; } = string.Empty;
    /// <summary>Human-readable CT log operator name when supplied by the log list.</summary>
    public string? OperatorName { get; init; }
    /// <summary>Human-readable log description when available.</summary>
    public string? Description { get; init; }
    /// <summary>Policy state supplied by the log list, for example usable, qualified, pending, retired, or rejected.</summary>
    public string? State { get; init; }
    /// <summary>True when the log list marks this log as retired.</summary>
    public bool IsRetired { get; init; }
    /// <summary>Temporal interval start when supplied by the log list.</summary>
    public DateTimeOffset? TemporalStartUtc { get; init; }
    /// <summary>Temporal interval end when supplied by the log list.</summary>
    public DateTimeOffset? TemporalEndUtc { get; init; }
}

/// <summary>
/// Represents a decoded CT log entry suitable for durable ingestion.
/// </summary>
public sealed class CtLogIngestionEntry {
    /// <summary>Base CT log URL.</summary>
    public string LogUrl { get; init; } = string.Empty;
    /// <summary>Entry index in the CT log.</summary>
    public long EntryIndex { get; init; }
    /// <summary>Tree size observed before fetching this entry batch.</summary>
    public long TreeSize { get; init; }
    /// <summary>CT entry timestamp from the Merkle tree leaf.</summary>
    public DateTimeOffset? EntryTimestampUtc { get; init; }
    /// <summary>Decoded CT entry type.</summary>
    public CtLogEntryType EntryType { get; init; } = CtLogEntryType.Unknown;
    /// <summary>True when this record came from a precertificate entry.</summary>
    public bool IsPrecertificate => EntryType == CtLogEntryType.Precertificate;
    /// <summary>Normalized certificate record derived from the CT entry DER bytes.</summary>
    public CtCertificateRecord Certificate { get; init; } = new();
}

/// <summary>
/// Represents one fetched CT log batch.
/// </summary>
public sealed class CtLogIngestionBatch {
    /// <summary>Base CT log URL.</summary>
    public string LogUrl { get; init; } = string.Empty;
    /// <summary>Tree size observed before fetching this batch.</summary>
    public long TreeSize { get; init; }
    /// <summary>Requested first entry index.</summary>
    public long StartIndex { get; init; }
    /// <summary>Requested last entry index.</summary>
    public long EndIndex { get; init; }
    /// <summary>Decoded certificate entries.</summary>
    public IReadOnlyList<CtLogIngestionEntry> Entries { get; init; } = Array.Empty<CtLogIngestionEntry>();
    /// <summary>Diagnostics for skipped or undecodable CT entries.</summary>
    public IReadOnlyList<string> Diagnostics { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Options for one CT log batch read.
/// </summary>
public sealed class CtLogIngestionBatchRequest {
    /// <summary>Base CT log URL.</summary>
    public string LogUrl { get; init; } = string.Empty;
    /// <summary>First entry index to fetch.</summary>
    public long StartIndex { get; init; }
    /// <summary>Maximum entries to request. RFC6962 logs may return fewer entries.</summary>
    public int BatchSize { get; init; } = 256;
    /// <summary>
    /// Optional signed tree size already obtained by the caller. When supplied, the batch read skips
    /// an additional <c>get-sth</c> request and trusts this tree size for range clamping. Callers
    /// should only supply a fresh value because a stale tree size can delay discovery of newer log
    /// entries until a later refresh.
    /// </summary>
    public long? KnownTreeSize { get; init; }
    /// <summary>HTTP request timeout.</summary>
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(30);
}

/// <summary>
/// Reads native RFC6962 Certificate Transparency log entries and returns normalized certificate records.
/// </summary>
public sealed class CtLogIngestionClient {
    private const int X509EntryType = 0;
    private const int PrecertEntryType = 1;
    private readonly ConcurrentDictionary<string, CachedSignedTreeHead> _signedTreeHeadCache = new();

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
            if (!op.TryGetProperty("logs", out JsonElement logs) || logs.ValueKind != JsonValueKind.Array) {
                continue;
            }

            string? operatorName = GetString(op, "name");
            foreach (JsonElement log in logs.EnumerateArray()) {
                if (!ShouldIncludeLog(log, includeRetired, includePending)) {
                    continue;
                }

                string? url = NormalizeLogUrl(GetString(log, "url"));
                if (url == null) {
                    continue;
                }

                TryGetTemporalInterval(log, out DateTimeOffset? startUtc, out DateTimeOffset? endUtc);
                output[url] = new CtLogDescriptor {
                    Url = url,
                    OperatorName = operatorName,
                    Description = GetString(log, "description"),
                    State = GetLogState(log),
                    IsRetired = IsRetiredLog(log),
                    TemporalStartUtc = startUtc,
                    TemporalEndUtc = endUtc
                };
            }
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
        long start = Math.Max(0, request.StartIndex);
        int batchSize = Math.Max(1, Math.Min(request.BatchSize, 2048));
        TimeSpan timeout = request.RequestTimeout > TimeSpan.Zero ? request.RequestTimeout : TimeSpan.FromSeconds(30);
        long treeSize = request.KnownTreeSize is long knownTreeSize && knownTreeSize >= 0
            ? knownTreeSize
            : (await GetSignedTreeHeadAsync(logUrl, timeout, cancellationToken).ConfigureAwait(false)).TreeSize;
        if (treeSize <= 0 || start >= treeSize) {
            return new CtLogIngestionBatch {
                LogUrl = logUrl,
                TreeSize = treeSize,
                StartIndex = start,
                EndIndex = start - 1
            };
        }

        long end = Math.Min(treeSize - 1, start + batchSize - 1);
        IReadOnlyList<RawCtEntryPayload> payloads = await GetEntriesAsync(logUrl, start, end, timeout, cancellationToken).ConfigureAwait(false);
        long actualEnd = payloads.Count > 0 ? start + payloads.Count - 1 : start - 1;
        var entries = new List<CtLogIngestionEntry>(payloads.Count);
        var diagnostics = new List<string>();
        for (int i = 0; i < payloads.Count; i++) {
            cancellationToken.ThrowIfCancellationRequested();
            long entryIndex = start + i;
            if (!TryDecodeCertificate(payloads[i], out DateTimeOffset? timestampUtc, out CtLogEntryType entryType, out byte[]? certificateDer, out string? diagnostic)) {
                if (!string.IsNullOrWhiteSpace(diagnostic)) {
                    diagnostics.Add($"Entry {entryIndex}: {diagnostic}");
                }

                continue;
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
                        isPrecertificate: entryType == CtLogEntryType.Precertificate)
                });
            } catch (Exception ex) when (!ExceptionHelper.IsFatal(ex)) {
                diagnostics.Add($"Entry {entryIndex}: certificate decode failed: {ex.Message}");
            }
        }

        return new CtLogIngestionBatch {
            LogUrl = logUrl,
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
    /// Reads the current signed tree head size for a CT log.
    /// </summary>
    public async Task<long> GetTreeSizeAsync(string logUrl, TimeSpan timeout, CancellationToken cancellationToken = default) {
        CtSignedTreeHead signedTreeHead = await GetSignedTreeHeadAsync(logUrl, timeout, cancellationToken).ConfigureAwait(false);
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
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Object ||
            !document.RootElement.TryGetProperty("entries", out JsonElement entries) ||
            entries.ValueKind != JsonValueKind.Array) {
            return Array.Empty<RawCtEntryPayload>();
        }

        var output = new List<RawCtEntryPayload>();
        foreach (JsonElement item in entries.EnumerateArray()) {
            if (item.ValueKind != JsonValueKind.Object) {
                continue;
            }

            string? leafInput = GetString(item, "leaf_input");
            if (string.IsNullOrWhiteSpace(leafInput)) {
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
            : await SharedHttpClient.Instance.SendAsync(request, effectiveToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) {
            throw CreateRequestFailure(response);
        }

        return await response.Content.ReadAsStringAsync().ConfigureAwait(false);
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

    private static bool TryDecodeCertificate(
        RawCtEntryPayload payload,
        out DateTimeOffset? timestampUtc,
        out CtLogEntryType entryType,
        out byte[]? certificateDer,
        out string? diagnostic) {
        timestampUtc = null;
        entryType = CtLogEntryType.Unknown;
        certificateDer = null;
        diagnostic = null;

        byte[] leafBytes;
        try {
            leafBytes = Convert.FromBase64String(payload.LeafInputBase64);
        } catch (FormatException) {
            diagnostic = "leaf_input was not valid base64.";
            return false;
        }

        if (!TryParseLeaf(leafBytes, out timestampUtc, out int rawEntryType, out byte[]? x509Leaf)) {
            diagnostic = "leaf_input could not be parsed.";
            return false;
        }

        entryType = rawEntryType switch {
            X509EntryType => CtLogEntryType.X509,
            PrecertEntryType => CtLogEntryType.Precertificate,
            _ => CtLogEntryType.Unknown
        };

        if (rawEntryType == X509EntryType) {
            certificateDer = x509Leaf;
        } else if (rawEntryType == PrecertEntryType) {
            if (string.IsNullOrWhiteSpace(payload.ExtraDataBase64)) {
                diagnostic = "precertificate extra_data was empty.";
                return false;
            }

            try {
                certificateDer = TryExtractPrecertificateLeaf(Convert.FromBase64String(payload.ExtraDataBase64));
            } catch (FormatException) {
                diagnostic = "precertificate extra_data was not valid base64.";
                return false;
            }
        }

        if (certificateDer == null || certificateDer.Length == 0) {
            diagnostic = "entry did not contain certificate bytes.";
            return false;
        }

        return true;
    }

    private static bool TryParseLeaf(byte[] leafBytes, out DateTimeOffset? timestampUtc, out int entryType, out byte[]? x509LeafCertificate) {
        timestampUtc = null;
        entryType = -1;
        x509LeafCertificate = null;
        if (leafBytes == null || leafBytes.Length < 12) {
            return false;
        }

        int offset = 2;
        if (!TryReadUInt64BigEndian(leafBytes, ref offset, out ulong timestampMs) ||
            !TryReadUInt16BigEndian(leafBytes, ref offset, out entryType)) {
            return false;
        }

        try {
            timestampUtc = DateTimeOffset.FromUnixTimeMilliseconds((long)timestampMs);
        } catch (ArgumentOutOfRangeException) {
            timestampUtc = null;
        }

        if (entryType == X509EntryType) {
            return TryReadVector24(leafBytes, ref offset, out x509LeafCertificate);
        }

        if (entryType == PrecertEntryType) {
            if (offset + 32 > leafBytes.Length) {
                return false;
            }

            offset += 32;
            return TryReadVector24(leafBytes, ref offset, out _);
        }

        return false;
    }

    private static byte[]? TryExtractPrecertificateLeaf(byte[] extraData) {
        int offset = 0;
        return TryReadVector24(extraData, ref offset, out byte[]? certBytes) ? certBytes : null;
    }

    private static bool TryReadUInt16BigEndian(byte[] data, ref int offset, out int value) {
        value = 0;
        if (data == null || offset < 0 || offset + 2 > data.Length) {
            return false;
        }

        value = (data[offset] << 8) | data[offset + 1];
        offset += 2;
        return true;
    }

    private static bool TryReadUInt64BigEndian(byte[] data, ref int offset, out ulong value) {
        value = 0;
        if (data == null || offset < 0 || offset + 8 > data.Length) {
            return false;
        }

        for (int i = 0; i < 8; i++) {
            value = (value << 8) | data[offset + i];
        }

        offset += 8;
        return true;
    }

    private static bool TryReadVector24(byte[] data, ref int offset, out byte[]? bytes) {
        bytes = null;
        if (!TryReadUInt24(data, ref offset, out int length) || length < 0 || offset + length > data.Length) {
            return false;
        }

        bytes = new byte[length];
        Buffer.BlockCopy(data, offset, bytes, 0, length);
        offset += length;
        return true;
    }

    private static bool TryReadUInt24(byte[] data, ref int offset, out int value) {
        value = 0;
        if (data == null || offset < 0 || offset + 3 > data.Length) {
            return false;
        }

        value = (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2];
        offset += 3;
        return true;
    }

    private static string CombineLogUrl(string logUrl, string relative) {
        string baseUrl = logUrl.EndsWith("/", StringComparison.Ordinal) ? logUrl : logUrl + "/";
        return baseUrl + relative;
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

    private static bool ShouldIncludeLog(JsonElement log, bool includeRetired, bool includePending) {
        if (!log.TryGetProperty("state", out JsonElement state) || state.ValueKind != JsonValueKind.Object) {
            return true;
        }

        if (state.TryGetProperty("rejected", out _)) {
            return false;
        }

        if (state.TryGetProperty("retired", out _)) {
            return includeRetired;
        }

        if (state.TryGetProperty("pending", out _)) {
            return includePending;
        }

        return true;
    }

    private static bool IsRetiredLog(JsonElement log) {
        return log.TryGetProperty("state", out JsonElement state) &&
               state.ValueKind == JsonValueKind.Object &&
               state.TryGetProperty("retired", out _);
    }

    private static string? GetLogState(JsonElement log) {
        if (!log.TryGetProperty("state", out JsonElement state) || state.ValueKind != JsonValueKind.Object) {
            return null;
        }

        foreach (string name in new[] { "usable", "qualified", "pending", "retired", "rejected", "readonly" }) {
            if (state.TryGetProperty(name, out _)) {
                return name;
            }
        }

        return state.EnumerateObject().FirstOrDefault().Name;
    }

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
