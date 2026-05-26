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
/// Describes the CT log read API used by an endpoint.
/// </summary>
public enum CtLogApiKind {
    /// <summary>RFC6962 JSON APIs such as <c>get-sth</c> and <c>get-entries</c>.</summary>
    Rfc6962 = 0,
    /// <summary>Static CT monitoring API with checkpoints and immutable data tiles.</summary>
    StaticCt = 1
}

/// <summary>
/// Describes one CT log endpoint.
/// </summary>
public sealed class CtLogDescriptor {
    /// <summary>Base CT log URL.</summary>
    public string Url { get; init; } = string.Empty;
    /// <summary>Base64 CT log ID when supplied by an authoritative log list.</summary>
    public string? LogId { get; init; }
    /// <summary>Base64 public key when supplied by an authoritative log list.</summary>
    public string? PublicKey { get; init; }
    /// <summary>Maximum merge delay in seconds when supplied by an authoritative log list.</summary>
    public int? MaximumMergeDelaySeconds { get; init; }
    /// <summary>Read API used by this log.</summary>
    public CtLogApiKind ApiKind { get; init; } = CtLogApiKind.Rfc6962;
    /// <summary>Static CT monitoring prefix when <see cref="ApiKind"/> is <see cref="CtLogApiKind.StaticCt"/>.</summary>
    public string? MonitoringUrl { get; init; }
    /// <summary>Static CT submission prefix, or the RFC6962 base URL.</summary>
    public string? SubmissionUrl { get; init; }
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
    /// <summary>True when the log list marks this log read-only.</summary>
    public bool IsReadOnly => IsState("readonly");
    /// <summary>True when the log list marks this log pending.</summary>
    public bool IsPending => IsState("pending");
    /// <summary>True when the log list marks this log rejected.</summary>
    public bool IsRejected => IsState("rejected");
    /// <summary>True when the log list marks this log usable.</summary>
    public bool IsUsable => IsState("usable");
    /// <summary>True when the log list marks this log qualified.</summary>
    public bool IsQualified => IsState("qualified");

    private bool IsState(string state)
        => string.Equals(State?.Trim(), state, StringComparison.OrdinalIgnoreCase);
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
    /// <summary>Read API used by this log.</summary>
    public CtLogApiKind ApiKind { get; init; } = CtLogApiKind.Rfc6962;
    /// <summary>Static CT monitoring prefix used for checkpoint and tile reads.</summary>
    public string? MonitoringUrl { get; init; }
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
    /// <summary>Maximum number of Static CT data tiles to fetch concurrently for one batch.</summary>
    public int StaticTileFetchConcurrency { get; init; } = 1;
    /// <summary>How much certificate metadata to decode for each entry.</summary>
    public CtCertificateRecordDetailLevel CertificateDetailLevel { get; init; } = CtCertificateRecordDetailLevel.Full;
}

/// <summary>
/// Reads native Certificate Transparency log entries and returns normalized certificate records.
/// </summary>
public sealed class CtLogIngestionClient {
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
                        isPrecertificate: entryType == CtLogEntryType.Precertificate,
                        detailLevel: certificateDetailLevel)
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

    private async Task<CtLogIngestionBatch> ReadStaticBatchAsync(
        CtLogIngestionBatchRequest request,
        string submissionUrl,
        CancellationToken cancellationToken) {
        string monitoringUrl = NormalizeLogUrl(request.MonitoringUrl) ??
            throw new ArgumentException("Static CT logs require an absolute monitoring URL.", nameof(request));
        long start = Math.Max(0, request.StartIndex);
        int batchSize = Math.Max(1, Math.Min(request.BatchSize, MaxBatchSize));
        TimeSpan timeout = request.RequestTimeout > TimeSpan.Zero ? request.RequestTimeout : TimeSpan.FromSeconds(30);
        CtCertificateRecordDetailLevel certificateDetailLevel = request.CertificateDetailLevel;
        long treeSize = request.KnownTreeSize is long knownTreeSize && knownTreeSize >= 0
            ? knownTreeSize
            : (await GetStaticSignedTreeHeadAsync(
                monitoringUrl,
                GetStaticCheckpointExpectedOrigin(submissionUrl, monitoringUrl, submissionUrl),
                timeout,
                cancellationToken).ConfigureAwait(false)).TreeSize;
        if (treeSize <= 0 || start >= treeSize) {
            return new CtLogIngestionBatch {
                LogUrl = submissionUrl,
                TreeSize = treeSize,
                StartIndex = start,
                EndIndex = start - 1
            };
        }

        long end = Math.Min(treeSize - 1, start + batchSize - 1);
        var entries = new List<CtLogIngestionEntry>();
        var diagnostics = new List<string>();
        IReadOnlyList<StaticCtDataTile> tiles = await GetStaticDataTilesAsync(
            monitoringUrl,
            start / StaticCtTileWidth,
            end / StaticCtTileWidth,
            treeSize,
            timeout,
            Math.Max(1, request.StaticTileFetchConcurrency),
            cancellationToken).ConfigureAwait(false);
        foreach (StaticCtDataTile tile in tiles) {
            cancellationToken.ThrowIfCancellationRequested();
            long tileStartIndex = tile.TileIndex * StaticCtTileWidth;
            for (int tileOffset = 0; tileOffset < tile.Entries.Count; tileOffset++) {
                long entryIndex = tileStartIndex + tileOffset;
                if (entryIndex < start || entryIndex > end) {
                    continue;
                }

                StaticCtTileEntry tileEntry = tile.Entries[tileOffset];
                try {
                    entries.Add(new CtLogIngestionEntry {
                        LogUrl = submissionUrl,
                        EntryIndex = entryIndex,
                        TreeSize = treeSize,
                        EntryTimestampUtc = tileEntry.TimestampUtc,
                        EntryType = tileEntry.EntryType,
                        Certificate = CtCertificateRecord.FromDer(
                            CtProviderProfiles.NativeCtProviderId,
                            tileEntry.CertificateDer,
                            providerCertificateId: $"{submissionUrl}#{entryIndex}",
                            entryTimestampUtc: tileEntry.TimestampUtc,
                            isPrecertificate: tileEntry.EntryType == CtLogEntryType.Precertificate,
                            detailLevel: certificateDetailLevel)
                    });
                } catch (Exception ex) when (!ExceptionHelper.IsFatal(ex)) {
                    diagnostics.Add($"Entry {entryIndex}: certificate decode failed: {ex.Message}");
                }
            }
        }

        return new CtLogIngestionBatch {
            LogUrl = submissionUrl,
            TreeSize = treeSize,
            StartIndex = start,
            EndIndex = end,
            Entries = entries,
            Diagnostics = diagnostics
        };
    }

    private async Task<IReadOnlyList<StaticCtDataTile>> GetStaticDataTilesAsync(
        string monitoringUrl,
        long firstTileIndex,
        long lastTileIndex,
        long treeSize,
        TimeSpan timeout,
        int fetchConcurrency,
        CancellationToken cancellationToken) {
        if (lastTileIndex < firstTileIndex) {
            return Array.Empty<StaticCtDataTile>();
        }

        int tileCount = checked((int)(lastTileIndex - firstTileIndex + 1));
        int concurrency = Math.Max(1, Math.Min(fetchConcurrency, tileCount));
        var tiles = new StaticCtDataTile[tileCount];
        if (concurrency == 1) {
            for (int offset = 0; offset < tileCount; offset++) {
                long tileIndex = firstTileIndex + offset;
                tiles[offset] = new StaticCtDataTile(
                    tileIndex,
                    await GetStaticDataTileEntriesAsync(monitoringUrl, tileIndex, treeSize, timeout, cancellationToken).ConfigureAwait(false));
            }

            return tiles;
        }

        using var gate = new SemaphoreSlim(concurrency);
        var tasks = new List<Task>(tileCount);
        for (int offset = 0; offset < tileCount; offset++) {
            int tileOffset = offset;
            long tileIndex = firstTileIndex + offset;
            tasks.Add(FetchTileAsync(tileOffset, tileIndex));
        }

        await Task.WhenAll(tasks).ConfigureAwait(false);
        return tiles;

        async Task FetchTileAsync(int tileOffset, long tileIndex) {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try {
                tiles[tileOffset] = new StaticCtDataTile(
                    tileIndex,
                    await GetStaticDataTileEntriesAsync(monitoringUrl, tileIndex, treeSize, timeout, cancellationToken).ConfigureAwait(false));
            } finally {
                gate.Release();
            }
        }
    }

    private async Task<CtSignedTreeHead> GetStaticSignedTreeHeadAsync(
        string monitoringUrl,
        string? expectedOrigin,
        TimeSpan timeout,
        CancellationToken cancellationToken) {
        monitoringUrl = NormalizeLogUrl(monitoringUrl) ??
            throw new ArgumentException("Static CT monitoring URL must be an absolute URL.", nameof(monitoringUrl));
        string cacheKey = "static:" + monitoringUrl;
        if (TryGetCachedSignedTreeHead(cacheKey, out CtSignedTreeHead cachedTreeHead)) {
            return cachedTreeHead;
        }

        string checkpoint = await FetchTextAsync(CombineLogUrl(monitoringUrl, "checkpoint"), timeout, cancellationToken).ConfigureAwait(false);
        long treeSize = ParseStaticCheckpointTreeSize(checkpoint, expectedOrigin);
        var signedTreeHead = new CtSignedTreeHead(treeSize, DateTimeOffset.UtcNow);
        CacheSignedTreeHead(cacheKey, signedTreeHead);
        return signedTreeHead;
    }

    private async Task<IReadOnlyList<StaticCtTileEntry>> GetStaticDataTileEntriesAsync(
        string monitoringUrl,
        long tileIndex,
        long treeSize,
        TimeSpan timeout,
        CancellationToken cancellationToken) {
        long firstEntryIndex = tileIndex * StaticCtTileWidth;
        int width = checked((int)Math.Min(StaticCtTileWidth, treeSize - firstEntryIndex));
        if (width <= 0) {
            return Array.Empty<StaticCtTileEntry>();
        }

        string encodedTileIndex = EncodeStaticTileIndex(tileIndex);
        string relativePath = width == StaticCtTileWidth
            ? $"tile/data/{encodedTileIndex}"
            : $"tile/data/{encodedTileIndex}.p/{width}";
        byte[] tileBytes;
        int expectedWidth = width;
        try {
            tileBytes = await FetchBytesAsync(CombineLogUrl(monitoringUrl, relativePath), timeout, cancellationToken).ConfigureAwait(false);
        } catch (HttpRequestException ex) when (width < StaticCtTileWidth && IsStaticPartialTileFallbackFailure(ex)) {
            tileBytes = await FetchBytesAsync(CombineLogUrl(monitoringUrl, $"tile/data/{encodedTileIndex}"), timeout, cancellationToken).ConfigureAwait(false);
            expectedWidth = StaticCtTileWidth;
        }

        return ParseStaticDataTile(tileBytes, expectedWidth);
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

    private static IReadOnlyList<StaticCtTileEntry> ParseStaticDataTile(byte[] tileBytes, int expectedWidth) {
        if (tileBytes == null) {
            throw new ArgumentNullException(nameof(tileBytes));
        }

        var entries = new List<StaticCtTileEntry>(Math.Max(0, expectedWidth));
        int offset = 0;
        while (offset < tileBytes.Length) {
            int entryOffset = offset;
            if (!TryParseStaticTileLeaf(tileBytes, ref offset, out StaticCtTileEntry? entry)) {
                throw new InvalidOperationException($"Static CT data tile could not be parsed at byte offset {entryOffset}.");
            }

            entries.Add(entry!);
        }

        if (expectedWidth > 0 && entries.Count != expectedWidth) {
            throw new InvalidOperationException($"Static CT data tile contained {entries.Count} entries but {expectedWidth} were expected.");
        }

        return entries;
    }

    private static bool TryParseStaticTileLeaf(byte[] data, ref int offset, out StaticCtTileEntry? entry) {
        entry = null;
        int startOffset = offset;
        if (!TryReadUInt64BigEndian(data, ref offset, out ulong timestampMs) ||
            !TryReadUInt16BigEndian(data, ref offset, out int rawEntryType)) {
            offset = startOffset;
            return false;
        }

        DateTimeOffset? timestampUtc;
        try {
            timestampUtc = DateTimeOffset.FromUnixTimeMilliseconds((long)timestampMs);
        } catch (ArgumentOutOfRangeException) {
            timestampUtc = null;
        }

        byte[]? certificateDer = null;
        CtLogEntryType entryType = rawEntryType switch {
            X509EntryType => CtLogEntryType.X509,
            PrecertEntryType => CtLogEntryType.Precertificate,
            _ => CtLogEntryType.Unknown
        };

        if (rawEntryType == X509EntryType) {
            if (!TryReadVector24(data, ref offset, out certificateDer)) {
                offset = startOffset;
                return false;
            }
        } else if (rawEntryType == PrecertEntryType) {
            if (offset + 32 > data.Length) {
                offset = startOffset;
                return false;
            }

            offset += 32;
            if (!TryReadVector24(data, ref offset, out _)) {
                offset = startOffset;
                return false;
            }
        } else {
            offset = startOffset;
            return false;
        }

        if (!TryReadVector16(data, ref offset, out _)) {
            offset = startOffset;
            return false;
        }

        if (rawEntryType == PrecertEntryType &&
            !TryReadVector24(data, ref offset, out certificateDer)) {
            offset = startOffset;
            return false;
        }

        if (!TryReadVector16(data, ref offset, out byte[]? certificateChain)) {
            offset = startOffset;
            return false;
        }

        if (certificateDer == null || certificateDer.Length == 0 ||
            certificateChain == null ||
            certificateChain.Length % 32 != 0) {
            offset = startOffset;
            return false;
        }

        entry = new StaticCtTileEntry(timestampUtc, entryType, certificateDer);
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

    private static bool TryReadVector16(byte[] data, ref int offset, out byte[]? bytes) {
        bytes = null;
        if (!TryReadUInt16BigEndian(data, ref offset, out int length) || length < 0 || offset + length > data.Length) {
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

    private static long ParseStaticCheckpointTreeSize(string checkpoint, string? expectedOrigin) {
        if (string.IsNullOrWhiteSpace(checkpoint)) {
            throw new InvalidOperationException("Static CT checkpoint was empty.");
        }

        string[] lines = checkpoint.Replace("\r\n", "\n").Split('\n');
        if (lines.Length < 2) {
            throw new InvalidOperationException("Static CT checkpoint did not include a tree size on the second line.");
        }

        if (!string.IsNullOrWhiteSpace(expectedOrigin)) {
            string checkpointOrigin = NormalizeStaticCheckpointOrigin(lines[0]);
            string expected = NormalizeStaticCheckpointOrigin(expectedOrigin);
            if (!string.Equals(checkpointOrigin, expected, StringComparison.OrdinalIgnoreCase)) {
                throw new InvalidOperationException($"Static CT checkpoint origin '{checkpointOrigin}' did not match expected origin '{expected}'.");
            }

            if (!HasStaticCheckpointSignatureForOrigin(lines, expected)) {
                throw new InvalidOperationException($"Static CT checkpoint did not include a note signature for expected origin '{expected}'.");
            }
        }

        if (!long.TryParse(lines[1].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out long treeSize) ||
            treeSize < 0) {
            throw new InvalidOperationException("Static CT checkpoint did not include a tree size on the second line.");
        }

        return treeSize;
    }

    private static string? GetStaticCheckpointExpectedOrigin(string? logUrl, string? monitoringUrl, string? submissionUrl) {
        string? normalizedMonitoringUrl = NormalizeLogUrl(monitoringUrl);
        string? normalizedSubmissionUrl = NormalizeLogUrl(submissionUrl) ?? NormalizeLogUrl(logUrl);
        if (string.IsNullOrWhiteSpace(normalizedSubmissionUrl) ||
            string.Equals(normalizedSubmissionUrl, normalizedMonitoringUrl, StringComparison.OrdinalIgnoreCase)) {
            return null;
        }

        return ToStaticCheckpointOrigin(normalizedSubmissionUrl!);
    }

    private static string ToStaticCheckpointOrigin(string normalizedUrl) {
        Uri uri = new(normalizedUrl, UriKind.Absolute);
        string path = uri.AbsolutePath.Trim('/');
        return path.Length == 0 ? uri.Host : uri.Host + "/" + path;
    }

    private static string NormalizeStaticCheckpointOrigin(string? origin)
        => (origin ?? string.Empty).Trim().TrimEnd('/');

    /// <remarks>
    /// Static CT checkpoints use note signatures. This check confirms a signature line for the
    /// expected origin is present, but does not cryptographically verify the signature value.
    /// </remarks>
    private static bool HasStaticCheckpointSignatureForOrigin(string[] checkpointLines, string expectedOrigin) {
        string asciiExpectedPrefix = "- " + expectedOrigin + " ";
        string noteExpectedPrefix = "\u2014 " + expectedOrigin + " ";
        foreach (string line in checkpointLines) {
            string trimmed = line.Trim();
            if (trimmed.StartsWith(asciiExpectedPrefix, StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith(noteExpectedPrefix, StringComparison.OrdinalIgnoreCase)) {
                return true;
            }
        }

        return false;
    }

    private static string EncodeStaticTileIndex(long tileIndex) {
        if (tileIndex < 0) {
            throw new ArgumentOutOfRangeException(nameof(tileIndex));
        }

        var parts = new Stack<string>();
        do {
            parts.Push((tileIndex % 1000).ToString("000", CultureInfo.InvariantCulture));
            tileIndex /= 1000;
        } while (tileIndex > 0);

        string[] pathParts = parts.ToArray();
        for (int i = 0; i < pathParts.Length - 1; i++) {
            pathParts[i] = "x" + pathParts[i];
        }

        return string.Join("/", pathParts);
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

    private sealed record StaticCtTileEntry(
        DateTimeOffset? TimestampUtc,
        CtLogEntryType EntryType,
        byte[] CertificateDer);

    private sealed record StaticCtDataTile(
        long TileIndex,
        IReadOnlyList<StaticCtTileEntry> Entries);
}
