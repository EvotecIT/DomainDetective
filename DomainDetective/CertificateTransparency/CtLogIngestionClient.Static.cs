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

public sealed partial class CtLogIngestionClient {
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
        CtSignedTreeHead? verifiedHead = request.RequireIntegrityVerification
            ? await GetVerifiedSignedTreeHeadAsync(DescribeRequest(request), request.PreviousTreeHead, timeout, cancellationToken).ConfigureAwait(false)
            : null;
        long treeSize = verifiedHead?.TreeSize ?? (request.KnownTreeSize is long knownTreeSize && knownTreeSize >= 0
            ? knownTreeSize
            : (await GetStaticSignedTreeHeadAsync(
                monitoringUrl,
                GetStaticCheckpointExpectedOrigin(submissionUrl, monitoringUrl, submissionUrl),
                timeout,
                cancellationToken).ConfigureAwait(false)).TreeSize);
        if (treeSize <= 0 || start >= treeSize) {
            return new CtLogIngestionBatch {
                LogUrl = submissionUrl,
                VerifiedTreeHead = verifiedHead,
                TreeSize = treeSize,
                StartIndex = start,
                EndIndex = start - 1
            };
        }

        long end = Math.Min(treeSize - 1, start + batchSize - 1);
        var entries = new List<CtLogIngestionEntry>();
        var diagnostics = new List<string>();
        var issuerCache = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        IReadOnlyList<StaticCtDataTile> tiles = await GetStaticDataTilesAsync(
            monitoringUrl,
            start / StaticCtTileWidth,
            end / StaticCtTileWidth,
            treeSize,
            timeout,
            Math.Max(1, request.StaticTileFetchConcurrency),
            cancellationToken).ConfigureAwait(false);
        if (verifiedHead != null) {
            var leafHashes = new List<byte[]>();
            foreach (StaticCtDataTile tile in tiles) {
                for (int i = 0; i < tile.Entries.Count; i++) {
                    long index = tile.TileIndex * StaticCtTileWidth + i;
                    if (index >= start && index <= end) leafHashes.Add(CtMerkleTree.HashLeaf(tile.Entries[i].LeafInput));
                }
            }
            if (leafHashes.Count != end - start + 1) throw new InvalidOperationException("Static CT tiles did not return the complete requested range.");
            await VerifyStaticRangeAsync(monitoringUrl, start, leafHashes, verifiedHead, timeout, cancellationToken).ConfigureAwait(false);
        }
        foreach (StaticCtDataTile tile in tiles) {
            cancellationToken.ThrowIfCancellationRequested();
            long tileStartIndex = tile.TileIndex * StaticCtTileWidth;
            for (int tileOffset = 0; tileOffset < tile.Entries.Count; tileOffset++) {
                long entryIndex = tileStartIndex + tileOffset;
                if (entryIndex < start || entryIndex > end) {
                    continue;
                }

                StaticCtTileEntry tileEntry = tile.Entries[tileOffset];
                if (request.RequireIntegrityVerification || request.RequireCompleteDecoding) {
                    try {
                        await VerifyCertificateBindingAsync(tileEntry.LeafInput, string.Empty,
                            tileEntry.CertificateDer, monitoringUrl, tileEntry.IssuerFingerprints, timeout, cancellationToken, issuerCache).ConfigureAwait(false);
                    } catch (Exception ex) when (ex is not OperationCanceledException && !ExceptionHelper.IsFatal(ex)) {
                        throw new CtEntryDecodingException(submissionUrl, entryIndex,
                            new RawCtEntryPayload(Convert.ToBase64String(tileEntry.LeafInput), Convert.ToBase64String(tileEntry.ExtraData)), ex.Message, ex) {
                            StaticTileEntryBase64 = Convert.ToBase64String(tileEntry.RawData)
                        };
                    }
                }
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
                } catch (Exception ex) when (ex is not OperationCanceledException && !ExceptionHelper.IsFatal(ex)) {
                    if (request.RequireCompleteDecoding) throw new CtEntryDecodingException(submissionUrl, entryIndex,
                        new RawCtEntryPayload(Convert.ToBase64String(tileEntry.LeafInput), Convert.ToBase64String(tileEntry.ExtraData)), ex.Message, ex) {
                        StaticTileEntryBase64 = Convert.ToBase64String(tileEntry.RawData)
                    };
                    diagnostics.Add($"Entry {entryIndex}: certificate decode failed: {ex.Message}");
                }
            }
        }

        return new CtLogIngestionBatch {
            LogUrl = submissionUrl,
            VerifiedTreeHead = verifiedHead,
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

        return ParseStaticDataTile(tileBytes, expectedWidth, monitoringUrl, tileIndex, cancellationToken);
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
        return path.Length == 0 ? uri.Authority : uri.Authority + "/" + path;
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

    private sealed record StaticCtTileEntry(
        DateTimeOffset? TimestampUtc,
        CtLogEntryType EntryType,
        byte[] CertificateDer,
        byte[] LeafInput,
        byte[] ExtraData,
        byte[] IssuerFingerprints,
        byte[] RawData);

    private sealed record StaticCtDataTile(
        long TileIndex,
        IReadOnlyList<StaticCtTileEntry> Entries);}
