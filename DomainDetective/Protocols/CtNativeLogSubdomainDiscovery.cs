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
}

internal sealed class NativeCtLogSubdomainDiscoveryResult {
    public int CertificateObservationCount { get; set; }
    public bool ResultsCapped { get; set; }
    public DateTimeOffset? FirstSeenUtc { get; set; }
    public DateTimeOffset? LastSeenUtc { get; set; }
    public Dictionary<string, int> IssuerCounts { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, (DateTimeOffset? First, DateTimeOffset? Last)> Subdomains { get; } = new(StringComparer.OrdinalIgnoreCase);
    public int LogsAttempted { get; set; }
    public int LogsSucceeded { get; set; }
    public List<string> Warnings { get; } = new();
    public bool SourceSucceeded => LogsSucceeded > 0;
}

internal sealed class NativeCtLogSubdomainDiscovery {
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

            try {
                var sth = await GetSignedTreeHeadAsync(logUrl, options.RequestDelay, cancellationToken).ConfigureAwait(false);
                result.LogsSucceeded++;

                var key = NativeCtCursorState.BuildKey(baseDomain, logUrl);
                var start = ComputeStartIndex(sth.TreeSize, cursor.GetLastProcessedIndex(key), options.InitialBackfillEntriesPerLog);
                if (start >= sth.TreeSize) {
                    cursor.SetLastProcessedIndex(key, sth.TreeSize - 1);
                    continue;
                }

                long end = sth.TreeSize - 1;
                if (options.MaxEntriesPerLog > 0) {
                    var maxEnd = start + Math.Max(0, options.MaxEntriesPerLog - 1);
                    if (maxEnd < end) {
                        end = maxEnd;
                    }
                }

                var batchSize = options.EntryBatchSize <= 0 ? 256 : options.EntryBatchSize;
                if (batchSize > 2048) {
                    batchSize = 2048;
                }

                var lastProcessed = start - 1;
                for (long batchStart = start; batchStart <= end; ) {
                    cancellationToken.ThrowIfCancellationRequested();

                    var batchEnd = batchStart + batchSize - 1;
                    if (batchEnd > end) {
                        batchEnd = end;
                    }

                    var entries = await GetEntriesAsync(logUrl, batchStart, batchEnd, options.RequestDelay, cancellationToken).ConfigureAwait(false);
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

                if (result.ResultsCapped) {
                    break;
                }
            } catch (Exception ex) {
                result.Warnings.Add($"Native CT log failed for {logUrl}: {ex.Message}");
                logger?.WriteVerbose("Native CT log failed for {0}: {1}", logUrl, ex.Message);
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

        var json = await FetchJsonAsync(options.LogListUrl, cancellationToken).ConfigureAwait(false);
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

    private async Task<CtSignedTreeHead> GetSignedTreeHeadAsync(string logUrl, TimeSpan requestDelay, CancellationToken cancellationToken) {
        var url = CombineLogUrl(logUrl, "ct/v1/get-sth");
        var json = await FetchJsonAsync(url, cancellationToken).ConfigureAwait(false);
        await DelayIfRequestedAsync(requestDelay, cancellationToken).ConfigureAwait(false);

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
        TimeSpan requestDelay,
        CancellationToken cancellationToken) {
        if (start > end) {
            return Array.Empty<CtEntryPayload>();
        }

        var url = CombineLogUrl(logUrl, $"ct/v1/get-entries?start={start}&end={end}");
        var json = await FetchJsonAsync(url, cancellationToken).ConfigureAwait(false);
        await DelayIfRequestedAsync(requestDelay, cancellationToken).ConfigureAwait(false);

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

    private static long ComputeStartIndex(long treeSize, long? lastProcessedIndex, int initialBackfillEntriesPerLog) {
        if (treeSize <= 0) {
            return 0;
        }

        if (lastProcessedIndex.HasValue) {
            var next = lastProcessedIndex.Value + 1;
            if (next < 0) {
                return 0;
            }
            return next;
        }

        if (initialBackfillEntriesPerLog <= 0) {
            return treeSize;
        }

        var backfill = initialBackfillEntriesPerLog;
        if (backfill < 0) {
            backfill = 0;
        }
        var start = treeSize - backfill;
        return start < 0 ? 0 : start;
    }

    private static bool TryProcessEntry(
        CtEntryPayload payload,
        string baseDomain,
        int maxSubdomains,
        NativeCtLogSubdomainDiscoveryResult result,
        InternalLogger? logger) {
        if (string.IsNullOrWhiteSpace(payload.LeafInputBase64)) {
            return true;
        }

        byte[] leafBytes;
        try {
            leafBytes = Convert.FromBase64String(payload.LeafInputBase64);
        } catch {
            return true;
        }

        if (!TryParseLeaf(leafBytes, out var timestampUtc, out var entryType, out var x509Leaf)) {
            return true;
        }

        byte[]? certBytes = null;
        if (entryType == X509EntryType) {
            certBytes = x509Leaf;
        } else if (entryType == PrecertEntryType) {
            if (!string.IsNullOrWhiteSpace(payload.ExtraDataBase64)) {
                try {
                    var extra = Convert.FromBase64String(payload.ExtraDataBase64);
                    certBytes = TryExtractPrecertificateLeaf(extra);
                } catch {
                    certBytes = null;
                }
            }
        }

        if (certBytes == null || certBytes.Length == 0) {
            return true;
        }

        try {
            using var cert = new X509Certificate2(certBytes);
            var issuer = cert.Issuer;
            if (!string.IsNullOrWhiteSpace(issuer)) {
                result.IssuerCounts[issuer] = result.IssuerCounts.TryGetValue(issuer, out var existing) ? existing + 1 : 1;
            }

            if (timestampUtc.HasValue) {
                var ts = timestampUtc.Value;
                if (!result.FirstSeenUtc.HasValue || ts < result.FirstSeenUtc.Value) {
                    result.FirstSeenUtc = ts;
                }
                if (!result.LastSeenUtc.HasValue || ts > result.LastSeenUtc.Value) {
                    result.LastSeenUtc = ts;
                }
            }

            foreach (var candidate in ExtractCandidateNames(cert)) {
                var normalized = NormalizeCandidate(candidate);
                if (normalized == null) {
                    continue;
                }
                if (!normalized.EndsWith("." + baseDomain, StringComparison.OrdinalIgnoreCase)) {
                    continue;
                }
                if (string.Equals(normalized, baseDomain, StringComparison.OrdinalIgnoreCase)) {
                    continue;
                }

                try {
                    normalized = DomainHelper.ValidateIdn(normalized);
                } catch {
                    continue;
                }

                if (!result.Subdomains.TryGetValue(normalized, out var agg)) {
                    if (maxSubdomains > 0 && result.Subdomains.Count >= maxSubdomains) {
                        return false;
                    }
                    result.Subdomains[normalized] = (timestampUtc, timestampUtc);
                } else {
                    var first = agg.First;
                    var last = agg.Last;
                    if (timestampUtc.HasValue) {
                        if (!first.HasValue || timestampUtc.Value < first.Value) {
                            first = timestampUtc.Value;
                        }
                        if (!last.HasValue || timestampUtc.Value > last.Value) {
                            last = timestampUtc.Value;
                        }
                    }
                    result.Subdomains[normalized] = (first, last);
                }
            }
        } catch (Exception ex) {
            logger?.WriteVerbose("Native CT certificate decode failed: {0}", ex.Message);
        }

        return true;
    }

    private static string? NormalizeCandidate(string? raw) {
        if (string.IsNullOrWhiteSpace(raw)) {
            return null;
        }

        var value = raw!.Trim().TrimEnd('.').ToLowerInvariant();
        while (value.StartsWith("*.", StringComparison.Ordinal)) {
            value = value.Substring(2);
        }

        if (value.Contains(" ", StringComparison.Ordinal)) {
            return null;
        }
        if (value.Contains("/", StringComparison.Ordinal)) {
            return null;
        }
        if (value.Length == 0) {
            return null;
        }

        return value;
    }

    private static IReadOnlyCollection<string> ExtractCandidateNames(X509Certificate2 certificate) {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var dnsName = SafeGetNameInfo(certificate, X509NameType.DnsName);
        if (!string.IsNullOrWhiteSpace(dnsName)) {
            names.Add(dnsName!);
        }

        var simpleName = SafeGetNameInfo(certificate, X509NameType.SimpleName);
        if (!string.IsNullOrWhiteSpace(simpleName)) {
            names.Add(simpleName!);
        }

        var commonName = TryExtractCommonName(certificate.Subject);
        if (!string.IsNullOrWhiteSpace(commonName)) {
            names.Add(commonName!);
        }

        var sanNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var extension in certificate.Extensions.OfType<X509Extension>()) {
            if (!string.Equals(extension.Oid?.Value, SubjectAlternativeNameOid, StringComparison.Ordinal)) {
                continue;
            }

            foreach (var dns in ParseDnsNamesFromSanExtension(extension.RawData)) {
                sanNames.Add(dns);
            }

            if (sanNames.Count == 0) {
                foreach (var dns in ParseDnsNamesFromSanText(extension.Format(true))) {
                    sanNames.Add(dns);
                }
            }
        }

        foreach (var san in sanNames) {
            names.Add(san);
        }

        return names;
    }

    private static string? SafeGetNameInfo(X509Certificate2 certificate, X509NameType type) {
        try {
            return certificate.GetNameInfo(type, false);
        } catch {
            return null;
        }
    }

    private static string? TryExtractCommonName(string? subject) {
        if (string.IsNullOrWhiteSpace(subject)) {
            return null;
        }

        var parts = subject!.Split(',');
        foreach (var part in parts) {
            var trimmed = part.Trim();
            if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)) {
                var value = trimmed.Substring(3).Trim();
                return value.Length == 0 ? null : value;
            }
        }

        return null;
    }

    private static IEnumerable<string> ParseDnsNamesFromSanText(string? formattedSan) {
        if (string.IsNullOrWhiteSpace(formattedSan)) {
            yield break;
        }

        var lines = formattedSan!
            .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Trim());

        foreach (var line in lines) {
            const string dnsNamePrefix = "DNS Name=";
            const string dnsShortPrefix = "DNS:";

            if (line.StartsWith(dnsNamePrefix, StringComparison.OrdinalIgnoreCase)) {
                var value = line.Substring(dnsNamePrefix.Length).Trim();
                if (!string.IsNullOrWhiteSpace(value)) {
                    yield return value;
                }
            } else if (line.StartsWith(dnsShortPrefix, StringComparison.OrdinalIgnoreCase)) {
                var value = line.Substring(dnsShortPrefix.Length).Trim();
                if (!string.IsNullOrWhiteSpace(value)) {
                    yield return value;
                }
            }
        }
    }

    private static IEnumerable<string> ParseDnsNamesFromSanExtension(byte[] rawData) {
        if (rawData == null || rawData.Length == 0) {
            yield break;
        }

        var offset = 0;
        if (!TryReadTagAndLength(rawData, ref offset, expectedTag: 0x04, out var octetLength)) {
            yield break;
        }
        if (offset + octetLength > rawData.Length) {
            yield break;
        }

        var innerOffset = offset;
        if (!TryReadTagAndLength(rawData, ref innerOffset, expectedTag: 0x30, out var sequenceLength)) {
            yield break;
        }
        var sequenceEnd = innerOffset + sequenceLength;
        if (sequenceEnd > offset + octetLength) {
            yield break;
        }

        while (innerOffset < sequenceEnd) {
            var tag = rawData[innerOffset++];
            if (!TryReadAsnLength(rawData, ref innerOffset, out var length)) {
                yield break;
            }
            if (innerOffset + length > sequenceEnd) {
                yield break;
            }

            if (tag == 0x82 && length > 0) {
                var value = Encoding.ASCII.GetString(rawData, innerOffset, length).Trim();
                if (!string.IsNullOrWhiteSpace(value)) {
                    yield return value;
                }
            }

            innerOffset += length;
        }
    }

    private static bool TryReadTagAndLength(byte[] data, ref int offset, byte expectedTag, out int length) {
        length = 0;
        if (data == null || offset < 0 || offset >= data.Length) {
            return false;
        }

        var tag = data[offset++];
        if (tag != expectedTag) {
            return false;
        }

        return TryReadAsnLength(data, ref offset, out length);
    }

    private static bool TryReadAsnLength(byte[] data, ref int offset, out int length) {
        length = 0;
        if (data == null || offset < 0 || offset >= data.Length) {
            return false;
        }

        var first = data[offset++];
        if ((first & 0x80) == 0) {
            length = first;
            return true;
        }

        var count = first & 0x7F;
        if (count <= 0 || count > 4 || offset + count > data.Length) {
            return false;
        }

        int value = 0;
        for (int i = 0; i < count; i++) {
            value = (value << 8) | data[offset++];
        }

        if (value < 0) {
            return false;
        }

        length = value;
        return true;
    }

    private static bool TryParseLeaf(byte[] leafBytes, out DateTimeOffset? timestampUtc, out int entryType, out byte[]? x509LeafCertificate) {
        timestampUtc = null;
        entryType = -1;
        x509LeafCertificate = null;

        if (leafBytes == null || leafBytes.Length < 12) {
            return false;
        }

        var offset = 0;
        offset++;
        offset++;

        if (!TryReadUInt64BigEndian(leafBytes, ref offset, out var timestampMs)) {
            return false;
        }

        if (!TryReadUInt16BigEndian(leafBytes, ref offset, out var parsedEntryType)) {
            return false;
        }
        entryType = parsedEntryType;
        try {
            timestampUtc = DateTimeOffset.FromUnixTimeMilliseconds((long)timestampMs);
        } catch {
            timestampUtc = null;
        }

        if (entryType == X509EntryType) {
            if (!TryReadVector24(leafBytes, ref offset, out var certBytes)) {
                return false;
            }
            x509LeafCertificate = certBytes;
            return true;
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
        if (extraData == null || extraData.Length < 3) {
            return null;
        }

        var offset = 0;
        return TryReadVector24(extraData, ref offset, out var certBytes) ? certBytes : null;
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

    private static bool TryReadVector24(byte[] data, ref int offset, out byte[] bytes) {
        bytes = Array.Empty<byte>();
        if (!TryReadUInt24(data, ref offset, out var length)) {
            return false;
        }
        if (length < 0 || offset + length > data.Length) {
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

    private static string? GetString(JsonElement obj, string propertyName) {
        if (obj.ValueKind != JsonValueKind.Object) {
            return null;
        }
        if (!obj.TryGetProperty(propertyName, out var value)) {
            return null;
        }
        return value.ValueKind == JsonValueKind.String ? value.GetString() : value.ToString();
    }

    private static long? GetLong(JsonElement obj, string propertyName) {
        if (obj.ValueKind != JsonValueKind.Object) {
            return null;
        }
        if (!obj.TryGetProperty(propertyName, out var value)) {
            return null;
        }
        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var number)) {
            return number;
        }
        if (value.ValueKind == JsonValueKind.String &&
            long.TryParse(value.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out number)) {
            return number;
        }
        return null;
    }

    private readonly struct CtSignedTreeHead {
        public CtSignedTreeHead(long treeSize) {
            TreeSize = treeSize;
        }

        public long TreeSize { get; }
    }

    private readonly struct CtEntryPayload {
        public CtEntryPayload(string leafInputBase64, string extraDataBase64) {
            LeafInputBase64 = leafInputBase64;
            ExtraDataBase64 = extraDataBase64;
        }

        public string LeafInputBase64 { get; }
        public string ExtraDataBase64 { get; }
    }
}

internal sealed class NativeCtCursorState {
    private readonly Dictionary<string, long> _lastProcessed = new(StringComparer.OrdinalIgnoreCase);

    public long? GetLastProcessedIndex(string key) {
        if (string.IsNullOrWhiteSpace(key)) {
            return null;
        }
        return _lastProcessed.TryGetValue(key, out var value) ? value : null;
    }

    public void SetLastProcessedIndex(string key, long value) {
        if (string.IsNullOrWhiteSpace(key)) {
            return;
        }
        if (value < 0) {
            return;
        }
        _lastProcessed[key] = value;
    }

    public static string BuildKey(string baseDomain, string logUrl) {
        return $"{baseDomain}|{logUrl}";
    }

    public static NativeCtCursorState Load(string? path) {
        var state = new NativeCtCursorState();
        if (string.IsNullOrWhiteSpace(path)) {
            return state;
        }
        if (!File.Exists(path)) {
            return state;
        }

        try {
            var json = File.ReadAllText(path);
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) {
                return state;
            }

            if (!doc.RootElement.TryGetProperty("entries", out var entries) || entries.ValueKind != JsonValueKind.Array) {
                return state;
            }

            foreach (var item in entries.EnumerateArray()) {
                if (item.ValueKind != JsonValueKind.Object) {
                    continue;
                }
                var key = item.TryGetProperty("key", out var keyElement) ? keyElement.GetString() : null;
                if (string.IsNullOrWhiteSpace(key)) {
                    continue;
                }

                long? value = null;
                if (item.TryGetProperty("lastProcessedIndex", out var idxElement)) {
                    if (idxElement.ValueKind == JsonValueKind.Number && idxElement.TryGetInt64(out var number)) {
                        value = number;
                    } else if (idxElement.ValueKind == JsonValueKind.String &&
                               long.TryParse(idxElement.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out number)) {
                        value = number;
                    }
                }

                if (value.HasValue && value.Value >= 0) {
                    state._lastProcessed[key!] = value.Value;
                }
            }
        } catch {
            return new NativeCtCursorState();
        }

        return state;
    }

    public void Save(string? path) {
        if (string.IsNullOrWhiteSpace(path)) {
            return;
        }

        try {
            var fullPath = Path.GetFullPath(path);
            var directory = Path.GetDirectoryName(fullPath);
            if (!string.IsNullOrWhiteSpace(directory)) {
                Directory.CreateDirectory(directory);
            }

            var payload = new NativeCtCursorStateDocument {
                Version = 1,
                UpdatedAtUtc = DateTimeOffset.UtcNow,
                Entries = _lastProcessed
                    .OrderBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
                    .Select(kvp => new NativeCtCursorStateEntry {
                        Key = kvp.Key,
                        LastProcessedIndex = kvp.Value
                    })
                    .ToList()
            };

            var json = JsonSerializer.Serialize(payload, JsonOptions.Default);
            File.WriteAllText(fullPath, json);
        } catch {
            // Best effort cursor persistence.
        }
    }

    private sealed class NativeCtCursorStateDocument {
        public int Version { get; set; }
        public DateTimeOffset UpdatedAtUtc { get; set; }
        public List<NativeCtCursorStateEntry> Entries { get; set; } = new();
    }

    private sealed class NativeCtCursorStateEntry {
        public string Key { get; set; } = string.Empty;
        public long LastProcessedIndex { get; set; }
    }
}
