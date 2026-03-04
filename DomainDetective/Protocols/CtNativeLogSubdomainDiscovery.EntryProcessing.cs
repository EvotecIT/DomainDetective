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

    private static bool TryProcessEntryForDomains(
        CtEntryPayload payload,
        HashSet<string> baseDomains,
        int maxSubdomainsPerDomain,
        NativeCtLogSubdomainDiscoveryBatchResult result,
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
        } else if (entryType == PrecertEntryType && !string.IsNullOrWhiteSpace(payload.ExtraDataBase64)) {
            try {
                var extra = Convert.FromBase64String(payload.ExtraDataBase64);
                certBytes = TryExtractPrecertificateLeaf(extra);
            } catch {
                certBytes = null;
            }
        }

        if (certBytes == null || certBytes.Length == 0) {
            return true;
        }

        try {
            using var cert = new X509Certificate2(certBytes);
            foreach (var candidate in ExtractCandidateNames(cert)) {
                var normalized = NormalizeCandidate(candidate);
                if (normalized == null) {
                    continue;
                }

                var matches = MatchBaseDomains(normalized, baseDomains);
                if (matches.Count == 0) {
                    continue;
                }

                foreach (var matchedDomain in matches) {
                    if (!result.SubdomainsByDomain.TryGetValue(matchedDomain, out var map)) {
                        map = new Dictionary<string, (DateTimeOffset? First, DateTimeOffset? Last)>(StringComparer.OrdinalIgnoreCase);
                        result.SubdomainsByDomain[matchedDomain] = map;
                    }

                    if (!map.TryGetValue(normalized, out var agg)) {
                        if (maxSubdomainsPerDomain > 0 && map.Count >= maxSubdomainsPerDomain) {
                            return false;
                        }
                        map[normalized] = (timestampUtc, timestampUtc);
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
                        map[normalized] = (first, last);
                    }
                }
            }
        } catch (Exception ex) {
            logger?.WriteVerbose("Native CT shared certificate decode failed: {0}", ex.Message);
        }

        return true;
    }

    private static IReadOnlyList<string> MatchBaseDomains(string normalizedName, HashSet<string> baseDomains) {
        if (string.IsNullOrWhiteSpace(normalizedName)) {
            return Array.Empty<string>();
        }

        var labels = normalizedName.Split('.');
        if (labels.Length < 3) {
            return Array.Empty<string>();
        }

        var matches = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 1; i <= labels.Length - 2; i++) {
            var suffix = string.Join(".", labels, i, labels.Length - i);
            if (baseDomains.Contains(suffix) && !string.Equals(suffix, normalizedName, StringComparison.OrdinalIgnoreCase)) {
                matches.Add(suffix);
            }
        }

        return matches.Count == 0
            ? Array.Empty<string>()
            : matches.OrderBy(domain => domain, StringComparer.OrdinalIgnoreCase).ToList();
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
