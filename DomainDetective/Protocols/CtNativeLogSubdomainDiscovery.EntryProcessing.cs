using DomainDetective.Helpers;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
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
        RawCtEntryPayload payload,
        string baseDomain,
        bool exactMatchOnly,
        int maxSubdomains,
        NativeCtLogSubdomainDiscoveryResult result,
        InternalLogger? logger,
        out int matchedObservationCount) {
        matchedObservationCount = 0;
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
            using var cert = CertificateLoaderCompat.LoadCertificate(certBytes);
            var matchedNames = new List<string>();
            foreach (var candidate in ExtractCandidateNames(cert)) {
                if (exactMatchOnly) {
                    if (!TryMatchExactHostCandidate(candidate, baseDomain, out var exactMatchedName)) {
                        continue;
                    }
                    matchedNames.Add(exactMatchedName);
                } else {
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

                    matchedNames.Add(normalized);
                }
            }

            if (matchedNames.Count == 0) {
                return true;
            }

            if (!HasCapacityForEntry(result.Subdomains, matchedNames, maxSubdomains)) {
                result.Warnings.Add($"Native CT certificate exceeds the remaining subdomain capacity for {baseDomain}; no part of this entry was emitted. Increase MaxSubdomains to replay it.");
                return false;
            }

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

            foreach (var matchedName in matchedNames) {
                if (!UpsertObservation(result.Subdomains, matchedName, maxSubdomains, timestampUtc, cert)) {
                    matchedObservationCount = 0;
                    return false;
                }
            }

            matchedObservationCount = matchedNames.Count;
        } catch (Exception ex) {
            logger?.WriteVerbose("Native CT certificate decode failed: {0}", ex.Message);
        }

        return true;
    }

    private static bool TryProcessEntryForDomains(
        RawCtEntryPayload payload,
        HashSet<string> baseDomains,
        HashSet<string> exactMatchDomains,
        int maxSubdomainsPerDomain,
        NativeCtLogSubdomainDiscoveryBatchResult result,
        InternalLogger? logger,
        out int matchedObservationCount) {
        matchedObservationCount = 0;
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
            using var cert = CertificateLoaderCompat.LoadCertificate(certBytes);
            var matchedByDomain = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var candidate in ExtractCandidateNames(cert)) {
                foreach (var exactDomain in MatchExactHostCandidates(candidate, exactMatchDomains)) {
                    if (!matchedByDomain.TryGetValue(exactDomain, out var exactNames)) {
                        exactNames = new List<string>();
                        matchedByDomain[exactDomain] = exactNames;
                    }
                    exactNames.Add(exactDomain);
                }

                var normalized = NormalizeCandidate(candidate);
                if (normalized == null) {
                    continue;
                }

                var matches = MatchBaseDomains(normalized, baseDomains, exactMatchDomains);
                if (matches.Count == 0) {
                    continue;
                }

                foreach (var matchedDomain in matches) {
                    if (!matchedByDomain.TryGetValue(matchedDomain, out var matchedNames)) {
                        matchedNames = new List<string>();
                        matchedByDomain[matchedDomain] = matchedNames;
                    }
                    matchedNames.Add(normalized);
                }
            }

            if (matchedByDomain.Count == 0) {
                return true;
            }

            foreach (var pair in matchedByDomain) {
                result.SubdomainsByDomain.TryGetValue(pair.Key, out var existingMap);
                if (!HasCapacityForEntry(existingMap, pair.Value, maxSubdomainsPerDomain)) {
                    result.Warnings.Add($"Native CT certificate exceeds the remaining subdomain capacity for {pair.Key}; no part of this entry was emitted. Increase MaxSubdomains to replay it.");
                    return false;
                }
            }

            foreach (var pair in matchedByDomain) {
                if (!result.SubdomainsByDomain.TryGetValue(pair.Key, out var map)) {
                    map = new Dictionary<string, NativeCtSubdomainObservation>(StringComparer.OrdinalIgnoreCase);
                    result.SubdomainsByDomain[pair.Key] = map;
                }

                foreach (var matchedName in pair.Value) {
                    if (!UpsertObservation(map, matchedName, maxSubdomainsPerDomain, timestampUtc, cert)) {
                        matchedObservationCount = 0;
                        return false;
                    }
                    matchedObservationCount++;
                }
            }
        } catch (Exception ex) {
            logger?.WriteVerbose("Native CT shared certificate decode failed: {0}", ex.Message);
        }

        return true;
    }

    private static bool HasCapacityForEntry(Dictionary<string, NativeCtSubdomainObservation>? map,
        IEnumerable<string> names, int maximum) {
        if (maximum <= 0) return true;
        int newNames = names.Distinct(StringComparer.OrdinalIgnoreCase).Count(name => map == null || !map.ContainsKey(name));
        return newNames <= maximum - (map?.Count ?? 0);
    }

    private static bool UpsertObservation(
        Dictionary<string, NativeCtSubdomainObservation> map,
        string normalizedName,
        int maxSubdomains,
        DateTimeOffset? timestampUtc,
        X509Certificate2 certificate) {
        if (!map.TryGetValue(normalizedName, out NativeCtSubdomainObservation? observation)) {
            if (maxSubdomains > 0 && map.Count >= maxSubdomains) {
                return false;
            }

            observation = new NativeCtSubdomainObservation();
            map[normalizedName] = observation;
        }

        observation.CertificateObservationCount++;
        if (timestampUtc.HasValue) {
            DateTimeOffset ts = timestampUtc.Value;
            if (!observation.FirstSeenUtc.HasValue || ts < observation.FirstSeenUtc.Value) {
                observation.FirstSeenUtc = ts;
            }
            if (!observation.LastSeenUtc.HasValue || ts > observation.LastSeenUtc.Value) {
                observation.LastSeenUtc = ts;
            }
        }

        var shouldUpdateLatestMetadata = !observation.LatestCertificateCtEntryTimestampUtc.HasValue;
        if (timestampUtc.HasValue &&
            (!observation.LatestCertificateCtEntryTimestampUtc.HasValue ||
             timestampUtc.Value >= observation.LatestCertificateCtEntryTimestampUtc.Value)) {
            shouldUpdateLatestMetadata = true;
        }

        if (shouldUpdateLatestMetadata) {
            var eku = CertificateExtendedKeyUsageAnalyzer.Analyze(certificate);
            string? signatureOid = certificate.SignatureAlgorithm?.Value;
            int keySize = GetPublicKeySize(certificate);
            IReadOnlyList<string> subjectAlternativeNames = ExtractCandidateNames(certificate)
                .Where(static name => !string.IsNullOrWhiteSpace(name))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static name => name, StringComparer.OrdinalIgnoreCase)
                .ToList();

            observation.LatestCertificateCtEntryTimestampUtc = timestampUtc;
            observation.LatestCertificateThumbprint = NormalizeThumbprint(certificate.Thumbprint);
            observation.LatestCertificateSubject = certificate.Subject;
            observation.LatestCertificateIssuer = certificate.Issuer;
            observation.LatestCertificateSerialNumber = certificate.SerialNumber;
            observation.LatestCertificateNotBeforeUtc = new DateTimeOffset(certificate.NotBefore.ToUniversalTime());
            observation.LatestCertificateNotAfterUtc = new DateTimeOffset(certificate.NotAfter.ToUniversalTime());
            observation.LatestCertificateSubjectAlternativeNames = subjectAlternativeNames;
            observation.LatestCertificateIsSelfSigned = IsSelfSigned(certificate);
            observation.LatestCertificateWeakKey = keySize > 0 && keySize < 2048;
            observation.LatestCertificateSha1Signature = IsSha1Signature(signatureOid);
            observation.LatestCertificateHasServerAuthentication = eku.AllowsServerAuthentication;
            observation.LatestCertificateHasClientAuthentication = eku.AllowsClientAuthentication;
            observation.LatestCertificateHasSecureEmail = eku.AllowsSecureEmail;
            observation.LatestCertificateAuthenticationProfile = string.IsNullOrWhiteSpace(eku.AuthenticationProfile)
                ? CertificateAuthenticationProfileClassifier.Classify(eku)
                : eku.AuthenticationProfile;
        }

        return true;
    }

    private static IReadOnlyList<string> MatchBaseDomains(
        string normalizedName,
        HashSet<string> baseDomains,
        HashSet<string> exactMatchDomains) {
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
            if (baseDomains.Contains(suffix) &&
                !string.Equals(suffix, normalizedName, StringComparison.OrdinalIgnoreCase) &&
                (exactMatchDomains == null || !exactMatchDomains.Contains(suffix))) {
                matches.Add(suffix);
            }
        }

        return matches.Count == 0
            ? Array.Empty<string>()
            : matches.OrderBy(domain => domain, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static IReadOnlyList<string> MatchExactHostCandidates(string? rawCandidate, HashSet<string> exactMatchDomains) {
        if (exactMatchDomains == null || exactMatchDomains.Count == 0 || string.IsNullOrWhiteSpace(rawCandidate)) {
            return Array.Empty<string>();
        }

        var matches = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var exactMatchDomain in exactMatchDomains) {
            if (TryMatchExactHostCandidate(rawCandidate, exactMatchDomain, out var matchedName)) {
                matches.Add(matchedName);
            }
        }

        return matches.Count == 0
            ? Array.Empty<string>()
            : matches.OrderBy(domain => domain, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static bool TryMatchExactHostCandidate(string? rawCandidate, string exactHost, out string matchedName) {
        matchedName = string.Empty;
        if (string.IsNullOrWhiteSpace(rawCandidate) || string.IsNullOrWhiteSpace(exactHost)) {
            return false;
        }

        var exactNormalized = NormalizeCandidate(exactHost);
        if (exactNormalized == null) {
            return false;
        }

        var normalizedCandidate = NormalizeCandidate(rawCandidate);
        if (normalizedCandidate != null &&
            string.Equals(normalizedCandidate, exactNormalized, StringComparison.OrdinalIgnoreCase)) {
            matchedName = exactNormalized;
            return true;
        }

        var wildcardCandidate = NormalizeCandidatePreserveWildcard(rawCandidate);
        if (wildcardCandidate == null || !wildcardCandidate.StartsWith("*.", StringComparison.Ordinal)) {
            return false;
        }

        var wildcardSuffix = wildcardCandidate.Substring(2);
        if (!IsSingleLabelWildcardMatch(exactNormalized, wildcardSuffix)) {
            return false;
        }

        matchedName = exactNormalized;
        return true;
    }

    private static bool IsSingleLabelWildcardMatch(string host, string wildcardSuffix) {
        if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(wildcardSuffix)) {
            return false;
        }

        if (!host.EndsWith("." + wildcardSuffix, StringComparison.OrdinalIgnoreCase)) {
            return false;
        }

        var hostLabels = host.Split('.');
        var suffixLabels = wildcardSuffix.Split('.');
        return hostLabels.Length == suffixLabels.Length + 1;
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

    private static string? NormalizeCandidatePreserveWildcard(string? raw) {
        if (string.IsNullOrWhiteSpace(raw)) {
            return null;
        }

        var value = raw!.Trim().TrimEnd('.').ToLowerInvariant();
        if (value.Contains(" ", StringComparison.Ordinal)) {
            return null;
        }
        if (value.Contains("/", StringComparison.Ordinal)) {
            return null;
        }
        if (string.Equals(value, "*", StringComparison.Ordinal)) {
            return null;
        }
        if (value.Length == 0) {
            return null;
        }

        return value;
    }

    private static IReadOnlyCollection<string> ExtractCandidateNames(X509Certificate2 certificate)
        => CtCertificateRecord.ExtractDnsNames(certificate);

    private static string? NormalizeThumbprint(string? value) {
        if (string.IsNullOrWhiteSpace(value)) {
            return null;
        }

        return value!.Trim().ToUpperInvariant();
    }

    private static bool IsSelfSigned(X509Certificate2? certificate) {
        if (certificate == null) {
            return false;
        }

        return string.Equals(certificate.Subject, certificate.Issuer, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSha1Signature(string? oid) {
        return oid == "1.2.840.113549.1.1.5" ||
               oid == "1.2.840.10040.4.3" ||
               oid == "1.3.14.3.2.29";
    }

    private static int GetPublicKeySize(X509Certificate2 certificate) {
        if (certificate == null) {
            return 0;
        }

        try {
            using RSA? rsa = certificate.GetRSAPublicKey();
            if (rsa != null) {
                return rsa.KeySize;
            }
        } catch {
        }

        try {
            using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
            if (ecdsa != null) {
                return ecdsa.KeySize;
            }
        } catch {
        }

        try {
            using DSA? dsa = certificate.GetDSAPublicKey();
            if (dsa != null) {
                return dsa.KeySize;
            }
        } catch {
        }

        return 0;
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

}
