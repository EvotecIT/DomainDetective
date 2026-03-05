using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

public sealed partial class CertificateInventoryCapture {
    private static void EnrichEntriesWithCtSubdomainMetadata(
        IReadOnlyList<CertificateInventoryEntry> entries,
        IReadOnlyDictionary<string, SubdomainDiscoveryEntry> discoveredCtEntries,
        DateTimeOffset capturedAtUtc) {
        if (entries == null || entries.Count == 0 || discoveredCtEntries == null || discoveredCtEntries.Count == 0) {
            return;
        }

        foreach (var entry in entries) {
            if (entry == null) {
                continue;
            }

            if (!TryFindCtDiscoveredEntry(entry, discoveredCtEntries, out var discoveredEntry)) {
                continue;
            }

            entry.PresentInCtLogs = true;
            entry.CtDiscoverySources = MergeDistinctStrings(entry.CtDiscoverySources, discoveredEntry.CtSources);

            entry.CtFirstSeenUtc = MinTimestamp(entry.CtFirstSeenUtc, discoveredEntry.FirstSeenUtc);
            entry.CtLastSeenUtc = MaxTimestamp(entry.CtLastSeenUtc, discoveredEntry.LastSeenUtc);
            entry.CtLatestCertificateEntryTimestampUtc = MaxTimestamp(
                entry.CtLatestCertificateEntryTimestampUtc,
                discoveredEntry.LatestCertificateCtEntryTimestampUtc);

            if (string.IsNullOrWhiteSpace(entry.CtLatestCertificateSubject)) {
                entry.CtLatestCertificateSubject = discoveredEntry.LatestCertificateSubject;
            }
            if (string.IsNullOrWhiteSpace(entry.CtLatestCertificateIssuer)) {
                entry.CtLatestCertificateIssuer = discoveredEntry.LatestCertificateIssuer;
            }
            if (string.IsNullOrWhiteSpace(entry.CtLatestCertificateSerialNumber)) {
                entry.CtLatestCertificateSerialNumber = discoveredEntry.LatestCertificateSerialNumber;
            }
            if (!entry.CtLatestCertificateNotBeforeUtc.HasValue) {
                entry.CtLatestCertificateNotBeforeUtc = discoveredEntry.LatestCertificateNotBeforeUtc;
            }
            if (!entry.CtLatestCertificateNotAfterUtc.HasValue) {
                entry.CtLatestCertificateNotAfterUtc = discoveredEntry.LatestCertificateNotAfterUtc;
            }
            entry.CtObservationCount += Math.Max(0, discoveredEntry.CertificateObservationCount);

            var hydratedFromCt = false;
            if (string.IsNullOrWhiteSpace(entry.CertificateSubject) && !string.IsNullOrWhiteSpace(discoveredEntry.LatestCertificateSubject)) {
                entry.CertificateSubject = discoveredEntry.LatestCertificateSubject;
                hydratedFromCt = true;
            }
            if (string.IsNullOrWhiteSpace(entry.CertificateIssuer) && !string.IsNullOrWhiteSpace(discoveredEntry.LatestCertificateIssuer)) {
                entry.CertificateIssuer = discoveredEntry.LatestCertificateIssuer;
                hydratedFromCt = true;
            }
            if (string.IsNullOrWhiteSpace(entry.CertificateSerialNumber) && !string.IsNullOrWhiteSpace(discoveredEntry.LatestCertificateSerialNumber)) {
                entry.CertificateSerialNumber = discoveredEntry.LatestCertificateSerialNumber;
                hydratedFromCt = true;
            }
            if (!entry.NotBeforeUtc.HasValue && discoveredEntry.LatestCertificateNotBeforeUtc.HasValue) {
                entry.NotBeforeUtc = discoveredEntry.LatestCertificateNotBeforeUtc;
                hydratedFromCt = true;
            }
            if (!entry.NotAfterUtc.HasValue && discoveredEntry.LatestCertificateNotAfterUtc.HasValue) {
                entry.NotAfterUtc = discoveredEntry.LatestCertificateNotAfterUtc;
                hydratedFromCt = true;
            }

            if (entry.NotAfterUtc.HasValue) {
                entry.DaysToExpire = (int)Math.Floor((entry.NotAfterUtc.Value - capturedAtUtc).TotalDays);
                entry.Expired = entry.NotAfterUtc.Value < capturedAtUtc;
            }

            if (hydratedFromCt && string.IsNullOrWhiteSpace(entry.CertificateChainSource)) {
                entry.CertificateChainSource = "ct-log";
            }

            if (string.Equals(entry.CertificateChainSource, "ct-log", StringComparison.OrdinalIgnoreCase)) {
                if (entry.CertificateChainSources == null) {
                    entry.CertificateChainSources = new List<string>();
                }

                if (!entry.CertificateChainSources.Any(source =>
                        string.Equals(source, "ct-log", StringComparison.OrdinalIgnoreCase))) {
                    entry.CertificateChainSources.Add("ct-log");
                }
            }
        }
    }

    private static bool TryFindCtDiscoveredEntry(
        CertificateInventoryEntry entry,
        IReadOnlyDictionary<string, SubdomainDiscoveryEntry> discoveredCtEntries,
        out SubdomainDiscoveryEntry discoveredEntry) {
        var lookupCandidates = new List<string>(3);
        if (!string.IsNullOrWhiteSpace(entry.Host)) {
            lookupCandidates.Add(entry.Host.Trim().TrimEnd('.'));
        }
        var resolvedHost = entry.ResolvedHost;
        if (!string.IsNullOrWhiteSpace(resolvedHost)) {
            lookupCandidates.Add(resolvedHost!.Trim().TrimEnd('.'));
        }
        var urlHost = TryGetHostFromUrl(entry.Url);
        if (!string.IsNullOrWhiteSpace(urlHost)) {
            lookupCandidates.Add(urlHost!);
        }

        foreach (var candidate in lookupCandidates) {
            if (discoveredCtEntries.TryGetValue(candidate, out discoveredEntry!)) {
                return true;
            }
        }

        discoveredEntry = null!;
        return false;
    }

    private static string? TryGetHostFromUrl(string? url) {
        if (string.IsNullOrWhiteSpace(url)) {
            return null;
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) {
            return null;
        }

        return string.IsNullOrWhiteSpace(uri.Host)
            ? null
            : uri.Host.Trim().TrimEnd('.');
    }

    private static IReadOnlyList<string> MergeDistinctStrings(
        IReadOnlyList<string> current,
        IReadOnlyList<string> incoming) {
        var merged = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (current != null) {
            foreach (var value in current) {
                if (!string.IsNullOrWhiteSpace(value)) {
                    merged.Add(value.Trim());
                }
            }
        }
        if (incoming != null) {
            foreach (var value in incoming) {
                if (!string.IsNullOrWhiteSpace(value)) {
                    merged.Add(value.Trim());
                }
            }
        }

        return merged
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
