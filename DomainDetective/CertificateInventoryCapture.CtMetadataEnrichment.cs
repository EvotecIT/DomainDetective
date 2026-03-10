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
            bool replaceCtLatestBundle = ShouldReplaceCtLatestBundle(
                entry.CtLatestCertificateEntryTimestampUtc,
                discoveredEntry.LatestCertificateCtEntryTimestampUtc);
            if (replaceCtLatestBundle) {
                ApplyCtLatestCertificateBundle(entry, discoveredEntry);
            } else {
                FillMissingCtLatestCertificateBundle(entry, discoveredEntry);
            }
            entry.CtObservationCount += Math.Max(0, discoveredEntry.CertificateObservationCount);

            bool hydratedFromCt;
            if (replaceCtLatestBundle &&
                string.Equals(entry.CertificateChainSource, "ct-log", StringComparison.OrdinalIgnoreCase)) {
                hydratedFromCt = ApplyPrimaryCertificateBundleFromCt(entry, discoveredEntry, replaceExisting: true);
            } else {
                hydratedFromCt = ApplyPrimaryCertificateBundleFromCt(entry, discoveredEntry, replaceExisting: false);
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

    private static bool ShouldReplaceCtLatestBundle(
        DateTimeOffset? currentTimestampUtc,
        DateTimeOffset? incomingTimestampUtc) {
        if (!currentTimestampUtc.HasValue) {
            return incomingTimestampUtc.HasValue;
        }

        return incomingTimestampUtc.HasValue && incomingTimestampUtc.Value > currentTimestampUtc.Value;
    }

    private static void ApplyCtLatestCertificateBundle(
        CertificateInventoryEntry entry,
        SubdomainDiscoveryEntry discoveredEntry) {
        entry.CtLatestCertificateEntryTimestampUtc = discoveredEntry.LatestCertificateCtEntryTimestampUtc;
        entry.CtLatestCertificateSubject = discoveredEntry.LatestCertificateSubject;
        entry.CtLatestCertificateIssuer = discoveredEntry.LatestCertificateIssuer;
        entry.CtLatestCertificateSerialNumber = discoveredEntry.LatestCertificateSerialNumber;
        entry.CtLatestCertificateNotBeforeUtc = discoveredEntry.LatestCertificateNotBeforeUtc;
        entry.CtLatestCertificateNotAfterUtc = discoveredEntry.LatestCertificateNotAfterUtc;
    }

    private static void FillMissingCtLatestCertificateBundle(
        CertificateInventoryEntry entry,
        SubdomainDiscoveryEntry discoveredEntry) {
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
    }

    private static bool ApplyPrimaryCertificateBundleFromCt(
        CertificateInventoryEntry entry,
        SubdomainDiscoveryEntry discoveredEntry,
        bool replaceExisting) {
        bool updated = false;

        if (replaceExisting || string.IsNullOrWhiteSpace(entry.CertificateSubject)) {
            if (!string.IsNullOrWhiteSpace(discoveredEntry.LatestCertificateSubject)) {
                entry.CertificateSubject = discoveredEntry.LatestCertificateSubject;
                updated = true;
            }
        }
        if (replaceExisting || string.IsNullOrWhiteSpace(entry.CertificateIssuer)) {
            if (!string.IsNullOrWhiteSpace(discoveredEntry.LatestCertificateIssuer)) {
                entry.CertificateIssuer = discoveredEntry.LatestCertificateIssuer;
                updated = true;
            }
        }
        if (replaceExisting || string.IsNullOrWhiteSpace(entry.CertificateSerialNumber)) {
            if (!string.IsNullOrWhiteSpace(discoveredEntry.LatestCertificateSerialNumber)) {
                entry.CertificateSerialNumber = discoveredEntry.LatestCertificateSerialNumber;
                updated = true;
            }
        }
        if (replaceExisting || !entry.NotBeforeUtc.HasValue) {
            if (discoveredEntry.LatestCertificateNotBeforeUtc.HasValue) {
                entry.NotBeforeUtc = discoveredEntry.LatestCertificateNotBeforeUtc;
                updated = true;
            }
        }
        if (replaceExisting || !entry.NotAfterUtc.HasValue) {
            if (discoveredEntry.LatestCertificateNotAfterUtc.HasValue) {
                entry.NotAfterUtc = discoveredEntry.LatestCertificateNotAfterUtc;
                updated = true;
            }
        }

        return updated;
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
