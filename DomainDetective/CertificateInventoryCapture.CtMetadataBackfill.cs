using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public sealed partial class CertificateInventoryCapture {
    private async Task<IReadOnlyList<SubdomainDiscoveryEntry>> BackfillMissingCtCertificateMetadataAsync(
        IReadOnlyList<string> domains,
        IReadOnlyList<SubdomainDiscoveryEntry> discoveredEntries,
        CertificateInventoryCaptureOptions options,
        List<string> warnings,
        InternalLogger logger,
        CancellationToken cancellationToken) {
        if (discoveredEntries == null || discoveredEntries.Count == 0) {
            return Array.Empty<SubdomainDiscoveryEntry>();
        }

        if (options == null ||
            options.NativeCtLogOnly ||
            !options.BackfillMissingCtCertificateMetadata) {
            return discoveredEntries;
        }

        var merged = new Dictionary<string, SubdomainDiscoveryEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in discoveredEntries) {
            if (entry == null || string.IsNullOrWhiteSpace(entry.Name)) {
                continue;
            }

            merged[entry.Name.Trim()] = CloneSubdomainEntry(entry);
        }

        if (merged.Count == 0) {
            return Array.Empty<SubdomainDiscoveryEntry>();
        }

        var missingByDomain = BuildMissingMetadataDomainMap(domains, merged.Values);
        if (missingByDomain.Count == 0) {
            return merged.Values
                .OrderBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        logger.WriteVerbose(
            "CT metadata backfill: querying passive CT for {0} domain(s) to hydrate {1} subdomain(s).",
            missingByDomain.Count,
            missingByDomain.Sum(static pair => pair.Value.Count));

        foreach (var pair in missingByDomain.OrderBy(static row => row.Key, StringComparer.OrdinalIgnoreCase)) {
            cancellationToken.ThrowIfCancellationRequested();

            var domain = pair.Key;
            var targetNames = pair.Value;
            if (targetNames.Count == 0) {
                continue;
            }

            IReadOnlyList<SubdomainDiscoveryEntry> passiveDiscovered;
            if (CtPassiveMetadataBackfillOverride != null) {
                passiveDiscovered = await CtPassiveMetadataBackfillOverride(
                    new[] { domain },
                    options,
                    logger,
                    cancellationToken).ConfigureAwait(false);
            } else {
                passiveDiscovered = await DiscoverCtSubdomainsPassiveAsync(
                    new[] { domain },
                    options,
                    warnings,
                    logger,
                    cancellationToken,
                    dnsEndpointOverride: null,
                    allowSystemDnsRetry: true).ConfigureAwait(false);
            }

            if (passiveDiscovered.Count == 0) {
                continue;
            }

            foreach (var passiveEntry in passiveDiscovered) {
                if (passiveEntry == null || string.IsNullOrWhiteSpace(passiveEntry.Name)) {
                    continue;
                }

                var normalizedName = passiveEntry.Name.Trim();
                if (!targetNames.Contains(normalizedName)) {
                    continue;
                }
                if (!merged.ContainsKey(normalizedName)) {
                    continue;
                }

                MergeCtSubdomainEntry(merged, passiveEntry);
                if (merged.TryGetValue(normalizedName, out var hydrated) &&
                    hydrated != null &&
                    !IsCtCertificateMetadataMissing(hydrated)) {
                    targetNames.Remove(normalizedName);
                }
            }
        }

        var remainingMissing = merged.Values.Count(IsCtCertificateMetadataMissing);
        if (remainingMissing > 0) {
            warnings.Add(
                "CT certificate metadata remained unavailable for " +
                remainingMissing +
                " discovered subdomain(s) after passive backfill.");
        }

        return merged.Values
            .OrderBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static Dictionary<string, HashSet<string>> BuildMissingMetadataDomainMap(
        IReadOnlyList<string> domains,
        IEnumerable<SubdomainDiscoveryEntry> entries) {
        var map = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        if (domains == null || domains.Count == 0 || entries == null) {
            return map;
        }

        var normalizedDomains = domains
            .Where(domain => !string.IsNullOrWhiteSpace(domain))
            .Select(static domain => domain.Trim().TrimEnd('.').ToLowerInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(static domain => domain.Length)
            .ToList();

        if (normalizedDomains.Count == 0) {
            return map;
        }

        foreach (var entry in entries) {
            if (entry == null || string.IsNullOrWhiteSpace(entry.Name) || !IsCtCertificateMetadataMissing(entry)) {
                continue;
            }

            var name = entry.Name.Trim().TrimEnd('.').ToLowerInvariant();
            var ownerDomain = ResolveOwnerDomain(name, normalizedDomains);
            if (ownerDomain == null) {
                continue;
            }

            if (!map.TryGetValue(ownerDomain, out var names)) {
                names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                map[ownerDomain] = names;
            }

            names.Add(name);
        }

        return map;
    }

    private static string? ResolveOwnerDomain(string host, IReadOnlyList<string> domains) {
        if (string.IsNullOrWhiteSpace(host) || domains == null || domains.Count == 0) {
            return null;
        }

        foreach (var domain in domains) {
            if (string.IsNullOrWhiteSpace(domain)) {
                continue;
            }

            if (host.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
                host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase)) {
                return domain;
            }
        }

        return null;
    }

    private static bool IsCtCertificateMetadataMissing(SubdomainDiscoveryEntry entry) {
        if (entry == null) {
            return true;
        }

        return string.IsNullOrWhiteSpace(entry.LatestCertificateSubject) &&
               string.IsNullOrWhiteSpace(entry.LatestCertificateIssuer) &&
               string.IsNullOrWhiteSpace(entry.LatestCertificateSerialNumber) &&
               !entry.LatestCertificateNotBeforeUtc.HasValue &&
               !entry.LatestCertificateNotAfterUtc.HasValue;
    }
}
