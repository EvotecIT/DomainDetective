using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Network;

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
            !options.EnablePassiveCtFallback ||
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

        var remainingMissingNames = merged.Values
            .Where(IsCtCertificateMetadataMissing)
            .Select(static entry => entry.Name?.Trim())
            .Where(static name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static name => name, StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (remainingMissingNames.Count > 0) {
            logger.WriteVerbose(
                "CT metadata backfill: querying exact passive CT metadata for {0} remaining host(s).",
                remainingMissingNames.Count);

            IReadOnlyList<SubdomainDiscoveryEntry> exactBackfilled = await BackfillMissingCtCertificateMetadataExactAsync(
                remainingMissingNames!,
                options,
                logger,
                cancellationToken).ConfigureAwait(false);
            foreach (var exactEntry in exactBackfilled) {
                if (exactEntry == null || string.IsNullOrWhiteSpace(exactEntry.Name)) {
                    continue;
                }

                MergeCtSubdomainEntry(merged, exactEntry);
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

    private async Task<IReadOnlyList<SubdomainDiscoveryEntry>> BackfillMissingCtCertificateMetadataExactAsync(
        IReadOnlyList<string> hostNames,
        CertificateInventoryCaptureOptions options,
        InternalLogger logger,
        CancellationToken cancellationToken) {
        if (hostNames == null || hostNames.Count == 0) {
            return Array.Empty<SubdomainDiscoveryEntry>();
        }

        var results = new Dictionary<string, SubdomainDiscoveryEntry>(StringComparer.OrdinalIgnoreCase);
        var maxParallelism = Math.Max(1, options.DiscoveryParallelism);
        using var gate = new SemaphoreSlim(maxParallelism, maxParallelism);
        var tasks = new List<Task>(hostNames.Count);
        foreach (var hostName in hostNames) {
            if (string.IsNullOrWhiteSpace(hostName)) {
                continue;
            }

            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            tasks.Add(Task.Run(async () => {
                try {
                    SubdomainDiscoveryEntry? exactEntry;
                    if (CtPassiveMetadataBackfillOverride != null) {
                        IReadOnlyList<SubdomainDiscoveryEntry> overridden = await CtPassiveMetadataBackfillOverride(
                            new[] { hostName },
                            options,
                            logger,
                            cancellationToken).ConfigureAwait(false);
                        exactEntry = overridden
                            .FirstOrDefault(entry =>
                                entry != null &&
                                !string.IsNullOrWhiteSpace(entry.Name) &&
                                hostName.Equals(entry.Name.Trim(), StringComparison.OrdinalIgnoreCase));
                    } else {
                        exactEntry = await QueryPassiveCtMetadataExactAsync(hostName, logger, cancellationToken)
                            .ConfigureAwait(false);
                    }

                    if (exactEntry == null || string.IsNullOrWhiteSpace(exactEntry.Name)) {
                        return;
                    }

                    lock (results) {
                        MergeCtSubdomainEntry(results, exactEntry);
                    }
                } catch (Exception ex) {
                    logger.WriteVerbose(
                        "CT metadata backfill exact lookup failed for {0}: {1}",
                        hostName,
                        ex.Message);
                } finally {
                    gate.Release();
                }
            }, cancellationToken));
        }

        await Task.WhenAll(tasks).ConfigureAwait(false);
        return results.Values
            .OrderBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static async Task<SubdomainDiscoveryEntry?> QueryPassiveCtMetadataExactAsync(
        string hostName,
        InternalLogger logger,
        CancellationToken cancellationToken) {
        if (string.IsNullOrWhiteSpace(hostName)) {
            return null;
        }

        string normalizedHost = hostName.Trim().TrimEnd('.').ToLowerInvariant();
        string requestUrl = "https://crt.sh/?q=" + Uri.EscapeDataString(normalizedHost) + "&output=json";

        using var request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
        using HttpResponseMessage response = await SharedHttpClient.Instance.SendAsync(request, cancellationToken)
            .ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        string payload = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(payload)) {
            return null;
        }

        using JsonDocument document = JsonDocument.Parse(payload);
        if (document.RootElement.ValueKind != JsonValueKind.Array) {
            return null;
        }

        DateTimeOffset? firstSeenUtc = null;
        DateTimeOffset? lastSeenUtc = null;
        DateTimeOffset? latestCertificateEntryTimestampUtc = null;
        string? latestCertificateSubject = null;
        string? latestCertificateIssuer = null;
        string? latestCertificateSerialNumber = null;
        DateTimeOffset? latestCertificateNotBeforeUtc = null;
        DateTimeOffset? latestCertificateNotAfterUtc = null;
        var ctSources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var observationCount = 0;

        foreach (JsonElement item in document.RootElement.EnumerateArray()) {
            IReadOnlyList<string> candidateNames = GetCtMetadataCandidateNames(item);
            if (!candidateNames.Any(candidate =>
                    string.Equals(candidate, normalizedHost, StringComparison.OrdinalIgnoreCase))) {
                continue;
            }

            DateTimeOffset? entryTimestampUtc = ParseCtMetadataTimestamp(
                GetCtMetadataString(item, "entry_timestamp") ?? GetCtMetadataString(item, "not_before"));
            if (entryTimestampUtc.HasValue) {
                if (!firstSeenUtc.HasValue || entryTimestampUtc.Value < firstSeenUtc.Value) {
                    firstSeenUtc = entryTimestampUtc.Value;
                }

                if (!lastSeenUtc.HasValue || entryTimestampUtc.Value > lastSeenUtc.Value) {
                    lastSeenUtc = entryTimestampUtc.Value;
                }
            }

            observationCount++;
            ctSources.Add("crt.sh");

            bool shouldUpdateLatestMetadata = !latestCertificateEntryTimestampUtc.HasValue;
            if (entryTimestampUtc.HasValue &&
                (!latestCertificateEntryTimestampUtc.HasValue ||
                 entryTimestampUtc.Value >= latestCertificateEntryTimestampUtc.Value)) {
                shouldUpdateLatestMetadata = true;
            }

            if (!shouldUpdateLatestMetadata) {
                continue;
            }

            latestCertificateEntryTimestampUtc = entryTimestampUtc;
            latestCertificateSubject = GetCtMetadataCommonName(item) ?? normalizedHost;
            latestCertificateIssuer = GetCtMetadataIssuerName(item);
            latestCertificateSerialNumber = GetCtMetadataString(item, "serial_number");
            latestCertificateNotBeforeUtc = ParseCtMetadataTimestamp(GetCtMetadataString(item, "not_before"));
            latestCertificateNotAfterUtc = ParseCtMetadataTimestamp(GetCtMetadataString(item, "not_after"));
        }

        if (observationCount == 0) {
            logger.WriteVerbose("CT metadata backfill exact lookup returned no rows for {0}.", normalizedHost);
            return null;
        }

        return new SubdomainDiscoveryEntry {
            Name = normalizedHost,
            FirstSeenUtc = firstSeenUtc,
            LastSeenUtc = lastSeenUtc,
            LatestCertificateCtEntryTimestampUtc = latestCertificateEntryTimestampUtc,
            LatestCertificateSubject = latestCertificateSubject,
            LatestCertificateIssuer = latestCertificateIssuer,
            LatestCertificateSerialNumber = latestCertificateSerialNumber,
            LatestCertificateNotBeforeUtc = latestCertificateNotBeforeUtc,
            LatestCertificateNotAfterUtc = latestCertificateNotAfterUtc,
            CtSources = ctSources.OrderBy(source => source, StringComparer.OrdinalIgnoreCase).ToList(),
            CertificateObservationCount = observationCount,
            ResolutionStatus = SubdomainResolutionStatus.Unknown
        };
    }

    private static string? GetCtMetadataString(JsonElement obj, string propertyName) {
        if (obj.ValueKind != JsonValueKind.Object || string.IsNullOrWhiteSpace(propertyName)) {
            return null;
        }

        if (!obj.TryGetProperty(propertyName, out JsonElement value)) {
            return null;
        }

        return value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : value.ToString();
    }

    private static string? GetCtMetadataIssuerName(JsonElement obj) {
        string? direct = GetCtMetadataString(obj, "issuer_name");
        if (!string.IsNullOrWhiteSpace(direct)) {
            return direct;
        }

        if (obj.ValueKind != JsonValueKind.Object || !obj.TryGetProperty("issuer", out JsonElement issuer)) {
            return null;
        }

        if (issuer.ValueKind == JsonValueKind.String) {
            return issuer.GetString();
        }

        if (issuer.ValueKind != JsonValueKind.Object) {
            return null;
        }

        return GetCtMetadataString(issuer, "name") ??
               GetCtMetadataString(issuer, "common_name") ??
               GetCtMetadataString(issuer, "organization");
    }

    private static string? GetCtMetadataCommonName(JsonElement obj) {
        string? commonName = GetCtMetadataString(obj, "common_name");
        if (!string.IsNullOrWhiteSpace(commonName)) {
            return commonName;
        }

        if (obj.ValueKind == JsonValueKind.Object &&
            obj.TryGetProperty("dns_names", out JsonElement dnsNames) &&
            dnsNames.ValueKind == JsonValueKind.Array) {
            foreach (JsonElement dnsName in dnsNames.EnumerateArray()) {
                if (dnsName.ValueKind != JsonValueKind.String) {
                    continue;
                }

                string? value = NormalizeCtMetadataCandidate(dnsName.GetString());
                if (!string.IsNullOrWhiteSpace(value)) {
                    return value;
                }
            }
        }

        return null;
    }

    private static IReadOnlyList<string> GetCtMetadataCandidateNames(JsonElement obj) {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        string? nameValue = GetCtMetadataString(obj, "name_value");
        if (!string.IsNullOrWhiteSpace(nameValue)) {
            string normalizedNameValue = nameValue!;
            foreach (string value in normalizedNameValue.Split('\n')) {
                string? normalized = NormalizeCtMetadataCandidate(value);
                if (!string.IsNullOrWhiteSpace(normalized)) {
                    names.Add(normalized!);
                }
            }
        }

        if (obj.ValueKind == JsonValueKind.Object &&
            obj.TryGetProperty("dns_names", out JsonElement dnsNames) &&
            dnsNames.ValueKind == JsonValueKind.Array) {
            foreach (JsonElement dnsName in dnsNames.EnumerateArray()) {
                if (dnsName.ValueKind != JsonValueKind.String) {
                    continue;
                }

                string? normalized = NormalizeCtMetadataCandidate(dnsName.GetString());
                if (!string.IsNullOrWhiteSpace(normalized)) {
                    names.Add(normalized!);
                }
            }
        }

        return names.Count == 0
            ? Array.Empty<string>()
            : names.OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static string? NormalizeCtMetadataCandidate(string? value) {
        if (string.IsNullOrWhiteSpace(value)) {
            return null;
        }

        string normalized = value!.Trim().TrimEnd('.').ToLowerInvariant();
        while (normalized.StartsWith("*.", StringComparison.Ordinal)) {
            normalized = normalized.Substring(2);
        }

        return normalized.Length == 0 ? null : normalized;
    }

    private static DateTimeOffset? ParseCtMetadataTimestamp(string? value) {
        if (string.IsNullOrWhiteSpace(value)) {
            return null;
        }

        return DateTimeOffset.TryParse(
            value,
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
            out DateTimeOffset parsed)
            ? parsed
            : (DateTimeOffset?)null;
    }
}
