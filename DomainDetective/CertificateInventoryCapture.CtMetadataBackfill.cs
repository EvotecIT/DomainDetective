using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;
using Npgsql;
using NpgsqlTypes;

namespace DomainDetective;

public sealed partial class CertificateInventoryCapture {
    internal sealed class CrtShPostgreSqlExactMetadataRow
    {
        public byte[]? CertificateDer { get; init; }

        public DateTimeOffset? EntryTimestampUtc { get; init; }

        public string? CommonName { get; init; }

        public string? IssuerName { get; init; }

        public string? SerialNumber { get; init; }

        public DateTimeOffset? NotBeforeUtc { get; init; }

        public DateTimeOffset? NotAfterUtc { get; init; }

        public IReadOnlyList<string> CandidateNames { get; init; } = Array.Empty<string>();
    }

    private async Task<IReadOnlyList<SubdomainDiscoveryEntry>> BackfillMissingCtCertificateMetadataAsync(
        IReadOnlyList<string> domains,
        IReadOnlyList<SubdomainDiscoveryEntry> discoveredEntries,
        CertificateInventoryCaptureOptions options,
        List<string> warnings,
        List<PassiveCtDiagnosticEntry> passiveCtDiagnosticEntries,
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

        bool allowPassiveMetadataFallback = options.EnablePassiveCtFallback ||
                                            options.EnablePassiveCtMetadataFallback;
        bool allowPostgreSqlMetadataFallback = ShouldUseCrtShPostgreSqlMetadataFallback(options);
        if (!allowPassiveMetadataFallback && !allowPostgreSqlMetadataFallback) {
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

        if (allowPassiveMetadataFallback) {
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
                        passiveCtDiagnosticEntries,
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
        }

        bool domainPostgreSqlLookupFailed = false;
        if (allowPostgreSqlMetadataFallback) {
            logger.WriteVerbose(
                "CT metadata backfill: querying domain-batched crt.sh PostgreSQL metadata for {0} domain(s) covering {1} remaining subdomain(s).",
                missingByDomain.Count(static pair => pair.Value.Count > 0),
                missingByDomain.Sum(static pair => pair.Value.Count));

            foreach (KeyValuePair<string, HashSet<string>> pair in missingByDomain
                         .Where(static pair => pair.Value.Count > 0)
                         .OrderBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase)) {
                cancellationToken.ThrowIfCancellationRequested();

                Dictionary<string, SubdomainDiscoveryEntry> domainHydrated;
                try {
                    domainHydrated =
                        await QueryCrtShPostgreSqlMetadataByDomainAsync(
                                pair.Key,
                                pair.Value,
                                options,
                                logger,
                                cancellationToken)
                            .ConfigureAwait(false);
                } catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) {
                    domainPostgreSqlLookupFailed = true;
                    string warning = $"CT metadata backfill domain PostgreSQL lookup timed out for {pair.Key}.";
                    warnings.Add(warning);
                    logger.WriteVerbose(warning);
                    continue;
                } catch (Exception ex) {
                    domainPostgreSqlLookupFailed = true;
                    string warning = $"CT metadata backfill domain PostgreSQL lookup failed for {pair.Key}: {ex.Message}";
                    warnings.Add(warning);
                    logger.WriteVerbose(warning);
                    continue;
                }

                foreach (KeyValuePair<string, SubdomainDiscoveryEntry> hydratedPair in domainHydrated) {
                    MergeCtSubdomainEntry(merged, hydratedPair.Value);
                    if (merged.TryGetValue(hydratedPair.Key, out SubdomainDiscoveryEntry? hydrated) &&
                        hydrated != null &&
                        !IsCtCertificateMetadataMissing(hydrated)) {
                        pair.Value.Remove(hydratedPair.Key);
                    }
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
        HashSet<string> suppressedHosts = options.ExactHostSeedCtMetadataSuppressedHosts
            .Where(static host => !string.IsNullOrWhiteSpace(host))
            .Select(static host => host.Trim().TrimEnd('.').ToLowerInvariant())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (remainingMissingNames.Count > 0 && suppressedHosts.Count > 0) {
            int suppressedCount = remainingMissingNames.Count(name =>
                suppressedHosts.Contains(name!.Trim().TrimEnd('.').ToLowerInvariant()));
            if (suppressedCount > 0 && !domainPostgreSqlLookupFailed) {
                remainingMissingNames = remainingMissingNames
                    .Where(name => !suppressedHosts.Contains(name!.Trim().TrimEnd('.').ToLowerInvariant()))
                    .ToList();
                logger.WriteVerbose(
                    "CT metadata backfill: skipping exact passive CT metadata for {0} remaining host(s) because the caller already supplied suppression state.",
                    suppressedCount);
            } else if (suppressedCount > 0) {
                logger.WriteVerbose(
                    "CT metadata backfill: retaining {0} remaining host(s) for exact passive CT metadata because domain-batched crt.sh PostgreSQL lookup failed in this pass.",
                    suppressedCount);
            }
        }
        if (allowPassiveMetadataFallback &&
            remainingMissingNames.Count > 0 &&
            !TryBuildPassiveCtRunSuppressionReason(passiveCtDiagnosticEntries, out _)) {
            logger.WriteVerbose(
                "CT metadata backfill: querying exact passive CT metadata for {0} remaining host(s).",
                remainingMissingNames.Count);

            IReadOnlyList<SubdomainDiscoveryEntry> exactBackfilled = await BackfillMissingCtCertificateMetadataExactAsync(
                remainingMissingNames!,
                options,
                warnings,
                passiveCtDiagnosticEntries,
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
        if (remainingMissing > 0 && allowPassiveMetadataFallback) {
            warnings.Add(
                "CT certificate metadata remained unavailable for " +
                remainingMissing +
                " discovered subdomain(s) after passive backfill.");
        }

        return merged.Values
            .OrderBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private async Task<IReadOnlyList<SubdomainDiscoveryEntry>> BackfillExactHostSeedCtMetadataAsync(
        IReadOnlyList<CertificateInventorySeed> seeds,
        IReadOnlyDictionary<string, SubdomainDiscoveryEntry> existingEntries,
        CertificateInventoryCaptureOptions options,
        List<string> warnings,
        List<PassiveCtDiagnosticEntry> passiveCtDiagnosticEntries,
        InternalLogger logger,
        CancellationToken cancellationToken) {
        if (seeds == null || seeds.Count == 0 || options == null) {
            return Array.Empty<SubdomainDiscoveryEntry>();
        }

        if (options.NativeCtLogOnly ||
            !options.BackfillMissingCtCertificateMetadata ||
            (!options.EnablePassiveCtFallback &&
             !options.EnablePassiveCtMetadataFallback &&
             !ShouldUseCrtShPostgreSqlMetadataFallback(options))) {
            return Array.Empty<SubdomainDiscoveryEntry>();
        }

        HashSet<string> suppressedHosts = options.ExactHostSeedCtMetadataSuppressedHosts
            .Where(static host => !string.IsNullOrWhiteSpace(host))
            .Select(static host => host.Trim().TrimEnd('.').ToLowerInvariant())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        HashSet<string> targetedExactCtMetadataHosts = options.ExactPassiveCtMetadataTargetHosts
            .Where(static host => !string.IsNullOrWhiteSpace(host))
            .Select(static host => host.Trim().TrimEnd('.').ToLowerInvariant())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (targetedExactCtMetadataHosts.Count == 0) {
            targetedExactCtMetadataHosts = options.CtMetadataTargetHosts
            .Where(static host => !string.IsNullOrWhiteSpace(host))
            .Select(static host => host.Trim().TrimEnd('.').ToLowerInvariant())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        }

        List<string> exactHostSeeds = seeds
            .Where(static seed => seed != null && seed.IsExactHostSeed && !string.IsNullOrWhiteSpace(seed.Name))
            .Select(static seed => seed.Name.Trim())
            .ToList();
        IReadOnlyList<string> exactPassiveCtMetadataHosts = BuildExactPassiveCtMetadataCandidateHosts(
            exactHostSeeds,
            targetedExactCtMetadataHosts,
            suppressedHosts,
            existingEntries);
        if (exactPassiveCtMetadataHosts.Count == 0) {
            return Array.Empty<SubdomainDiscoveryEntry>();
        }

        if (targetedExactCtMetadataHosts.Count > 0) {
            logger.WriteVerbose(
                "CT metadata backfill: targeted exact passive CT metadata to {0} host(s) from {1} caller-supplied target host(s).",
                exactPassiveCtMetadataHosts.Count,
                targetedExactCtMetadataHosts.Count);
        }

        if (!TryBuildPassiveCtRunSuppressionReason(passiveCtDiagnosticEntries, out _)) {
            logger.WriteVerbose(
                "CT metadata backfill: querying exact passive CT metadata for {0} host(s).",
                exactPassiveCtMetadataHosts.Count);
        }

        return await BackfillMissingCtCertificateMetadataExactAsync(
            exactPassiveCtMetadataHosts,
            options,
            warnings,
            passiveCtDiagnosticEntries,
            logger,
            cancellationToken).ConfigureAwait(false);
    }

    internal static IReadOnlyList<string> BuildExactPassiveCtMetadataCandidateHosts(
        IEnumerable<string>? exactHostSeeds,
        IEnumerable<string>? targetedExactCtMetadataHosts,
        ISet<string>? suppressedHosts,
        IReadOnlyDictionary<string, SubdomainDiscoveryEntry>? existingEntries) {
        var candidateHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        HashSet<string> targetedHosts = targetedExactCtMetadataHosts == null
            ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            : targetedExactCtMetadataHosts
                .Where(static host => !string.IsNullOrWhiteSpace(host))
                .Select(static host => host.Trim().TrimEnd('.').ToLowerInvariant())
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

        void TryAddCandidate(string? host) {
            if (string.IsNullOrWhiteSpace(host)) {
                return;
            }

            string normalizedHost = host!.Trim().TrimEnd('.');
            string canonicalHost = normalizedHost.ToLowerInvariant();
            if (suppressedHosts != null && suppressedHosts.Contains(canonicalHost)) {
                return;
            }

            if (targetedHosts.Count > 0 && !targetedHosts.Contains(canonicalHost)) {
                return;
            }

            if (HasCtCertificateMetadata(existingEntries, normalizedHost)) {
                return;
            }

            candidateHosts.Add(normalizedHost);
        }

        if (exactHostSeeds != null) {
            foreach (string host in exactHostSeeds) {
                TryAddCandidate(host);
            }
        }

        if (targetedHosts.Count > 0) {
            foreach (string host in targetedHosts) {
                TryAddCandidate(host);
            }
        }

        return candidateHosts
            .OrderBy(static name => name, StringComparer.OrdinalIgnoreCase)
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

        return string.IsNullOrWhiteSpace(entry.LatestCertificateSubject) ||
               string.IsNullOrWhiteSpace(entry.LatestCertificateIssuer) ||
               string.IsNullOrWhiteSpace(entry.LatestCertificateSerialNumber) ||
               !entry.LatestCertificateNotBeforeUtc.HasValue ||
               !entry.LatestCertificateNotAfterUtc.HasValue ||
               string.IsNullOrWhiteSpace(entry.LatestCertificateThumbprint) ||
               string.IsNullOrWhiteSpace(entry.LatestCertificateAuthenticationProfile);
    }

    private static bool HasCtCertificateMetadata(
        IReadOnlyDictionary<string, SubdomainDiscoveryEntry>? existingEntries,
        string? name) {
        if (existingEntries == null || string.IsNullOrWhiteSpace(name)) {
            return false;
        }

        var normalizedName = name!.Trim();
        if (!existingEntries.TryGetValue(normalizedName, out var existingEntry) || existingEntry == null) {
            return false;
        }

        return !IsCtCertificateMetadataMissing(existingEntry);
    }

    private async Task<IReadOnlyList<SubdomainDiscoveryEntry>> BackfillMissingCtCertificateMetadataExactAsync(
        IReadOnlyList<string> hostNames,
        CertificateInventoryCaptureOptions options,
        List<string> warnings,
        List<PassiveCtDiagnosticEntry> passiveCtDiagnosticEntries,
        InternalLogger logger,
        CancellationToken cancellationToken) {
        if (hostNames == null || hostNames.Count == 0) {
            return Array.Empty<SubdomainDiscoveryEntry>();
        }

        var results = new Dictionary<string, SubdomainDiscoveryEntry>(StringComparer.OrdinalIgnoreCase);
        bool allowPassiveMetadataFallback = options.EnablePassiveCtFallback ||
                                            options.EnablePassiveCtMetadataFallback;
        bool usePassiveNetworkQueries = allowPassiveMetadataFallback && CtPassiveMetadataBackfillOverride == null;
        List<string> normalizedHostNames = hostNames
            .Where(static hostName => !string.IsNullOrWhiteSpace(hostName))
            .Select(static hostName => hostName.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (normalizedHostNames.Count == 0) {
            return Array.Empty<SubdomainDiscoveryEntry>();
        }

        IReadOnlyList<string> remainingHostNames = normalizedHostNames;
        if (ShouldUseCrtShPostgreSqlMetadataFallback(options)) {
            Dictionary<string, SubdomainDiscoveryEntry> directResults = await QueryCrtShPostgreSqlExactMetadataAsync(
                normalizedHostNames,
                options,
                logger,
                cancellationToken).ConfigureAwait(false);
            foreach (KeyValuePair<string, SubdomainDiscoveryEntry> pair in directResults) {
                lock (results) {
                    MergeCtSubdomainEntry(results, pair.Value);
                }
            }

            if (directResults.Count == normalizedHostNames.Count) {
                return results.Values
                    .OrderBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }

            remainingHostNames = normalizedHostNames
                .Where(hostName => !directResults.ContainsKey(hostName))
                .ToList();
            if (remainingHostNames.Count == 0) {
                return results.Values
                    .OrderBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }
        }

        if (!allowPassiveMetadataFallback) {
            return results.Values
                .OrderBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        if (TryBuildPassiveCtRunSuppressionReason(passiveCtDiagnosticEntries, out string suppressionReason)) {
            string warning =
                "Passive CT exact metadata backfill skipped for " +
                remainingHostNames.Count.ToString(System.Globalization.CultureInfo.InvariantCulture) +
                " host(s) because shared sources are cooling down: " +
                suppressionReason;
            warnings?.Add(warning);
            logger.WriteVerbose("{0}", warning);
            return results.Values
                .OrderBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        if (usePassiveNetworkQueries) {
            var sharedClient = new PassiveCtSourceClient();
            int exactNetworkParallelism = ResolveExactPassiveCtMetadataBackfillParallelism(
                options.DiscoveryParallelism,
                options.PassiveCtParallelism,
                options.CrtShPostgreSqlMaximumConcurrentRequests,
                remainingHostNames.Count,
                usePassiveNetworkQueries: true);
            int scheduledHosts = 0;
            while (scheduledHosts < remainingHostNames.Count) {
                cancellationToken.ThrowIfCancellationRequested();

                if (TryBuildPassiveCtRunSuppressionReason(passiveCtDiagnosticEntries, out string preBatchSuppressionReason)) {
                    LogExactPassiveCtMetadataSuppression(
                        warnings,
                        logger,
                        remainingHostNames.Count - scheduledHosts,
                        preBatchSuppressionReason);
                    break;
                }

                List<string> batch = remainingHostNames
                    .Skip(scheduledHosts)
                    .Take(exactNetworkParallelism)
                    .ToList();
                var batchTasks = new List<Task>(batch.Count);
                foreach (string hostName in batch) {
                    batchTasks.Add(Task.Run(async () => {
                        try {
                            SubdomainDiscoveryEntry? exactEntry = await QueryPassiveCtMetadataExactAsync(
                                    hostName,
                                    options,
                                    warnings,
                                    passiveCtDiagnosticEntries,
                                    logger,
                                    sharedClient,
                                    CtPassiveCertificateDownloadOverride,
                                    cancellationToken)
                                .ConfigureAwait(false);
                            if (exactEntry == null || string.IsNullOrWhiteSpace(exactEntry.Name)) {
                                return;
                            }

                            lock (results) {
                                MergeCtSubdomainEntry(results, exactEntry);
                            }
                        } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                            throw;
                        } catch (Exception ex) {
                            logger.WriteVerbose(
                                "CT metadata backfill exact lookup failed for {0}: {1}",
                                hostName,
                                ex.Message);
                        }
                    }, cancellationToken));
                }

                await Task.WhenAll(batchTasks).ConfigureAwait(false);
                scheduledHosts += batch.Count;

                if (TryBuildPassiveCtRunSuppressionReason(passiveCtDiagnosticEntries, out string postBatchSuppressionReason)) {
                    LogExactPassiveCtMetadataSuppression(
                        warnings,
                        logger,
                        remainingHostNames.Count - scheduledHosts,
                        postBatchSuppressionReason);
                    break;
                }
            }

            return results.Values
                .OrderBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        int overrideParallelism = Math.Max(1, options.DiscoveryParallelism);
        using var gate = new SemaphoreSlim(overrideParallelism, overrideParallelism);
        var overrideTasks = new List<Task>(remainingHostNames.Count);
        foreach (string hostName in remainingHostNames) {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            overrideTasks.Add(Task.Run(async () => {
                try {
                    IReadOnlyList<SubdomainDiscoveryEntry> overridden = await CtPassiveMetadataBackfillOverride!(
                        new[] { hostName },
                        options,
                        logger,
                        cancellationToken).ConfigureAwait(false);
                    SubdomainDiscoveryEntry? exactEntry = overridden
                        .FirstOrDefault(entry =>
                            entry != null &&
                            !string.IsNullOrWhiteSpace(entry.Name) &&
                            hostName.Equals(entry.Name.Trim(), StringComparison.OrdinalIgnoreCase));

                    if (exactEntry == null || string.IsNullOrWhiteSpace(exactEntry.Name)) {
                        return;
                    }

                    lock (results) {
                        MergeCtSubdomainEntry(results, exactEntry);
                    }
                } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                    throw;
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

        await Task.WhenAll(overrideTasks).ConfigureAwait(false);
        return results.Values
            .OrderBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private bool ShouldUseCrtShPostgreSqlMetadataFallback(CertificateInventoryCaptureOptions options) {
        var exactMetadataProvider = CtExactMetadataPostgreSqlOverride ?? DomainDetectiveOptionalFeatures.GetCtSqlExactMetadataProvider();
        return options != null &&
               (options.EnableCrtShPostgreSqlMetadataFallback || exactMetadataProvider != null);
    }

    private async Task<Dictionary<string, SubdomainDiscoveryEntry>> QueryCrtShPostgreSqlExactMetadataAsync(
        IReadOnlyList<string> hostNames,
        CertificateInventoryCaptureOptions options,
        InternalLogger logger,
        CancellationToken cancellationToken) {
        var results = new Dictionary<string, SubdomainDiscoveryEntry>(StringComparer.OrdinalIgnoreCase);
        if (hostNames == null || hostNames.Count == 0) {
            return results;
        }

        var exactMetadataProvider = CtExactMetadataPostgreSqlOverride ?? DomainDetectiveOptionalFeatures.GetCtSqlExactMetadataProvider();
        if (exactMetadataProvider == null) {
            return await QueryCrtShPostgreSqlMetadataExactSequentialAsync(
                hostNames,
                options,
                logger,
                cancellationToken).ConfigureAwait(false);
        }

        int exactParallelism = ResolveExactPassiveCtMetadataBackfillParallelism(
            options.DiscoveryParallelism,
            options.PassiveCtParallelism,
            options.CrtShPostgreSqlMaximumConcurrentRequests,
            hostNames.Count,
            usePassiveNetworkQueries: false);
        using var gate = new SemaphoreSlim(exactParallelism, exactParallelism);
        var tasks = new List<Task>(hostNames.Count);
        foreach (string hostName in hostNames) {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            tasks.Add(Task.Run(async () => {
                try {
                    SubdomainDiscoveryEntry? entry = exactMetadataProvider != null
                        ? await exactMetadataProvider(hostName, options, logger, cancellationToken).ConfigureAwait(false)
                        : await QueryCrtShPostgreSqlMetadataExactAsync(hostName, options, logger, cancellationToken).ConfigureAwait(false);
                    if (entry == null || string.IsNullOrWhiteSpace(entry.Name)) {
                        return;
                    }

                    lock (results) {
                        MergeCtSubdomainEntry(results, entry);
                    }
                } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                    throw;
                } catch (Exception ex) {
                    logger.WriteVerbose(
                        "CT metadata backfill exact PostgreSQL lookup failed for {0}: {1}",
                        hostName,
                        ex.Message);
                } finally {
                    gate.Release();
                }
            }, cancellationToken));
        }

        await Task.WhenAll(tasks).ConfigureAwait(false);
        return results;
    }

    private static async Task<Dictionary<string, SubdomainDiscoveryEntry>> QueryCrtShPostgreSqlMetadataExactSequentialAsync(
        IReadOnlyList<string> hostNames,
        CertificateInventoryCaptureOptions options,
        InternalLogger? logger,
        CancellationToken cancellationToken) {
        var results = new Dictionary<string, SubdomainDiscoveryEntry>(StringComparer.OrdinalIgnoreCase);
        if (hostNames == null || hostNames.Count == 0 || options == null) {
            return results;
        }

        List<string> normalizedHosts = hostNames
            .Where(static host => !string.IsNullOrWhiteSpace(host))
            .Select(static host => host.Trim().TrimEnd('.').ToLowerInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (normalizedHosts.Count == 0) {
            return results;
        }

        string connectionString = BuildCrtShPostgreSqlConnectionString(options);
        HashSet<string> targetedThumbprints = BuildTargetedCtMetadataThumbprintSet(options);
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        foreach (string normalizedHost in normalizedHosts) {
            cancellationToken.ThrowIfCancellationRequested();
            try {
                SubdomainDiscoveryEntry? entry = await QueryCrtShPostgreSqlMetadataExactAsync(
                    connection,
                    normalizedHost,
                    options,
                    logger,
                    targetedThumbprints,
                    cancellationToken).ConfigureAwait(false);
                if (entry == null || string.IsNullOrWhiteSpace(entry.Name)) {
                    continue;
                }

                MergeCtSubdomainEntry(results, entry);
            } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                throw;
            } catch (Exception ex) {
                logger?.WriteVerbose(
                    "CT metadata backfill exact PostgreSQL lookup failed for {0}: {1}",
                    normalizedHost,
                    ex.Message);
                if (connection.FullState == System.Data.ConnectionState.Broken ||
                    connection.FullState == System.Data.ConnectionState.Closed) {
                    break;
                }
            }
        }

        return results;
    }

    private static HashSet<string> BuildTargetedCtMetadataThumbprintSet(CertificateInventoryCaptureOptions? options) {
        if (options == null || options.CtMetadataTargetThumbprints.Count == 0) {
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        var thumbprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string rawThumbprint in options.CtMetadataTargetThumbprints) {
            string? normalizedThumbprint = NormalizeCtMetadataThumbprint(rawThumbprint);
            if (!string.IsNullOrWhiteSpace(normalizedThumbprint)) {
                thumbprints.Add(normalizedThumbprint!);
            }
        }

        return thumbprints;
    }

    private static async Task<SubdomainDiscoveryEntry?> QueryCrtShPostgreSqlMetadataExactAsync(
        string hostName,
        CertificateInventoryCaptureOptions options,
        InternalLogger? logger,
        CancellationToken cancellationToken) {
        if (string.IsNullOrWhiteSpace(hostName) || options == null) {
            return null;
        }

        string normalizedHost = hostName.Trim().TrimEnd('.').ToLowerInvariant();
        string connectionString = BuildCrtShPostgreSqlConnectionString(options);
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await QueryCrtShPostgreSqlMetadataExactAsync(
            connection,
            normalizedHost,
            options,
            logger,
            BuildTargetedCtMetadataThumbprintSet(options),
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task<SubdomainDiscoveryEntry?> QueryCrtShPostgreSqlMetadataExactAsync(
        NpgsqlConnection connection,
        string normalizedHost,
        CertificateInventoryCaptureOptions options,
        InternalLogger? logger,
        ISet<string>? targetedThumbprints,
        CancellationToken cancellationToken) {
        if (connection == null ||
            string.IsNullOrWhiteSpace(normalizedHost) ||
            options == null) {
            return null;
        }

        using var command = connection.CreateCommand();
        command.CommandTimeout = Math.Max(1, options.CrtShPostgreSqlCommandTimeoutSeconds);
        command.CommandText = BuildCrtShPostgreSqlExactMetadataQuery();
        command.Parameters.AddWithValue("host", normalizedHost);

        var rows = new List<CrtShPostgreSqlExactMetadataRow>();
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) {
            rows.Add(new CrtShPostgreSqlExactMetadataRow {
                CertificateDer = reader.IsDBNull(0) ? null : (byte[])reader.GetValue(0),
                EntryTimestampUtc = reader.IsDBNull(1) ? null : ReadDateTimeOffset(reader.GetValue(1)),
                CommonName = reader.IsDBNull(2) ? null : reader.GetString(2),
                IssuerName = reader.IsDBNull(3) ? null : reader.GetString(3),
                SerialNumber = reader.IsDBNull(4) ? null : reader.GetString(4),
                NotBeforeUtc = reader.IsDBNull(5) ? null : ReadDateTimeOffset(reader.GetValue(5)),
                NotAfterUtc = reader.IsDBNull(6) ? null : ReadDateTimeOffset(reader.GetValue(6)),
                CandidateNames = reader.IsDBNull(7)
                    ? Array.Empty<string>()
                    : ((string[])reader.GetValue(7))
                        .Select(static name => NormalizeCtMetadataCandidate(name, preserveWildcard: true))
                        .Where(static name => !string.IsNullOrWhiteSpace(name))
                        .Select(static name => name!)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToList()
            });
        }

        SubdomainDiscoveryEntry? entry = TryBuildExactCtMetadataEntryFromCrtShPostgreSqlRows(
            normalizedHost,
            rows,
            targetedThumbprints);
        if (entry != null) {
            logger?.WriteVerbose(
                "CT metadata backfill exact PostgreSQL lookup matched {0} row(s) for {1}.",
                rows.Count,
                normalizedHost);
        }

        return entry;
    }

    private async Task<Dictionary<string, SubdomainDiscoveryEntry>> QueryCrtShPostgreSqlMetadataByDomainAsync(
        string domain,
        IReadOnlyCollection<string> hostNames,
        CertificateInventoryCaptureOptions options,
        InternalLogger logger,
        CancellationToken cancellationToken) {
        var results = new Dictionary<string, SubdomainDiscoveryEntry>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(domain) || hostNames == null || hostNames.Count == 0 || options == null) {
            return results;
        }

        List<string> normalizedHosts = hostNames
            .Where(static host => !string.IsNullOrWhiteSpace(host))
            .Select(static host => host.Trim().TrimEnd('.').ToLowerInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (normalizedHosts.Count == 0) {
            return results;
        }

        string normalizedDomain = domain.Trim().TrimEnd('.').ToLowerInvariant();
        HashSet<string> targetedThumbprints = BuildTargetedCtMetadataThumbprintSet(options);
        string connectionString = BuildCrtShPostgreSqlConnectionString(options);
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        using var command = connection.CreateCommand();
        command.CommandTimeout = Math.Max(1, options.CrtShPostgreSqlCommandTimeoutSeconds);
        command.CommandText = BuildCrtShPostgreSqlDomainMetadataQuery();
        command.Parameters.AddWithValue("domain", normalizedDomain);
        command.Parameters.Add(new NpgsqlParameter<string[]>("hosts", NpgsqlDbType.Array | NpgsqlDbType.Text)
        {
            TypedValue = normalizedHosts.ToArray()
        });
        command.Parameters.Add(new NpgsqlParameter<string[]>("wildcardHosts", NpgsqlDbType.Array | NpgsqlDbType.Text)
        {
            TypedValue = normalizedHosts.Select(BuildWildcardCandidateHost).ToArray()
        });
        command.Parameters.AddWithValue("limit", Math.Max(32, normalizedHosts.Count * 8));

        var rows = new List<CrtShPostgreSqlExactMetadataRow>();
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) {
            rows.Add(new CrtShPostgreSqlExactMetadataRow
            {
                CertificateDer = reader.IsDBNull(0) ? null : (byte[])reader.GetValue(0),
                EntryTimestampUtc = reader.IsDBNull(1) ? null : ReadDateTimeOffset(reader.GetValue(1)),
                CommonName = reader.IsDBNull(2) ? null : reader.GetString(2),
                IssuerName = reader.IsDBNull(3) ? null : reader.GetString(3),
                SerialNumber = reader.IsDBNull(4) ? null : reader.GetString(4),
                NotBeforeUtc = reader.IsDBNull(5) ? null : ReadDateTimeOffset(reader.GetValue(5)),
                NotAfterUtc = reader.IsDBNull(6) ? null : ReadDateTimeOffset(reader.GetValue(6)),
                CandidateNames = reader.IsDBNull(7)
                    ? Array.Empty<string>()
                    : ((string[])reader.GetValue(7))
                        .Select(static name => NormalizeCtMetadataCandidate(name, preserveWildcard: true))
                        .Where(static name => !string.IsNullOrWhiteSpace(name))
                        .Select(static name => name!)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToList()
            });
        }

        foreach (string normalizedHost in normalizedHosts) {
            SubdomainDiscoveryEntry? entry = TryBuildExactCtMetadataEntryFromCrtShPostgreSqlRows(
                normalizedHost,
                rows,
                targetedThumbprints);
            if (entry == null || string.IsNullOrWhiteSpace(entry.Name)) {
                continue;
            }

            results[normalizedHost] = entry;
        }

        if (results.Count > 0) {
            logger.WriteVerbose(
                "CT metadata backfill domain PostgreSQL lookup matched {0} host(s) for {1} from {2} candidate certificate row(s).",
                results.Count,
                normalizedDomain,
                rows.Count);
        }

        return results;
    }

    internal static string BuildCrtShPostgreSqlExactMetadataQuery() {
        return
            """
            SELECT
                c.certificate,
                COALESCE(
                    (
                        SELECT MAX(ctle.entry_timestamp)
                        FROM ct_log_entry ctle
                        WHERE ctle.certificate_id = c.id
                    ),
                    NULL
                ) AS entry_timestamp,
                x509_commonName(c.certificate) AS common_name,
                x509_issuerName(c.certificate) AS issuer_name,
                encode(x509_serialNumber(c.certificate), 'hex') AS serial_number,
                x509_notBefore(c.certificate) AS not_before,
                x509_notAfter(c.certificate) AS not_after,
                ARRAY(
                    SELECT candidate_name
                    FROM (
                        SELECT x509_commonName(c.certificate) AS candidate_name
                        UNION
                        SELECT alt_name
                        FROM x509_altnames(c.certificate) AS alt_name
                    ) AS candidate_names
                    WHERE candidate_name IS NOT NULL
                    ORDER BY lower(candidate_name)
                ) AS dns_names
            FROM certificate c
            WHERE identities(c.certificate) @@ plainto_tsquery('simple', @host)
              AND (
                    lower(COALESCE(x509_commonName(c.certificate), '')) = lower(@host)
                 OR EXISTS (
                        SELECT 1
                        FROM x509_altnames(c.certificate) AS alt_name
                        WHERE lower(alt_name) = lower(@host)
                    )
                  )
            ORDER BY entry_timestamp DESC NULLS LAST,
                     x509_notBefore(c.certificate) DESC NULLS LAST
            LIMIT 16;
            """;
    }

    internal static string BuildCrtShPostgreSqlDomainMetadataQuery() {
        return
            """
            SELECT
                c.certificate,
                COALESCE(
                    (
                        SELECT MAX(ctle.entry_timestamp)
                        FROM ct_log_entry ctle
                        WHERE ctle.certificate_id = c.id
                    ),
                    NULL
                ) AS entry_timestamp,
                x509_commonName(c.certificate) AS common_name,
                x509_issuerName(c.certificate) AS issuer_name,
                encode(x509_serialNumber(c.certificate), 'hex') AS serial_number,
                x509_notBefore(c.certificate) AS not_before,
                x509_notAfter(c.certificate) AS not_after,
                ARRAY(
                    SELECT candidate_name
                    FROM (
                        SELECT x509_commonName(c.certificate) AS candidate_name
                        UNION
                        SELECT alt_name
                        FROM x509_altnames(c.certificate) AS alt_name
                    ) AS candidate_names
                    WHERE candidate_name IS NOT NULL
                    ORDER BY lower(candidate_name)
                ) AS dns_names
            FROM certificate c
            WHERE identities(c.certificate) @@ plainto_tsquery('simple', @domain)
              AND EXISTS (
                    SELECT 1
                    FROM (
                        SELECT lower(COALESCE(x509_commonName(c.certificate), '')) AS candidate_name
                        UNION
                        SELECT lower(alt_name)
                        FROM x509_altnames(c.certificate) AS alt_name
                    ) AS candidate_names
                    WHERE candidate_name = ANY(@hosts)
                       OR candidate_name = ANY(@wildcardHosts)
                )
            ORDER BY entry_timestamp DESC NULLS LAST,
                     x509_notBefore(c.certificate) DESC NULLS LAST
            LIMIT @limit;
            """;
    }

    internal static SubdomainDiscoveryEntry? TryBuildExactCtMetadataEntryFromCrtShPostgreSqlRows(
        string normalizedHost,
        IReadOnlyList<CrtShPostgreSqlExactMetadataRow>? rows,
        ISet<string>? targetedThumbprints = null) {
        if (string.IsNullOrWhiteSpace(normalizedHost) || rows == null || rows.Count == 0) {
            return null;
        }

        List<CrtShPostgreSqlExactMetadataRow> matchingRows = rows
            .Where(row => row != null &&
                          row.CandidateNames.Any(candidate => CtMetadataCandidateMatchesHost(normalizedHost, candidate)))
            .ToList();
        if (matchingRows.Count == 0) {
            return null;
        }

        var normalizedTargetedThumbprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (targetedThumbprints != null && targetedThumbprints.Count > 0) {
            foreach (string rawThumbprint in targetedThumbprints) {
                string? normalizedThumbprint = NormalizeCtMetadataThumbprint(rawThumbprint);
                if (!string.IsNullOrWhiteSpace(normalizedThumbprint)) {
                    normalizedTargetedThumbprints.Add(normalizedThumbprint!);
                }
            }
        }

        IEnumerable<CrtShPostgreSqlExactMetadataRow> candidateRows = matchingRows;
        if (normalizedTargetedThumbprints.Count > 0) {
            List<CrtShPostgreSqlExactMetadataRow> targetedRows = matchingRows
                .Where(row => DoesCrtShPostgreSqlRowMatchTargetThumbprint(row, normalizedTargetedThumbprints))
                .ToList();
            if (targetedRows.Count > 0) {
                candidateRows = targetedRows;
            }
        }

        CrtShPostgreSqlExactMetadataRow? selectedRow = candidateRows
            .OrderByDescending(static row => row.EntryTimestampUtc ?? DateTimeOffset.MinValue)
            .ThenByDescending(static row => row.NotBeforeUtc ?? DateTimeOffset.MinValue)
            .FirstOrDefault();
        if (selectedRow == null) {
            return null;
        }

        string? thumbprint = null;
        bool? isSelfSigned = null;
        bool? weakKey = null;
        bool? sha1Signature = null;
        bool? hasServerAuthentication = null;
        bool? hasClientAuthentication = null;
        bool? hasSecureEmail = null;
        string? authenticationProfile = null;
        if (selectedRow.CertificateDer != null && selectedRow.CertificateDer.Length > 0) {
            using X509Certificate2 certificate = CertificateLoaderCompat.LoadCertificate(selectedRow.CertificateDer);
            thumbprint = NormalizeCtMetadataThumbprint(certificate.Thumbprint);
            CertificateExtendedKeyUsageInfo eku = CertificateExtendedKeyUsageAnalyzer.Analyze(certificate);
            string? signatureOid = certificate.SignatureAlgorithm?.Value;
            int keySize = GetPublicKeySize(certificate);

            isSelfSigned = IsSelfSigned(certificate);
            weakKey = keySize > 0 && keySize < 2048;
            sha1Signature = IsSha1Signature(signatureOid);
            hasServerAuthentication = eku.AllowsServerAuthentication;
            hasClientAuthentication = eku.AllowsClientAuthentication;
            hasSecureEmail = eku.AllowsSecureEmail;
            authenticationProfile = string.IsNullOrWhiteSpace(eku.AuthenticationProfile)
                ? CertificateAuthenticationProfileClassifier.Classify(eku)
                : eku.AuthenticationProfile;
        }

        return new SubdomainDiscoveryEntry {
            Name = normalizedHost,
            FirstSeenUtc = selectedRow.EntryTimestampUtc,
            LastSeenUtc = selectedRow.EntryTimestampUtc,
            LatestCertificateCtEntryTimestampUtc = selectedRow.EntryTimestampUtc,
            LatestCertificateThumbprint = thumbprint,
            LatestCertificateSubject = string.IsNullOrWhiteSpace(selectedRow.CommonName) ? normalizedHost : selectedRow.CommonName,
            LatestCertificateIssuer = selectedRow.IssuerName,
            LatestCertificateSerialNumber = selectedRow.SerialNumber,
            LatestCertificateNotBeforeUtc = selectedRow.NotBeforeUtc,
            LatestCertificateNotAfterUtc = selectedRow.NotAfterUtc,
            LatestCertificateSubjectAlternativeNames = selectedRow.CandidateNames,
            LatestCertificateIsSelfSigned = isSelfSigned,
            LatestCertificateWeakKey = weakKey,
            LatestCertificateSha1Signature = sha1Signature,
            LatestCertificateHasServerAuthentication = hasServerAuthentication,
            LatestCertificateHasClientAuthentication = hasClientAuthentication,
            LatestCertificateHasSecureEmail = hasSecureEmail,
            LatestCertificateAuthenticationProfile = authenticationProfile,
            CtSources = new[] { "crt.sh-db" },
            CertificateObservationCount = rows.Count,
            ResolutionStatus = SubdomainResolutionStatus.Unknown
        };
    }

    private static bool DoesCrtShPostgreSqlRowMatchTargetThumbprint(
        CrtShPostgreSqlExactMetadataRow? row,
        ISet<string>? targetedThumbprints) {
        if (row == null ||
            targetedThumbprints == null ||
            targetedThumbprints.Count == 0 ||
            row.CertificateDer == null ||
            row.CertificateDer.Length == 0) {
            return false;
        }

        using X509Certificate2 certificate = CertificateLoaderCompat.LoadCertificate(row.CertificateDer);
        string? thumbprint = NormalizeCtMetadataThumbprint(certificate.Thumbprint);
        return !string.IsNullOrWhiteSpace(thumbprint) &&
               targetedThumbprints.Contains(thumbprint!);
    }

    private static string BuildCrtShPostgreSqlConnectionString(CertificateInventoryCaptureOptions options) {
        if (!string.IsNullOrWhiteSpace(options?.CrtShPostgreSqlConnectionString)) {
            return options!.CrtShPostgreSqlConnectionString!;
        }

        var builder = new NpgsqlConnectionStringBuilder {
            Host = "91.199.212.73",
            Port = 5432,
            Database = "certwatch",
            Username = "guest",
            SslMode = SslMode.Require,
            Timeout = Math.Max(1, options?.CrtShPostgreSqlCommandTimeoutSeconds ?? 15),
            CommandTimeout = Math.Max(1, options?.CrtShPostgreSqlCommandTimeoutSeconds ?? 15)
        };
        return builder.ConnectionString;
    }

    internal static string BuildWildcardCandidateHost(string normalizedHost) {
        if (string.IsNullOrWhiteSpace(normalizedHost)) {
            return normalizedHost ?? string.Empty;
        }

        int firstDotIndex = normalizedHost.IndexOf('.');
        int lastDotIndex = normalizedHost.LastIndexOf('.');
        return firstDotIndex <= 0 ||
               firstDotIndex >= normalizedHost.Length - 1 ||
               firstDotIndex == lastDotIndex
            ? normalizedHost
            : "*." + normalizedHost.Substring(firstDotIndex + 1);
    }

    private static DateTimeOffset? ReadDateTimeOffset(object? value) {
        return value switch {
            null => null,
            DateTimeOffset dateTimeOffset => dateTimeOffset.ToUniversalTime(),
            DateTime dateTime => new DateTimeOffset(DateTime.SpecifyKind(dateTime, DateTimeKind.Utc)),
            _ => DateTimeOffset.TryParse(
                value.ToString(),
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
                out DateTimeOffset parsed)
                ? parsed
                : (DateTimeOffset?)null
        };
    }

    private static bool IsSha1Signature(string? oid) {
        return oid == "1.2.840.113549.1.1.5" ||
               oid == "1.2.840.10040.4.3" ||
               oid == "1.3.14.3.2.29";
    }

    internal static int ResolveExactPassiveCtMetadataBackfillParallelism(
        int configuredDiscoveryParallelism,
        int configuredPassiveCtParallelism,
        int configuredCrtShPostgreSqlMaximumConcurrentRequests,
        int hostCount,
        bool usePassiveNetworkQueries) {
        int configuredParallelism = Math.Max(1, configuredDiscoveryParallelism);
        int effectiveParallelism = usePassiveNetworkQueries
            ? Math.Min(
                Math.Min(configuredParallelism, Math.Max(1, configuredPassiveCtParallelism)),
                4)
            : Math.Min(
                configuredParallelism,
                Math.Max(1, configuredCrtShPostgreSqlMaximumConcurrentRequests));
        return Math.Min(Math.Max(1, hostCount), effectiveParallelism);
    }

    private static void LogExactPassiveCtMetadataSuppression(
        List<string>? warnings,
        InternalLogger logger,
        int skippedHosts,
        string suppressionReason) {
        if (skippedHosts <= 0 || string.IsNullOrWhiteSpace(suppressionReason)) {
            return;
        }

        string warning =
            "Passive CT exact metadata backfill skipped " +
            skippedHosts.ToString(System.Globalization.CultureInfo.InvariantCulture) +
            " remaining host(s) after shared source cooldown was detected: " +
            suppressionReason;
        if (warnings != null) {
            lock (warnings) {
                warnings.Add(warning);
            }
        }
        logger.WriteVerbose("{0}", warning);
    }

    private static async Task<SubdomainDiscoveryEntry?> QueryPassiveCtMetadataExactAsync(
        string hostName,
        CertificateInventoryCaptureOptions options,
        List<string>? warnings,
        List<PassiveCtDiagnosticEntry>? passiveCtDiagnosticEntries,
        InternalLogger logger,
        PassiveCtSourceClient client,
        Func<string, CancellationToken, Task<byte[]?>>? certificateDownloadOverride,
        CancellationToken cancellationToken) {
        if (string.IsNullOrWhiteSpace(hostName)) {
            return null;
        }

        string normalizedHost = hostName.Trim().TrimEnd('.').ToLowerInvariant();
        IReadOnlyList<PassiveCtSourceClient.SourceRequest> requests = PassiveCtSourceClient.OrderRequestsBySourceHealth(
            BuildPassiveCtMetadataSourceRequests(normalizedHost));
        if (requests.Count == 0) {
            return null;
        }

        var exhaustedNoRowRequests = new List<PassiveCtSourceClient.SourceRequest>(requests.Count);
        var evaluatedSources = new List<string>(requests.Count);
        bool exactNoRowsFullyExhausted = true;
        foreach (PassiveCtSourceClient.SourceRequest request in requests) {
            PassiveCtSourceClient.QueryResult queryResult = await client.QueryAsync(
                new[] { request },
                new PassiveCtSourceClient.QueryOptions {
                    RequestTimeout = options.PassiveCtRequestTimeout,
                    RetryCount = options.PassiveCtRetryCount,
                    RetryBaseDelay = options.PassiveCtRetryBaseDelay,
                    RetryMaxDelay = options.PassiveCtRetryMaxDelay,
                    SourceCooldown = options.PassiveCtSourceCooldown,
                    CrtShMinimumSpacing = options.PassiveCtCrtShMinimumSpacing,
                    CertSpotterMinimumSpacing = options.PassiveCtCertSpotterMinimumSpacing,
                    CrtShMaximumRequestsPerRun = options.PassiveCtCrtShMaximumRequestsPerRun,
                    CertSpotterMaximumRequestsPerRun = options.PassiveCtCertSpotterMaximumRequestsPerRun,
                    QueryAllSources = false,
                    PayloadValidator = ValidatePassiveCtMetadataArrayPayload
                },
                queryOverride: null,
                logger,
                cancellationToken).ConfigureAwait(false);
            AppendPassiveCtExactQueryDiagnostics(
                normalizedHost,
                warnings,
                passiveCtDiagnosticEntries,
                queryResult);
            if (!CanPersistPassiveCtExactNoRowsDiagnostic(queryResult)) {
                exactNoRowsFullyExhausted = false;
            }
            if (queryResult.Payloads.Count == 0) {
                continue;
            }

            if (CanPersistPassiveCtExactNoRowsDiagnostic(queryResult)) {
                exhaustedNoRowRequests.Add(request);
            }

            evaluatedSources.Add(request.SourceName);
            SubdomainDiscoveryEntry? exactEntry = TryBuildExactCtMetadataEntry(normalizedHost, queryResult.Payloads);
            if (exactEntry != null) {
                exactEntry = await TryHydrateExactCtMetadataThumbprintFromCrtShCertificateAsync(
                    exactEntry,
                    queryResult.Payloads,
                    certificateDownloadOverride,
                    options.PassiveCtRequestTimeout,
                    logger,
                    cancellationToken).ConfigureAwait(false);
                return exactEntry;
            }
        }

        if (evaluatedSources.Count == 0) {
            return null;
        }

        if (exactNoRowsFullyExhausted) {
            AppendPassiveCtExactNoRowsDiagnostics(normalizedHost, exhaustedNoRowRequests, passiveCtDiagnosticEntries);
        }

        logger.WriteVerbose(
            "CT metadata backfill exact lookup returned no rows for {0} after checking source(s): {1}.",
            normalizedHost,
            string.Join(", ", evaluatedSources));
        return null;
    }

    internal static async Task<SubdomainDiscoveryEntry> TryHydrateExactCtMetadataThumbprintFromCrtShCertificateAsync(
        SubdomainDiscoveryEntry entry,
        IReadOnlyList<PassiveCtSourceClient.SourcePayload>? payloads,
        Func<string, CancellationToken, Task<byte[]?>>? certificateDownloadOverride,
        TimeSpan requestTimeout,
        InternalLogger? logger,
        CancellationToken cancellationToken) {
        if (string.IsNullOrWhiteSpace(entry.Name) ||
            !string.IsNullOrWhiteSpace(entry.LatestCertificateThumbprint) ||
            payloads == null ||
            payloads.Count == 0) {
            return entry;
        }

        string? selectedCertificateDownloadId = SelectBestCrtShCertificateDownloadId(entry, payloads);
        if (string.IsNullOrWhiteSpace(selectedCertificateDownloadId)) {
            return entry;
        }
        string certificateDownloadId = selectedCertificateDownloadId!;

        byte[]? certificateBytes = certificateDownloadOverride != null
            ? await certificateDownloadOverride(certificateDownloadId, cancellationToken).ConfigureAwait(false)
            : await DownloadCrtShCertificateDerAsync(certificateDownloadId, requestTimeout, logger, cancellationToken).ConfigureAwait(false);
        if (certificateBytes == null || certificateBytes.Length == 0) {
            return entry;
        }

        using X509Certificate2 certificate = CertificateLoaderCompat.LoadCertificate(certificateBytes);
        string? thumbprint = NormalizeCtMetadataThumbprint(certificate.Thumbprint);
        if (string.IsNullOrWhiteSpace(thumbprint)) {
            return entry;
        }

        CertificateExtendedKeyUsageInfo eku = CertificateExtendedKeyUsageAnalyzer.Analyze(certificate);
        string? signatureOid = certificate.SignatureAlgorithm?.Value;
        int keySize = GetPublicKeySize(certificate);
        bool isSelfSigned = IsSelfSigned(certificate);
        bool weakKey = keySize > 0 && keySize < 2048;
        bool sha1Signature = IsSha1Signature(signatureOid);
        bool hasServerAuthentication = eku.AllowsServerAuthentication;
        bool hasClientAuthentication = eku.AllowsClientAuthentication;
        bool hasSecureEmail = eku.AllowsSecureEmail;
        string authenticationProfile = string.IsNullOrWhiteSpace(eku.AuthenticationProfile)
            ? CertificateAuthenticationProfileClassifier.Classify(eku)
            : eku.AuthenticationProfile;

        SubdomainDiscoveryEntry hydratedEntry = CloneSubdomainEntry(entry);
        hydratedEntry = new SubdomainDiscoveryEntry {
            Name = hydratedEntry.Name,
            FirstSeenUtc = hydratedEntry.FirstSeenUtc,
            LastSeenUtc = hydratedEntry.LastSeenUtc,
            LatestCertificateCtEntryTimestampUtc = hydratedEntry.LatestCertificateCtEntryTimestampUtc,
            LatestCertificateThumbprint = thumbprint,
            LatestCertificateSubject = string.IsNullOrWhiteSpace(hydratedEntry.LatestCertificateSubject) ? certificate.Subject : hydratedEntry.LatestCertificateSubject,
            LatestCertificateIssuer = string.IsNullOrWhiteSpace(hydratedEntry.LatestCertificateIssuer) ? certificate.Issuer : hydratedEntry.LatestCertificateIssuer,
            LatestCertificateSerialNumber = string.IsNullOrWhiteSpace(hydratedEntry.LatestCertificateSerialNumber) ? certificate.SerialNumber : hydratedEntry.LatestCertificateSerialNumber,
            LatestCertificateNotBeforeUtc = hydratedEntry.LatestCertificateNotBeforeUtc ?? new DateTimeOffset(certificate.NotBefore.ToUniversalTime()),
            LatestCertificateNotAfterUtc = hydratedEntry.LatestCertificateNotAfterUtc ?? new DateTimeOffset(certificate.NotAfter.ToUniversalTime()),
            LatestCertificateSubjectAlternativeNames = hydratedEntry.LatestCertificateSubjectAlternativeNames == null ? Array.Empty<string>() : hydratedEntry.LatestCertificateSubjectAlternativeNames.ToList(),
            LatestCertificateIsSelfSigned = hydratedEntry.LatestCertificateIsSelfSigned ?? isSelfSigned,
            LatestCertificateWeakKey = hydratedEntry.LatestCertificateWeakKey ?? weakKey,
            LatestCertificateSha1Signature = hydratedEntry.LatestCertificateSha1Signature ?? sha1Signature,
            LatestCertificateHasServerAuthentication = hydratedEntry.LatestCertificateHasServerAuthentication ?? hasServerAuthentication,
            LatestCertificateHasClientAuthentication = hydratedEntry.LatestCertificateHasClientAuthentication ?? hasClientAuthentication,
            LatestCertificateHasSecureEmail = hydratedEntry.LatestCertificateHasSecureEmail ?? hasSecureEmail,
            LatestCertificateAuthenticationProfile = string.IsNullOrWhiteSpace(hydratedEntry.LatestCertificateAuthenticationProfile)
                ? authenticationProfile
                : hydratedEntry.LatestCertificateAuthenticationProfile,
            CtSources = hydratedEntry.CtSources == null ? Array.Empty<string>() : hydratedEntry.CtSources.ToList(),
            CertificateObservationCount = hydratedEntry.CertificateObservationCount,
            ResolutionStatus = hydratedEntry.ResolutionStatus,
            ARecords = hydratedEntry.ARecords == null ? Array.Empty<string>() : hydratedEntry.ARecords.ToList(),
            AaaaRecords = hydratedEntry.AaaaRecords == null ? Array.Empty<string>() : hydratedEntry.AaaaRecords.ToList(),
            SensitiveRisk = hydratedEntry.SensitiveRisk,
            SensitiveSignals = hydratedEntry.SensitiveSignals == null ? Array.Empty<string>() : hydratedEntry.SensitiveSignals.ToList(),
            AiSignals = hydratedEntry.AiSignals == null ? Array.Empty<string>() : hydratedEntry.AiSignals.ToList()
        };
        return hydratedEntry;
    }

    internal static bool CanPersistPassiveCtExactNoRowsDiagnostic(
        PassiveCtSourceClient.QueryResult? queryResult) {
        if (queryResult == null || queryResult.RetrySuggested) {
            return false;
        }

        foreach (PassiveCtDiagnosticEntry diagnostic in queryResult.Diagnostics) {
            if (diagnostic == null) {
                continue;
            }

            if (!string.IsNullOrWhiteSpace(diagnostic.State) &&
                !string.Equals(diagnostic.State, "Succeeded", StringComparison.OrdinalIgnoreCase)) {
                return false;
            }
        }

        return true;
    }

    internal static void AppendPassiveCtExactNoRowsDiagnostics(
        string normalizedHost,
        IEnumerable<PassiveCtSourceClient.SourceRequest>? exhaustedRequests,
        List<PassiveCtDiagnosticEntry>? passiveCtDiagnosticEntries) {
        if (string.IsNullOrWhiteSpace(normalizedHost) ||
            passiveCtDiagnosticEntries == null ||
            exhaustedRequests == null) {
            return;
        }

        var requests = new List<PassiveCtSourceClient.SourceRequest>();
        var seenSources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (PassiveCtSourceClient.SourceRequest request in exhaustedRequests) {
            if (request == null ||
                string.IsNullOrWhiteSpace(request.SourceName) ||
                !seenSources.Add(request.SourceName)) {
                continue;
            }

            requests.Add(request);
        }

        if (requests.Count == 0) {
            return;
        }

        lock (passiveCtDiagnosticEntries) {
            foreach (PassiveCtSourceClient.SourceRequest request in requests) {
                passiveCtDiagnosticEntries.Add(new PassiveCtDiagnosticEntry {
                    Scope = normalizedHost,
                    QueryKind = "MetadataExact",
                    SourceName = request.SourceName ?? string.Empty,
                    RequestUrl = request.Url ?? string.Empty,
                    State = "NoRows"
                });
            }
        }
    }

    private static void AppendPassiveCtExactQueryDiagnostics(
        string normalizedHost,
        List<string>? warnings,
        List<PassiveCtDiagnosticEntry>? passiveCtDiagnosticEntries,
        PassiveCtSourceClient.QueryResult queryResult) {
        if (passiveCtDiagnosticEntries != null && queryResult.Diagnostics.Count > 0) {
            lock (passiveCtDiagnosticEntries) {
                foreach (PassiveCtDiagnosticEntry diagnostic in queryResult.Diagnostics) {
                    if (diagnostic == null || string.IsNullOrWhiteSpace(diagnostic.SourceName)) {
                        continue;
                    }

                    passiveCtDiagnosticEntries.Add(new PassiveCtDiagnosticEntry {
                        Scope = normalizedHost,
                        QueryKind = "MetadataExact",
                        SourceName = diagnostic.SourceName ?? string.Empty,
                        RequestUrl = diagnostic.RequestUrl ?? string.Empty,
                        State = diagnostic.State ?? string.Empty,
                        RetrySuggested = diagnostic.RetrySuggested,
                        CooldownUntilUtc = diagnostic.CooldownUntilUtc,
                        RetryAfterSeconds = diagnostic.RetryAfterSeconds,
                        Failure = PassiveCtSourceClient.SanitizeFailureText(diagnostic.Failure)
                    });
                }
            }
        }
        if (warnings != null && queryResult.Warnings.Count > 0) {
            lock (warnings) {
                foreach (string warning in queryResult.Warnings) {
                    warnings.Add("Passive CT exact metadata for " + normalizedHost + ": " + warning);
                }
            }
        }
    }

    private static SubdomainDiscoveryEntry? TryBuildExactCtMetadataEntry(
        string normalizedHost,
        IReadOnlyList<PassiveCtSourceClient.SourcePayload> payloads) {
        if (string.IsNullOrWhiteSpace(normalizedHost) || payloads == null || payloads.Count == 0) {
            return null;
        }

        DateTimeOffset? firstSeenUtc = null;
        DateTimeOffset? lastSeenUtc = null;
        DateTimeOffset? latestCertificateEntryTimestampUtc = null;
        string? latestCertificateThumbprint = null;
        string? latestCertificateSubject = null;
        string? latestCertificateIssuer = null;
        string? latestCertificateSerialNumber = null;
        DateTimeOffset? latestCertificateNotBeforeUtc = null;
        DateTimeOffset? latestCertificateNotAfterUtc = null;
        IReadOnlyList<string> latestCertificateSubjectAlternativeNames = Array.Empty<string>();
        var ctSources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var observationCount = 0;

        foreach (PassiveCtSourceClient.SourcePayload sourcePayload in payloads) {
            if (string.IsNullOrWhiteSpace(sourcePayload.Payload)) {
                continue;
            }

            using JsonDocument document = JsonDocument.Parse(sourcePayload.Payload);
            if (document.RootElement.ValueKind != JsonValueKind.Array) {
                continue;
            }

            foreach (JsonElement item in document.RootElement.EnumerateArray()) {
                IReadOnlyList<string> candidateNames = GetCtMetadataCandidateNames(item);
                if (!candidateNames.Any(candidate =>
                        CtMetadataCandidateMatchesHost(normalizedHost, candidate))) {
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
                ctSources.Add(sourcePayload.SourceName);

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
                latestCertificateThumbprint = GetCtMetadataString(item, "sha1_fingerprint") ??
                                             GetCtMetadataString(item, "thumbprint");
                latestCertificateSubject = GetCtMetadataCommonName(item) ?? normalizedHost;
                latestCertificateIssuer = GetCtMetadataIssuerName(item);
                latestCertificateSerialNumber = GetCtMetadataString(item, "serial_number");
                latestCertificateNotBeforeUtc = ParseCtMetadataTimestamp(GetCtMetadataString(item, "not_before"));
                latestCertificateNotAfterUtc = ParseCtMetadataTimestamp(GetCtMetadataString(item, "not_after"));
                latestCertificateSubjectAlternativeNames = candidateNames;
            }
        }

        if (observationCount == 0) {
            return null;
        }

        return new SubdomainDiscoveryEntry {
            Name = normalizedHost,
            FirstSeenUtc = firstSeenUtc,
            LastSeenUtc = lastSeenUtc,
            LatestCertificateCtEntryTimestampUtc = latestCertificateEntryTimestampUtc,
            LatestCertificateThumbprint = NormalizeCtMetadataThumbprint(latestCertificateThumbprint),
            LatestCertificateSubject = latestCertificateSubject,
            LatestCertificateIssuer = latestCertificateIssuer,
            LatestCertificateSerialNumber = latestCertificateSerialNumber,
            LatestCertificateNotBeforeUtc = latestCertificateNotBeforeUtc,
            LatestCertificateNotAfterUtc = latestCertificateNotAfterUtc,
            LatestCertificateSubjectAlternativeNames = latestCertificateSubjectAlternativeNames,
            CtSources = ctSources.OrderBy(source => source, StringComparer.OrdinalIgnoreCase).ToList(),
            CertificateObservationCount = observationCount,
            ResolutionStatus = SubdomainResolutionStatus.Unknown
        };
    }

    private static string? SelectBestCrtShCertificateDownloadId(
        SubdomainDiscoveryEntry entry,
        IReadOnlyList<PassiveCtSourceClient.SourcePayload> payloads) {
        if (entry == null ||
            string.IsNullOrWhiteSpace(entry.Name) ||
            payloads == null ||
            payloads.Count == 0) {
            return null;
        }

        string normalizedHost = entry.Name.Trim().TrimEnd('.').ToLowerInvariant();
        string? normalizedSerial = NormalizeCtMetadataStringToken(entry.LatestCertificateSerialNumber);
        DateTimeOffset? latestEntryTimestampUtc = entry.LatestCertificateCtEntryTimestampUtc;
        string? selectedId = null;
        DateTimeOffset? selectedTimestampUtc = null;
        var selectedScore = int.MinValue;

        foreach (PassiveCtSourceClient.SourcePayload sourcePayload in payloads) {
            if (!string.Equals(sourcePayload.SourceName, "crt.sh", StringComparison.OrdinalIgnoreCase) ||
                string.IsNullOrWhiteSpace(sourcePayload.Payload)) {
                continue;
            }

            using JsonDocument document = JsonDocument.Parse(sourcePayload.Payload);
            if (document.RootElement.ValueKind != JsonValueKind.Array) {
                continue;
            }

            foreach (JsonElement item in document.RootElement.EnumerateArray()) {
                IReadOnlyList<string> candidateNames = GetCtMetadataCandidateNames(item);
                if (!candidateNames.Any(candidate =>
                        CtMetadataCandidateMatchesHost(normalizedHost, candidate))) {
                    continue;
                }

                string? downloadId = GetCtMetadataString(item, "id");
                if (string.IsNullOrWhiteSpace(downloadId)) {
                    continue;
                }

                DateTimeOffset? entryTimestampUtc = ParseCtMetadataTimestamp(
                    GetCtMetadataString(item, "entry_timestamp") ?? GetCtMetadataString(item, "not_before"));
                string? candidateSerial = NormalizeCtMetadataStringToken(GetCtMetadataString(item, "serial_number"));

                var score = 0;
                if (entryTimestampUtc.HasValue && latestEntryTimestampUtc.HasValue && entryTimestampUtc.Value == latestEntryTimestampUtc.Value) {
                    score += 100;
                }

                if (!string.IsNullOrWhiteSpace(normalizedSerial) &&
                    string.Equals(candidateSerial, normalizedSerial, StringComparison.OrdinalIgnoreCase)) {
                    score += 10;
                }

                if (score > selectedScore ||
                    (score == selectedScore &&
                     entryTimestampUtc.HasValue &&
                     (!selectedTimestampUtc.HasValue || entryTimestampUtc.Value > selectedTimestampUtc.Value))) {
                    selectedScore = score;
                    selectedTimestampUtc = entryTimestampUtc;
                    selectedId = downloadId;
                }
            }
        }

        return selectedId;
    }

    private static async Task<byte[]?> DownloadCrtShCertificateDerAsync(
        string certificateDownloadId,
        TimeSpan requestTimeout,
        InternalLogger? logger,
        CancellationToken cancellationToken) {
        if (string.IsNullOrWhiteSpace(certificateDownloadId)) {
            return null;
        }

        using var client = new HttpClient {
            Timeout = requestTimeout > TimeSpan.Zero ? requestTimeout : TimeSpan.FromSeconds(15)
        };

        using HttpResponseMessage response = await client.GetAsync(
            "https://crt.sh/?d=" + Uri.EscapeDataString(certificateDownloadId),
            cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) {
            logger?.WriteVerbose(
                "CT metadata backfill exact certificate download failed for crt.sh id {0}: HTTP {1}.",
                certificateDownloadId,
                (int)response.StatusCode);
            return null;
        }

        return await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
    }

    private static string? NormalizeCtMetadataStringToken(string? value) {
        return string.IsNullOrWhiteSpace(value)
            ? null
            : value!.Trim();
    }

    internal static IReadOnlyList<PassiveCtSourceClient.SourceRequest> BuildPassiveCtMetadataSourceRequests(string normalizedHost) {
        var requests = new List<PassiveCtSourceClient.SourceRequest>(2);
        requests.Add(new PassiveCtSourceClient.SourceRequest {
            SourceName = "certspotter",
            Url = "https://api.certspotter.com/v1/issuances?domain=" + Uri.EscapeDataString(normalizedHost) + "&match_wildcards=true&expand=dns_names"
        });
        requests.Add(new PassiveCtSourceClient.SourceRequest {
            SourceName = "crt.sh",
            Url = "https://crt.sh/?q=" + Uri.EscapeDataString(normalizedHost) + "&output=json"
        });
        return requests;
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

                string? value = NormalizeCtMetadataCandidate(dnsName.GetString(), preserveWildcard: true);
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
                string? normalized = NormalizeCtMetadataCandidate(value, preserveWildcard: true);
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

                string? normalized = NormalizeCtMetadataCandidate(dnsName.GetString(), preserveWildcard: true);
                if (!string.IsNullOrWhiteSpace(normalized)) {
                    names.Add(normalized!);
                }
            }
        }

        return names.Count == 0
            ? Array.Empty<string>()
            : names.OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static bool CtMetadataCandidateMatchesHost(string normalizedHost, string? candidateName) {
        if (string.IsNullOrWhiteSpace(normalizedHost) || string.IsNullOrWhiteSpace(candidateName)) {
            return false;
        }

        string normalizedCandidate = candidateName!.Trim().TrimEnd('.').ToLowerInvariant();
        if (string.Equals(normalizedCandidate, normalizedHost, StringComparison.OrdinalIgnoreCase)) {
            return true;
        }

        if (!normalizedCandidate.StartsWith("*.", StringComparison.Ordinal)) {
            return false;
        }

        string suffix = normalizedCandidate.Substring(2);
        if (string.IsNullOrWhiteSpace(suffix) ||
            normalizedHost.Length <= suffix.Length + 1 ||
            !normalizedHost.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase)) {
            return false;
        }

        string wildcardLabel = normalizedHost.Substring(0, normalizedHost.Length - suffix.Length - 1);
        return wildcardLabel.Length > 0 && wildcardLabel.IndexOf('.') < 0;
    }

    private static string? NormalizeCtMetadataCandidate(string? value, bool preserveWildcard = false) {
        if (string.IsNullOrWhiteSpace(value)) {
            return null;
        }

        string normalized = value!.Trim().TrimEnd('.').ToLowerInvariant();
        while (!preserveWildcard && normalized.StartsWith("*.", StringComparison.Ordinal)) {
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

    private static string? NormalizeCtMetadataThumbprint(string? value) {
        if (string.IsNullOrWhiteSpace(value)) {
            return null;
        }

        return value!.Trim().Replace(":", string.Empty).ToUpperInvariant();
    }

    private static string? ValidatePassiveCtMetadataArrayPayload(string payload) {
        if (string.IsNullOrWhiteSpace(payload)) {
            return "response payload was empty.";
        }

        try {
            using var document = JsonDocument.Parse(payload);
            return document.RootElement.ValueKind == JsonValueKind.Array
                ? null
                : "response root element must be an array.";
        } catch (JsonException ex) {
            return ex.Message;
        }
    }
}
