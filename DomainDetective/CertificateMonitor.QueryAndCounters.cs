using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;
using PeriodicTimer = System.Threading.PeriodicTimer;

namespace DomainDetective {
    public partial class CertificateMonitor {
        /// <summary>Queries persisted inventory entries using structured filters.</summary>
        /// <param name="query">Query options.</param>
        public CertificateInventoryQueryResult QueryInventoryEntries(CertificateInventoryQuery? query = null) {
            var effectiveQuery = query ?? new CertificateInventoryQuery();
            var result = new CertificateInventoryQueryResult();
            var maxResults = Math.Max(0, effectiveQuery.MaxResults);
            var matchedEndpointKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var latestOnly = effectiveQuery.LatestPerEndpointOnly;
            var observedEndpointKeys = latestOnly
                ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                : null;
            var snapshots = LoadInventorySnapshots(effectiveQuery.SinceUtc)
                .OrderByDescending(snapshot => snapshot.CapturedAtUtc)
                .ToList();
            result.LoadedSnapshotCount = snapshots.Count;
            var now = DateTimeOffset.UtcNow;
            foreach (var snapshot in snapshots) {
                if (effectiveQuery.UntilUtc.HasValue && snapshot.CapturedAtUtc > effectiveQuery.UntilUtc.Value) {
                    result.SkippedSnapshotCountByUntilUtc++;
                    continue;
                }

                result.ScannedSnapshotCount++;
                foreach (var entry in snapshot.Entries) {
                    result.ScannedEntryCount++;
                    string? endpointKey = null;
                    if (latestOnly) {
                        var latestObservedEndpointKeys = observedEndpointKeys!;
                        endpointKey = BuildEndpointKey(entry);
                        if (!latestObservedEndpointKeys.Add(endpointKey)) {
                            result.SkippedByLatestPerEndpointCount++;
                            continue;
                        }
                    }

                    result.EvaluatedEntryCount++;
                    if (!MatchesQuery(entry, effectiveQuery, now)) {
                        result.ExcludedByFiltersCount++;
                        continue;
                    }

                    result.MatchedEntryCount++;
                    if (endpointKey == null) {
                        endpointKey = BuildEndpointKey(entry);
                    }
                    matchedEndpointKeys.Add(endpointKey);
                    IncrementMatchedBreakdown(result, entry);
                    if (result.Entries.Count >= maxResults) {
                        result.Truncated = true;
                        continue;
                    }

                    result.Entries.Add(new CertificateInventoryObservedEntry {
                        CapturedAtUtc = snapshot.CapturedAtUtc,
                        Entry = entry
                    });
                }
            }

            result.MatchedUniqueEndpointCount = matchedEndpointKeys.Count;
            result.EntriesTruncatedByMaxResults = result.MatchedEntryCount - result.Entries.Count;
            return result;
        }

        /// <summary>Queries persisted native CT ingestion diagnostics captured alongside inventory snapshots.</summary>
        /// <param name="query">Native CT diagnostics query options.</param>
        public CertificateInventoryNativeCtDiagnosticsResult QueryInventoryNativeCtDiagnostics(CertificateInventoryNativeCtDiagnosticsQuery? query = null) {
            var effectiveQuery = query ?? new CertificateInventoryNativeCtDiagnosticsQuery();
            var snapshots = LoadInventorySnapshots(effectiveQuery.SinceUtc);
            return CertificateInventoryNativeCtDiagnosticsAnalyzer.Query(snapshots, effectiveQuery);
        }

        /// <summary>Builds CT diagnostics health timeline from persisted inventory snapshots.</summary>
        /// <param name="query">Health query options including thresholds and snapshot window.</param>
        public CertificateInventoryNativeCtDiagnosticsHealthSummary BuildInventoryNativeCtDiagnosticsHealth(
            CertificateInventoryNativeCtDiagnosticsHealthQuery? query = null) {
            var effectiveQuery = query ?? new CertificateInventoryNativeCtDiagnosticsHealthQuery();
            var snapshots = LoadInventorySnapshots(effectiveQuery.SinceUtc);
            return CertificateInventoryNativeCtDiagnosticsHealthAnalyzer.Build(snapshots, effectiveQuery);
        }

        private static bool MatchesQuery(CertificateInventoryEntry entry, CertificateInventoryQuery query, DateTimeOffset now) {
            var hostContains = query.HostContains;
            if (!string.IsNullOrWhiteSpace(hostContains)) {
                var hostNeedle = hostContains!.Trim();
                var hostHaystack = entry.ResolvedHost ?? entry.Host;
                if (hostHaystack.IndexOf(hostNeedle, StringComparison.OrdinalIgnoreCase) < 0) {
                    return false;
                }
            }

            var subjectContains = query.SubjectContains;
            if (!string.IsNullOrWhiteSpace(subjectContains)) {
                var subjectNeedle = subjectContains!.Trim();
                var subjectHaystack = entry.CertificateSubject ?? string.Empty;
                if (subjectHaystack.IndexOf(subjectNeedle, StringComparison.OrdinalIgnoreCase) < 0) {
                    return false;
                }
            }

            var sanContains = query.SanContains;
            if (!string.IsNullOrWhiteSpace(sanContains)) {
                var sanNeedle = sanContains!.Trim();
                var hasMatch = entry.SubjectAlternativeNames != null &&
                               entry.SubjectAlternativeNames.Any(san => !string.IsNullOrWhiteSpace(san) &&
                                                                        san.IndexOf(sanNeedle, StringComparison.OrdinalIgnoreCase) >= 0);
                if (!hasMatch) {
                    return false;
                }
            }

            var serviceEquals = query.ServiceEquals;
            if (!string.IsNullOrWhiteSpace(serviceEquals)) {
                var expectedService = serviceEquals!.Trim();
                var actualService = string.IsNullOrWhiteSpace(entry.Service)
                    ? CertificateServiceClassifier.GuessService(entry.Scheme ?? "https", entry.Port)
                    : entry.Service ?? string.Empty;
                if (!actualService.Equals(expectedService, StringComparison.OrdinalIgnoreCase)) {
                    return false;
                }
            }

            var issuerContains = query.IssuerContains;
            if (!string.IsNullOrWhiteSpace(issuerContains)) {
                var issuerNeedle = issuerContains!.Trim();
                var issuerHaystack = entry.CertificateIssuerNormalized ?? entry.CertificateIssuerOrganization ?? entry.CertificateIssuer ?? string.Empty;
                if (issuerHaystack.IndexOf(issuerNeedle, StringComparison.OrdinalIgnoreCase) < 0) {
                    return false;
                }
            }

            var authorityFamilyEquals = query.AuthorityFamilyEquals;
            if (!string.IsNullOrWhiteSpace(authorityFamilyEquals)) {
                var expectedFamily = authorityFamilyEquals!.Trim();
                var actualFamily = entry.CertificateAuthorityFamily ?? string.Empty;
                if (!actualFamily.Equals(expectedFamily, StringComparison.OrdinalIgnoreCase)) {
                    return false;
                }
            }

            var rootContains = query.RootContains;
            if (!string.IsNullOrWhiteSpace(rootContains)) {
                var rootNeedle = rootContains!.Trim();
                var rootHaystack = entry.CertificateRootIssuerNormalized ??
                                   entry.CertificateRootIssuerOrganization ??
                                   entry.CertificateRootIssuer ??
                                   entry.CertificateRootSubject ??
                                   string.Empty;
                if (rootHaystack.IndexOf(rootNeedle, StringComparison.OrdinalIgnoreCase) < 0) {
                    return false;
                }
            }

            var rootAuthorityFamilyEquals = query.RootAuthorityFamilyEquals;
            if (!string.IsNullOrWhiteSpace(rootAuthorityFamilyEquals)) {
                var expectedRootFamily = rootAuthorityFamilyEquals!.Trim();
                var actualRootFamily = entry.CertificateRootAuthorityFamily ?? string.Empty;
                if (!actualRootFamily.Equals(expectedRootFamily, StringComparison.OrdinalIgnoreCase)) {
                    return false;
                }
            }

            var ctSourceContains = query.CtSourceContains;
            if (!string.IsNullOrWhiteSpace(ctSourceContains)) {
                var ctNeedle = ctSourceContains!.Trim();
                var hasCtMatch = entry.CtDiscoverySources != null &&
                                 entry.CtDiscoverySources.Any(source =>
                                     !string.IsNullOrWhiteSpace(source) &&
                                     source.IndexOf(ctNeedle, StringComparison.OrdinalIgnoreCase) >= 0);
                if (!hasCtMatch) {
                    return false;
                }
            }

            var ctTemplateErrorContains = query.CtTemplateErrorContains;
            if (!string.IsNullOrWhiteSpace(ctTemplateErrorContains)) {
                var ctTemplateErrorNeedle = ctTemplateErrorContains!.Trim();
                var hasTemplateErrorMatch = CertificateInventoryEntryHelpers.EnumerateCtTemplateFormatErrors(entry).Any(error =>
                    error.IndexOf(ctTemplateErrorNeedle, StringComparison.OrdinalIgnoreCase) >= 0);
                if (!hasTemplateErrorMatch) {
                    return false;
                }
            }

            var chainSourceContains = query.ChainSourceContains;
            if (!string.IsNullOrWhiteSpace(chainSourceContains)) {
                var chainNeedle = chainSourceContains!.Trim();
                var hasChainSourceMatch = CertificateInventoryEntryHelpers.EnumerateChainSources(entry).Any(source =>
                    source.IndexOf(chainNeedle, StringComparison.OrdinalIgnoreCase) >= 0);
                if (!hasChainSourceMatch) {
                    return false;
                }
            }

            var thumbprintEquals = query.ThumbprintEquals;
            if (!string.IsNullOrWhiteSpace(thumbprintEquals)) {
                var expectedThumbprint = NormalizeHexIdentifier(thumbprintEquals);
                var actualThumbprint = NormalizeHexIdentifier(entry.CertificateThumbprint);
                if (expectedThumbprint.Length == 0 || !actualThumbprint.Equals(expectedThumbprint, StringComparison.OrdinalIgnoreCase)) {
                    return false;
                }
            }

            var rootThumbprintEquals = query.RootThumbprintEquals;
            if (!string.IsNullOrWhiteSpace(rootThumbprintEquals)) {
                var expectedRootThumbprint = NormalizeHexIdentifier(rootThumbprintEquals);
                var actualRootThumbprint = NormalizeHexIdentifier(entry.CertificateRootThumbprint);
                if (expectedRootThumbprint.Length == 0 || !actualRootThumbprint.Equals(expectedRootThumbprint, StringComparison.OrdinalIgnoreCase)) {
                    return false;
                }
            }

            var serialNumberEquals = query.SerialNumberEquals;
            if (!string.IsNullOrWhiteSpace(serialNumberEquals)) {
                var expectedSerialNumber = NormalizeHexIdentifier(serialNumberEquals);
                var actualSerialNumber = NormalizeHexIdentifier(entry.CertificateSerialNumber);
                if (expectedSerialNumber.Length == 0 || !actualSerialNumber.Equals(expectedSerialNumber, StringComparison.OrdinalIgnoreCase)) {
                    return false;
                }
            }

            if (query.KnownAuthorityOnly.HasValue && query.KnownAuthorityOnly.Value != entry.IsKnownCertificateAuthority) {
                return false;
            }

            if (query.KnownRootAuthorityOnly.HasValue && query.KnownRootAuthorityOnly.Value != entry.IsKnownRootCertificateAuthority) {
                return false;
            }

            if (query.ValidOnly.HasValue && query.ValidOnly.Value != entry.Valid) {
                return false;
            }

            if (query.ExpiredOnly.HasValue) {
                var isExpired = entry.NotAfterUtc.HasValue ? entry.NotAfterUtc.Value <= now : entry.Expired;
                if (query.ExpiredOnly.Value != isExpired) {
                    return false;
                }
            }

            if (query.ChainCompleteOnly.HasValue && query.ChainCompleteOnly.Value != entry.ChainComplete) {
                return false;
            }

            if (query.HostnameMatchOnly.HasValue && query.HostnameMatchOnly.Value != entry.HostnameMatch) {
                return false;
            }

            if (query.SelfSignedOnly.HasValue && query.SelfSignedOnly.Value != entry.IsSelfSigned) {
                return false;
            }

            if (query.ReachableOnly.HasValue && query.ReachableOnly.Value != entry.IsReachable) {
                return false;
            }

            if (query.PresentInCtOnly.HasValue && query.PresentInCtOnly.Value != entry.PresentInCtLogs) {
                return false;
            }

            if (query.AllowsServerAuthOnly.HasValue && query.AllowsServerAuthOnly.Value != entry.AllowsServerAuthentication) {
                return false;
            }

            if (query.AllowsClientAuthOnly.HasValue && query.AllowsClientAuthOnly.Value != entry.AllowsClientAuthentication) {
                return false;
            }

            if (query.AllowsSecureEmailOnly.HasValue && query.AllowsSecureEmailOnly.Value != entry.AllowsSecureEmail) {
                return false;
            }

            if (query.WeakKeyOnly.HasValue && query.WeakKeyOnly.Value != entry.WeakKey) {
                return false;
            }

            if (query.Sha1SignatureOnly.HasValue && query.Sha1SignatureOnly.Value != entry.Sha1Signature) {
                return false;
            }

            if (query.NotYetValidOnly.HasValue) {
                var isNotYetValid = entry.NotBeforeUtc.HasValue && entry.NotBeforeUtc.Value > now;
                if (query.NotYetValidOnly.Value != isNotYetValid) {
                    return false;
                }
            }

            var authenticationProfileEquals = query.AuthenticationProfileEquals;
            if (!string.IsNullOrWhiteSpace(authenticationProfileEquals)) {
                var expectedProfile = authenticationProfileEquals!.Trim();
                var actualProfile = CertificateInventoryEntryHelpers.ResolveAuthenticationProfile(entry);
                if (!actualProfile.Equals(expectedProfile, StringComparison.OrdinalIgnoreCase)) {
                    return false;
                }
            }

            if (query.ExpiringWithinDays.HasValue) {
                if (!entry.NotAfterUtc.HasValue) {
                    return false;
                }

                var threshold = now.AddDays(Math.Max(0, query.ExpiringWithinDays.Value));
                if (entry.NotAfterUtc.Value > threshold || entry.NotAfterUtc.Value <= now) {
                    return false;
                }
            }

            return true;
        }

        private static string NormalizeHexIdentifier(string? value) {
            if (string.IsNullOrWhiteSpace(value)) {
                return string.Empty;
            }

            var chars = value.Where(c => !char.IsWhiteSpace(c) && c != ':').ToArray();
            return new string(chars).Trim().ToUpperInvariant();
        }

        private static void IncrementMatchedBreakdown(CertificateInventoryQueryResult result, CertificateInventoryEntry entry) {
            var service = string.IsNullOrWhiteSpace(entry.Service)
                ? CertificateServiceClassifier.GuessService(entry.Scheme ?? "https", entry.Port)
                : entry.Service!;
            IncrementCounter(result.MatchedServiceCounts, service);
            IncrementCounter(result.MatchedIssuerCounts, PickIssuer(entry));
            IncrementCounter(result.MatchedRootIssuerCounts, PickRootIssuer(entry));
            IncrementCounter(result.MatchedAuthenticationProfileCounts, CertificateInventoryEntryHelpers.ResolveAuthenticationProfile(entry));
            IncrementCounter(result.MatchedChainSourceCounts, CertificateInventoryEntryHelpers.PickChainSource(entry));
            IncrementCtSources(result.MatchedCtSourceCounts, entry);
            IncrementCtTemplateErrorCategories(result.MatchedCtTemplateErrorCounts, entry);
        }

        private static string BuildEndpointKey(CertificateInventoryEntry entry) {
            return CertificateInventoryEndpointKey.Build(entry);
        }

        private static string PickIssuer(CertificateInventoryEntry entry) {
            if (!string.IsNullOrWhiteSpace(entry.CertificateIssuerNormalized)) {
                return entry.CertificateIssuerNormalized!;
            }
            if (!string.IsNullOrWhiteSpace(entry.CertificateIssuerOrganization)) {
                return entry.CertificateIssuerOrganization!;
            }
            if (!string.IsNullOrWhiteSpace(entry.CertificateIssuer)) {
                return CertificateIssuerClassifier.Classify(entry.CertificateIssuer).NormalizedName;
            }
            return "Unknown";
        }

        private static string PickRootIssuer(CertificateInventoryEntry entry) {
            if (!string.IsNullOrWhiteSpace(entry.CertificateRootIssuerNormalized)) {
                return entry.CertificateRootIssuerNormalized!;
            }
            if (!string.IsNullOrWhiteSpace(entry.CertificateRootIssuerOrganization)) {
                return entry.CertificateRootIssuerOrganization!;
            }
            if (!string.IsNullOrWhiteSpace(entry.CertificateRootIssuer)) {
                return CertificateIssuerClassifier.Classify(entry.CertificateRootIssuer).NormalizedName;
            }
            return "Unknown";
        }

        private static void IncrementCounter(Dictionary<string, int> counters, string key) {
            if (string.IsNullOrWhiteSpace(key)) {
                key = "Unknown";
            }

            counters[key] = counters.TryGetValue(key, out var count) ? count + 1 : 1;
        }

        private static void IncrementCtSources(Dictionary<string, int> counters, CertificateInventoryEntry entry) {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (entry.CtDiscoverySources != null) {
                foreach (var source in entry.CtDiscoverySources) {
                    if (string.IsNullOrWhiteSpace(source)) {
                        continue;
                    }

                    var normalized = source.Trim();
                    if (seen.Add(normalized)) {
                        IncrementCounter(counters, normalized);
                    }
                }
            }

            if (seen.Count == 0) {
                IncrementCounter(counters, "none");
            }
        }

        private static void IncrementCtTemplateErrorCategories(Dictionary<string, int> counters, CertificateInventoryEntry entry) {
            foreach (var error in CertificateInventoryEntryHelpers.EnumerateCtTemplateFormatErrors(entry)) {
                IncrementCounter(counters, ExtractCtTemplateErrorCategory(error));
            }
        }

        private static string ExtractCtTemplateErrorCategory(string error) {
            if (string.IsNullOrWhiteSpace(error)) {
                return "Unknown";
            }

            var separatorIndex = error.IndexOf(':');
            if (separatorIndex <= 0) {
                return "Unknown";
            }

            var category = error.Substring(0, separatorIndex).Trim();
            return string.IsNullOrWhiteSpace(category) ? "Unknown" : category;
        }

        /// <summary>Disposes timer resources.</summary>
        public void Dispose() {
            Stop();
        }
    }
}
