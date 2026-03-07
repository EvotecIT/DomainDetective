using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective {
    /// <summary>
    /// Summary view over persisted certificate inventory snapshots.
    /// </summary>
    public sealed class CertificateInventorySummary {
        public int SnapshotCount { get; set; }
        public int SampleCount { get; set; }
        public int UniqueEndpointCount { get; set; }
        public int ExpiredEndpointCount { get; set; }
        public int ExpiringSoonEndpointCount { get; set; }
        public int MissingServerAuthEndpointCount { get; set; }
        public int ClientAuthEndpointCount { get; set; }
        public int SecureEmailEndpointCount { get; set; }
        public int SelfSignedEndpointCount { get; set; }
        public int IncompleteChainEndpointCount { get; set; }
        public int CtTemplateErrorEndpointCount { get; set; }
        public Dictionary<string, int> ServiceCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> IssuerCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> RootIssuerCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> AuthenticationProfileCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> ChainSourceCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> CtSourceCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> CtTemplateErrorCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public List<CertificateExpiringEndpoint> ExpiringSoon { get; set; } = new();
    }

    /// <summary>
    /// Minimal endpoint row for expiring-certificate reports.
    /// </summary>
    public sealed class CertificateExpiringEndpoint {
        public string Host { get; set; } = string.Empty;
        public int Port { get; set; }
        public string Service { get; set; } = string.Empty;
        public DateTimeOffset? NotAfterUtc { get; set; }
        public int DaysToExpire { get; set; }
        public string Issuer { get; set; } = string.Empty;
    }

    /// <summary>
    /// Performs aggregation and summarization over certificate inventory snapshots.
    /// </summary>
    public static class CertificateInventoryAnalyzer {
        private sealed class LatestEntryState {
            public DateTimeOffset CapturedAtUtc { get; init; }
            public CertificateInventoryEntry Entry { get; init; } = null!;
        }

        public static CertificateInventorySummary BuildSummary(
            IEnumerable<CertificateInventorySnapshot>? snapshots,
            int expiringWithinDays = 30,
            int maxExpiringEndpoints = 200) {
            var summary = new CertificateInventorySummary();
            var latestByEndpoint = new Dictionary<string, LatestEntryState>(StringComparer.OrdinalIgnoreCase);
            foreach (var snapshot in snapshots ?? Array.Empty<CertificateInventorySnapshot>()) {
                if (snapshot == null) {
                    continue;
                }

                summary.SnapshotCount++;
                IEnumerable<CertificateInventoryEntry> entries;
                if (snapshot.Entries != null) {
                    entries = snapshot.Entries;
                } else {
                    entries = Array.Empty<CertificateInventoryEntry>();
                }
                foreach (var entry in entries) {
                    if (entry == null) {
                        continue;
                    }

                    summary.SampleCount++;
                    var endpointKey = BuildEndpointKey(entry);
                    var state = new LatestEntryState {
                        CapturedAtUtc = snapshot.CapturedAtUtc,
                        Entry = entry
                    };
                    if (!latestByEndpoint.TryGetValue(endpointKey, out var current) || current.CapturedAtUtc <= state.CapturedAtUtc) {
                        latestByEndpoint[endpointKey] = state;
                    }
                }
            }

            summary.UniqueEndpointCount = latestByEndpoint.Count;
            var now = DateTimeOffset.UtcNow;
            var expiringThresholdUtc = now.AddDays(Math.Max(0, expiringWithinDays));
            foreach (var latest in latestByEndpoint.Values) {
                var entry = latest.Entry;
                var service = string.IsNullOrWhiteSpace(entry.Service) ? CertificateServiceClassifier.GuessService(entry.Scheme ?? "https", entry.Port) : entry.Service;
                Increment(summary.ServiceCounts, service);

                var issuer = PickIssuer(entry);
                Increment(summary.IssuerCounts, issuer);
                Increment(summary.AuthenticationProfileCounts, CertificateInventoryEntryHelpers.ResolveAuthenticationProfile(entry));
                Increment(summary.ChainSourceCounts, CertificateInventoryEntryHelpers.PickChainSource(entry));
                IncrementCtSources(summary.CtSourceCounts, entry);
                if (IncrementCtTemplateErrors(summary.CtTemplateErrorCounts, entry)) {
                    summary.CtTemplateErrorEndpointCount++;
                }

                if (!entry.AllowsServerAuthentication) {
                    summary.MissingServerAuthEndpointCount++;
                }
                if (entry.AllowsClientAuthentication) {
                    summary.ClientAuthEndpointCount++;
                }
                if (entry.AllowsSecureEmail) {
                    summary.SecureEmailEndpointCount++;
                }
                if (entry.IsSelfSigned) {
                    summary.SelfSignedEndpointCount++;
                }
                if (!entry.ChainComplete && entry.IsReachable && !entry.IsSelfSigned) {
                    summary.IncompleteChainEndpointCount++;
                }

                var rootIssuer = PickRootIssuer(entry);
                Increment(summary.RootIssuerCounts, rootIssuer);

                if (!entry.NotAfterUtc.HasValue) {
                    continue;
                }

                if (entry.NotAfterUtc <= now) {
                    summary.ExpiredEndpointCount++;
                    continue;
                }
                if (entry.NotAfterUtc > expiringThresholdUtc) {
                    continue;
                }

                summary.ExpiringSoonEndpointCount++;
                summary.ExpiringSoon.Add(new CertificateExpiringEndpoint {
                    Host = entry.ResolvedHost ?? entry.Host,
                    Port = entry.Port,
                    Service = service,
                    NotAfterUtc = entry.NotAfterUtc,
                    DaysToExpire = Math.Max(0, (int)(entry.NotAfterUtc.Value - now).TotalDays),
                    Issuer = issuer
                });
            }

            summary.ExpiringSoon = summary.ExpiringSoon
                .OrderBy(x => x.NotAfterUtc ?? DateTimeOffset.MaxValue)
                .ThenBy(x => x.Host, StringComparer.OrdinalIgnoreCase)
                .Take(Math.Max(0, maxExpiringEndpoints))
                .ToList();
            return summary;
        }

        private static void Increment(Dictionary<string, int> counters, string key) {
            if (string.IsNullOrWhiteSpace(key)) {
                key = "Unknown";
            }

            counters[key] = counters.TryGetValue(key, out var count) ? count + 1 : 1;
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

        private static string BuildEndpointKey(CertificateInventoryEntry entry) {
            return CertificateInventoryEndpointKey.Build(entry);
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

        private static void IncrementCtSources(Dictionary<string, int> counters, CertificateInventoryEntry entry) {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (entry.CtDiscoverySources != null) {
                foreach (var source in entry.CtDiscoverySources) {
                    if (string.IsNullOrWhiteSpace(source)) {
                        continue;
                    }

                    var normalized = source.Trim();
                    if (!seen.Add(normalized)) {
                        continue;
                    }

                    Increment(counters, normalized);
                }
            }

            if (seen.Count == 0) {
                Increment(counters, "none");
            }
        }

        private static bool IncrementCtTemplateErrors(Dictionary<string, int> counters, CertificateInventoryEntry entry) {
            var hadErrors = false;
            foreach (var error in CertificateInventoryEntryHelpers.EnumerateCtTemplateFormatErrors(entry)) {
                hadErrors = true;
                Increment(counters, ExtractCtTemplateErrorCategory(error));
            }

            return hadErrors;
        }

        private static string ExtractCtTemplateErrorCategory(string error) {
            var separatorIndex = error.IndexOf(':');
            if (separatorIndex <= 0) {
                return "unknown";
            }

            var category = error.Substring(0, separatorIndex).Trim();
            return string.IsNullOrWhiteSpace(category) ? "unknown" : category;
        }
    }
}
