using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace DomainDetective {
    /// <summary>
    /// Certificate reuse summary over persisted certificate inventory snapshots.
    /// </summary>
    public sealed class CertificateInventoryReuseSummary {
        /// <summary>Gets or sets the snapshot count value.</summary>
        public int SnapshotCount { get; set; }
        /// <summary>Gets or sets the endpoint count value.</summary>
        public int EndpointCount { get; set; }
        /// <summary>Gets or sets the certificate count value.</summary>
        public int CertificateCount { get; set; }
        /// <summary>Gets or sets the multi endpoint certificate count value.</summary>
        public int MultiEndpointCertificateCount { get; set; }
        /// <summary>Gets or sets the cross service certificate count value.</summary>
        public int CrossServiceCertificateCount { get; set; }
        /// <summary>Gets or sets the wildcard certificate count value.</summary>
        public int WildcardCertificateCount { get; set; }
        /// <summary>Gets or sets the certificates value.</summary>
        public List<CertificateInventoryCertificateReuse> Certificates { get; set; } = new();
    }

    /// <summary>
    /// Reuse details for one certificate identity.
    /// </summary>
    public sealed class CertificateInventoryCertificateReuse {
        /// <summary>Gets or sets the certificate id value.</summary>
        public string CertificateId { get; set; } = string.Empty;
        /// <summary>Gets or sets the thumbprint value.</summary>
        public string? Thumbprint { get; set; }
        /// <summary>Gets or sets the subject value.</summary>
        public string Subject { get; set; } = string.Empty;
        /// <summary>Gets or sets the issuer value.</summary>
        public string Issuer { get; set; } = string.Empty;
        /// <summary>Gets or sets the root issuer value.</summary>
        public string RootIssuer { get; set; } = string.Empty;
        /// <summary>Gets or sets the not after utc value.</summary>
        public DateTimeOffset? NotAfterUtc { get; set; }
        /// <summary>Gets or sets the is known certificate authority value.</summary>
        public bool IsKnownCertificateAuthority { get; set; }
        /// <summary>Gets or sets the has wildcard san value.</summary>
        public bool HasWildcardSan { get; set; }
        /// <summary>Gets or sets the allows server authentication value.</summary>
        public bool AllowsServerAuthentication { get; set; }
        /// <summary>Gets or sets the allows client authentication value.</summary>
        public bool AllowsClientAuthentication { get; set; }
        /// <summary>Gets or sets the endpoint count value.</summary>
        public int EndpointCount { get; set; }
        /// <summary>Gets or sets the distinct service count value.</summary>
        public int DistinctServiceCount { get; set; }
        /// <summary>Gets or sets the distinct port count value.</summary>
        public int DistinctPortCount { get; set; }
        /// <summary>Gets or sets the endpoints value.</summary>
        public List<CertificateInventoryEndpointReference> Endpoints { get; set; } = new();
    }

    /// <summary>
    /// Endpoint reference for certificate reuse reports.
    /// </summary>
    public sealed class CertificateInventoryEndpointReference {
        /// <summary>Gets or sets the host value.</summary>
        public string Host { get; set; } = string.Empty;
        /// <summary>Gets or sets the port value.</summary>
        public int Port { get; set; }
        /// <summary>Gets or sets the service value.</summary>
        public string Service { get; set; } = string.Empty;
        /// <summary>Gets or sets the last observed utc value.</summary>
        public DateTimeOffset LastObservedUtc { get; set; }
    }

    /// <summary>
    /// Computes certificate reuse across latest endpoint observations.
    /// </summary>
    public static class CertificateInventoryReuseAnalyzer {
        private sealed class LatestEntryState {
            public DateTimeOffset CapturedAtUtc { get; init; }
            public CertificateInventoryEntry Entry { get; init; } = null!;
        }

        /// <summary>Builds reuse.</summary>
        public static CertificateInventoryReuseSummary BuildReuse(
            IEnumerable<CertificateInventorySnapshot>? snapshots,
            bool includeSingleEndpointCertificates = false,
            int minEndpointCount = 2,
            int maxCertificates = 300,
            int maxEndpointsPerCertificate = 30) {
            var summary = new CertificateInventoryReuseSummary();
            var latestByEndpoint = new Dictionary<string, LatestEntryState>(StringComparer.OrdinalIgnoreCase);

            foreach (var snapshot in snapshots ?? Array.Empty<CertificateInventorySnapshot>()) {
                if (snapshot == null) {
                    continue;
                }

                summary.SnapshotCount++;
                foreach (var entry in snapshot.Entries ?? new List<CertificateInventoryEntry>()) {
                    if (entry == null) {
                        continue;
                    }

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

            summary.EndpointCount = latestByEndpoint.Count;

            var normalizedMinEndpointCount = Math.Max(1, minEndpointCount);
            if (includeSingleEndpointCertificates && normalizedMinEndpointCount > 1) {
                normalizedMinEndpointCount = 1;
            }

            var byCertificate = new Dictionary<string, List<LatestEntryState>>(StringComparer.OrdinalIgnoreCase);
            foreach (var latest in latestByEndpoint.Values) {
                var certificateId = BuildCertificateId(latest.Entry);
                if (!byCertificate.TryGetValue(certificateId, out var list)) {
                    list = new List<LatestEntryState>();
                    byCertificate[certificateId] = list;
                }
                list.Add(latest);
            }

            summary.CertificateCount = byCertificate.Count;

            var rows = new List<CertificateInventoryCertificateReuse>(byCertificate.Count);
            foreach (var group in byCertificate.Values) {
                if (group.Count == 0) {
                    continue;
                }

                var representative = group[0].Entry;
                var services = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var ports = new HashSet<int>();
                var hasWildcardSan = false;
                var allowsServerAuth = false;
                var allowsClientAuth = false;
                var lastNotAfter = representative.NotAfterUtc;
                var endpoints = new List<CertificateInventoryEndpointReference>(group.Count);

                foreach (var state in group) {
                    var entry = state.Entry;
                    services.Add(PickService(entry));
                    ports.Add(entry.Port > 0 ? entry.Port : 443);
                    hasWildcardSan = hasWildcardSan || SubjectHasWildcard(entry.CertificateSubject) || entry.SubjectAlternativeNames.Any(SubjectHasWildcard);
                    allowsServerAuth = allowsServerAuth || entry.AllowsServerAuthentication;
                    allowsClientAuth = allowsClientAuth || entry.AllowsClientAuthentication;
                    if (entry.NotAfterUtc.HasValue && (!lastNotAfter.HasValue || entry.NotAfterUtc.Value > lastNotAfter.Value)) {
                        lastNotAfter = entry.NotAfterUtc;
                    }

                    endpoints.Add(new CertificateInventoryEndpointReference {
                        Host = entry.ResolvedHost ?? entry.Host,
                        Port = entry.Port > 0 ? entry.Port : 443,
                        Service = PickService(entry),
                        LastObservedUtc = state.CapturedAtUtc
                    });
                }

                var endpointCount = group.Count;
                if (endpointCount < normalizedMinEndpointCount) {
                    continue;
                }

                if (endpointCount > 1) {
                    summary.MultiEndpointCertificateCount++;
                }
                if (services.Count > 1) {
                    summary.CrossServiceCertificateCount++;
                }
                if (hasWildcardSan) {
                    summary.WildcardCertificateCount++;
                }

                var row = new CertificateInventoryCertificateReuse {
                    CertificateId = BuildCertificateId(representative),
                    Thumbprint = representative.CertificateThumbprint,
                    Subject = representative.CertificateSubject ?? string.Empty,
                    Issuer = PickIssuer(representative),
                    RootIssuer = PickRootIssuer(representative),
                    NotAfterUtc = lastNotAfter,
                    IsKnownCertificateAuthority = representative.IsKnownCertificateAuthority,
                    HasWildcardSan = hasWildcardSan,
                    AllowsServerAuthentication = allowsServerAuth,
                    AllowsClientAuthentication = allowsClientAuth,
                    EndpointCount = endpointCount,
                    DistinctServiceCount = services.Count,
                    DistinctPortCount = ports.Count,
                    Endpoints = endpoints
                        .OrderBy(x => x.Host, StringComparer.OrdinalIgnoreCase)
                        .ThenBy(x => x.Port)
                        .Take(Math.Max(0, maxEndpointsPerCertificate))
                        .ToList()
                };
                rows.Add(row);
            }

            summary.Certificates = rows
                .OrderByDescending(x => x.EndpointCount)
                .ThenByDescending(x => x.DistinctServiceCount)
                .ThenBy(x => x.NotAfterUtc ?? DateTimeOffset.MaxValue)
                .ThenBy(x => x.Subject, StringComparer.OrdinalIgnoreCase)
                .Take(Math.Max(0, maxCertificates))
                .ToList();

            return summary;
        }

        private static string BuildEndpointKey(CertificateInventoryEntry entry) {
            return CertificateInventoryEndpointKey.Build(entry);
        }

        private static string BuildCertificateId(CertificateInventoryEntry entry) {
            if (!string.IsNullOrWhiteSpace(entry.CertificateThumbprint)) {
                return NormalizeThumbprint(entry.CertificateThumbprint);
            }

            var subject = entry.CertificateSubject ?? string.Empty;
            var issuer = PickIssuer(entry);
            var notBefore = entry.NotBeforeUtc?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty;
            var notAfter = entry.NotAfterUtc?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty;
            return $"{subject}|{issuer}|{notBefore}|{notAfter}";
        }

        private static string NormalizeThumbprint(string? value) {
            if (string.IsNullOrWhiteSpace(value)) {
                return string.Empty;
            }

            var chars = value.Where(c => !char.IsWhiteSpace(c) && c != ':').ToArray();
            return new string(chars).Trim().ToUpperInvariant();
        }

        private static string PickService(CertificateInventoryEntry entry) {
            if (!string.IsNullOrWhiteSpace(entry.Service)) {
                return entry.Service!;
            }

            return CertificateServiceClassifier.GuessService(entry.Scheme ?? "https", entry.Port);
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
            if (!string.IsNullOrWhiteSpace(entry.CertificateRootSubject)) {
                return entry.CertificateRootSubject!;
            }
            return "Unknown";
        }

        private static bool SubjectHasWildcard(string? value) {
            if (string.IsNullOrWhiteSpace(value)) {
                return false;
            }

            return (value ?? string.Empty).IndexOf("*.", StringComparison.OrdinalIgnoreCase) >= 0;
        }
    }
}
