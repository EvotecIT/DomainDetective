using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace DomainDetective {
    /// <summary>
    /// Endpoint-level drift summary over persisted certificate inventory snapshots.
    /// </summary>
    public sealed class CertificateInventoryDriftSummary {
        public int SnapshotCount { get; set; }
        public int EndpointCount { get; set; }
        public int EndpointsWithAnyChange { get; set; }
        public int EndpointsWithHighSeverityDrift { get; set; }
        public int EndpointsWithMediumSeverityDrift { get; set; }
        public int EndpointsWithLowSeverityDrift { get; set; }
        public int EndpointsWithCertificateChange { get; set; }
        public int EndpointsWithIssuerChange { get; set; }
        public int EndpointsWithExpiryChange { get; set; }
        public int EndpointsWithServiceChange { get; set; }
        public int EndpointsWithAuthenticationProfileChange { get; set; }
        public int EndpointsWithChainSourceChange { get; set; }
        public List<CertificateInventoryEndpointDrift> Endpoints { get; set; } = new();
    }

    /// <summary>
    /// Drift details for one endpoint over time.
    /// </summary>
    public sealed class CertificateInventoryEndpointDrift {
        public string Host { get; set; } = string.Empty;
        public int Port { get; set; }
        public string Service { get; set; } = string.Empty;
        public DateTimeOffset? FirstSeenUtc { get; set; }
        public DateTimeOffset? LastSeenUtc { get; set; }
        public int ObservationCount { get; set; }
        public int DistinctCertificateCount { get; set; }
        public string? PreviousCertificateId { get; set; }
        public string? CurrentCertificateId { get; set; }
        public string? PreviousIssuer { get; set; }
        public string? CurrentIssuer { get; set; }
        public DateTimeOffset? PreviousNotAfterUtc { get; set; }
        public DateTimeOffset? CurrentNotAfterUtc { get; set; }
        public bool CertificateChanged { get; set; }
        public bool IssuerChanged { get; set; }
        public bool ExpiryChanged { get; set; }
        public bool ServiceChanged { get; set; }
        public string? PreviousAuthenticationProfile { get; set; }
        public string? CurrentAuthenticationProfile { get; set; }
        public bool AuthenticationProfileChanged { get; set; }
        public string? PreviousChainSource { get; set; }
        public string? CurrentChainSource { get; set; }
        public bool ChainSourceChanged { get; set; }
        public string DriftSeverity { get; set; } = "None";
        public List<string> ChangeKinds { get; set; } = new();
        public DateTimeOffset? LastChangedAtUtc { get; set; }
    }

    /// <summary>
    /// Computes per-endpoint certificate drift from persisted snapshots.
    /// </summary>
    public static class CertificateInventoryDriftAnalyzer {
        private sealed class Observation {
            public DateTimeOffset CapturedAtUtc { get; init; }
            public CertificateInventoryEntry Entry { get; init; } = null!;
        }

        public static CertificateInventoryDriftSummary BuildDrift(
            IEnumerable<CertificateInventorySnapshot>? snapshots,
            bool changedOnly = false,
            int maxEndpoints = 200) {
            var summary = new CertificateInventoryDriftSummary();
            var grouped = new Dictionary<string, List<Observation>>(StringComparer.OrdinalIgnoreCase);

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
                    if (!grouped.TryGetValue(endpointKey, out var observations)) {
                        observations = new List<Observation>();
                        grouped[endpointKey] = observations;
                    }

                    observations.Add(new Observation {
                        CapturedAtUtc = snapshot.CapturedAtUtc,
                        Entry = entry
                    });
                }
            }

            var driftRows = new List<CertificateInventoryEndpointDrift>(grouped.Count);
            foreach (var pair in grouped) {
                var observations = pair.Value
                    .OrderBy(o => o.CapturedAtUtc)
                    .ToList();
                if (observations.Count == 0) {
                    continue;
                }

                var latest = observations[observations.Count - 1];
                var previous = observations.Count > 1 ? observations[observations.Count - 2] : null;

                var certificateIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var issuers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var expiries = new HashSet<string>(StringComparer.Ordinal);
                var services = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var authenticationProfiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var chainSources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (var observation in observations) {
                    certificateIds.Add(BuildCertificateId(observation.Entry));

                    var issuer = PickIssuer(observation.Entry);
                    if (!string.IsNullOrWhiteSpace(issuer)) {
                        issuers.Add(issuer);
                    }

                    var expiry = observation.Entry.NotAfterUtc?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty;
                    expiries.Add(expiry);

                    var service = string.IsNullOrWhiteSpace(observation.Entry.Service)
                        ? CertificateServiceClassifier.GuessService(observation.Entry.Scheme ?? "https", observation.Entry.Port)
                        : observation.Entry.Service!;
                    services.Add(service);

                    var authenticationProfile = CertificateInventoryEntryHelpers.ResolveAuthenticationProfile(observation.Entry);
                    authenticationProfiles.Add(authenticationProfile);

                    var chainSource = CertificateInventoryEntryHelpers.PickChainSource(observation.Entry);
                    chainSources.Add(chainSource);
                }

                var previousAuthenticationProfile = previous != null
                    ? CertificateInventoryEntryHelpers.ResolveAuthenticationProfile(previous.Entry)
                    : null;
                var currentAuthenticationProfile = CertificateInventoryEntryHelpers.ResolveAuthenticationProfile(latest.Entry);
                var previousChainSource = previous != null
                    ? CertificateInventoryEntryHelpers.PickChainSource(previous.Entry)
                    : null;
                var currentChainSource = CertificateInventoryEntryHelpers.PickChainSource(latest.Entry);

                var row = new CertificateInventoryEndpointDrift {
                    Host = latest.Entry.ResolvedHost ?? latest.Entry.Host,
                    Port = latest.Entry.Port > 0 ? latest.Entry.Port : 443,
                    Service = string.IsNullOrWhiteSpace(latest.Entry.Service)
                        ? CertificateServiceClassifier.GuessService(latest.Entry.Scheme ?? "https", latest.Entry.Port)
                        : latest.Entry.Service!,
                    FirstSeenUtc = observations[0].CapturedAtUtc,
                    LastSeenUtc = latest.CapturedAtUtc,
                    ObservationCount = observations.Count,
                    DistinctCertificateCount = certificateIds.Count,
                    PreviousCertificateId = previous != null ? BuildCertificateId(previous.Entry) : null,
                    CurrentCertificateId = BuildCertificateId(latest.Entry),
                    PreviousIssuer = previous != null ? PickIssuer(previous.Entry) : null,
                    CurrentIssuer = PickIssuer(latest.Entry),
                    PreviousNotAfterUtc = previous?.Entry.NotAfterUtc,
                    CurrentNotAfterUtc = latest.Entry.NotAfterUtc,
                    CertificateChanged = certificateIds.Count > 1,
                    IssuerChanged = issuers.Count > 1,
                    ExpiryChanged = expiries.Count > 1,
                    ServiceChanged = services.Count > 1,
                    PreviousAuthenticationProfile = previousAuthenticationProfile,
                    CurrentAuthenticationProfile = currentAuthenticationProfile,
                    AuthenticationProfileChanged = authenticationProfiles.Count > 1,
                    PreviousChainSource = previousChainSource,
                    CurrentChainSource = currentChainSource,
                    ChainSourceChanged = chainSources.Count > 1,
                    LastChangedAtUtc = FindLastChangedAt(observations)
                };
                row.ChangeKinds = BuildChangeKinds(row);
                row.DriftSeverity = ClassifyDriftSeverity(row);

                if (changedOnly && row.ChangeKinds.Count == 0) {
                    continue;
                }

                driftRows.Add(row);
            }

            summary.EndpointCount = grouped.Count;
            summary.EndpointsWithCertificateChange = driftRows.Count(row => row.CertificateChanged);
            summary.EndpointsWithIssuerChange = driftRows.Count(row => row.IssuerChanged);
            summary.EndpointsWithExpiryChange = driftRows.Count(row => row.ExpiryChanged);
            summary.EndpointsWithServiceChange = driftRows.Count(row => row.ServiceChanged);
            summary.EndpointsWithAuthenticationProfileChange = driftRows.Count(row => row.AuthenticationProfileChanged);
            summary.EndpointsWithChainSourceChange = driftRows.Count(row => row.ChainSourceChanged);
            summary.EndpointsWithAnyChange = driftRows.Count(row =>
                row.CertificateChanged ||
                row.IssuerChanged ||
                row.ExpiryChanged ||
                row.ServiceChanged ||
                row.AuthenticationProfileChanged ||
                row.ChainSourceChanged);
            summary.EndpointsWithHighSeverityDrift = driftRows.Count(row => row.DriftSeverity.Equals("High", StringComparison.OrdinalIgnoreCase));
            summary.EndpointsWithMediumSeverityDrift = driftRows.Count(row => row.DriftSeverity.Equals("Medium", StringComparison.OrdinalIgnoreCase));
            summary.EndpointsWithLowSeverityDrift = driftRows.Count(row => row.DriftSeverity.Equals("Low", StringComparison.OrdinalIgnoreCase));

            summary.Endpoints = driftRows
                .OrderByDescending(row => row.LastChangedAtUtc ?? DateTimeOffset.MinValue)
                .ThenBy(row => row.Host, StringComparer.OrdinalIgnoreCase)
                .ThenBy(row => row.Port)
                .Take(Math.Max(0, maxEndpoints))
                .ToList();

            return summary;
        }

        private static DateTimeOffset? FindLastChangedAt(IReadOnlyList<Observation> observations) {
            for (var i = observations.Count - 1; i >= 1; i--) {
                var previous = observations[i - 1].Entry;
                var current = observations[i].Entry;
                if (EntryChanged(previous, current)) {
                    return observations[i].CapturedAtUtc;
                }
            }

            return null;
        }

        private static bool EntryChanged(CertificateInventoryEntry previous, CertificateInventoryEntry current) {
            var previousCert = BuildCertificateId(previous);
            var currentCert = BuildCertificateId(current);
            if (!string.Equals(previousCert, currentCert, StringComparison.OrdinalIgnoreCase)) {
                return true;
            }

            var previousIssuer = PickIssuer(previous);
            var currentIssuer = PickIssuer(current);
            if (!string.Equals(previousIssuer, currentIssuer, StringComparison.OrdinalIgnoreCase)) {
                return true;
            }

            var previousExpiry = previous.NotAfterUtc?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty;
            var currentExpiry = current.NotAfterUtc?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty;
            if (!string.Equals(previousExpiry, currentExpiry, StringComparison.Ordinal)) {
                return true;
            }

            var previousService = string.IsNullOrWhiteSpace(previous.Service)
                ? CertificateServiceClassifier.GuessService(previous.Scheme ?? "https", previous.Port)
                : previous.Service!;
            var currentService = string.IsNullOrWhiteSpace(current.Service)
                ? CertificateServiceClassifier.GuessService(current.Scheme ?? "https", current.Port)
                : current.Service!;
            if (!string.Equals(previousService, currentService, StringComparison.OrdinalIgnoreCase)) {
                return true;
            }

            var previousAuthenticationProfile = CertificateInventoryEntryHelpers.ResolveAuthenticationProfile(previous);
            var currentAuthenticationProfile = CertificateInventoryEntryHelpers.ResolveAuthenticationProfile(current);
            if (!string.Equals(previousAuthenticationProfile, currentAuthenticationProfile, StringComparison.OrdinalIgnoreCase)) {
                return true;
            }

            var previousChainSource = CertificateInventoryEntryHelpers.PickChainSource(previous);
            var currentChainSource = CertificateInventoryEntryHelpers.PickChainSource(current);
            return !string.Equals(previousChainSource, currentChainSource, StringComparison.OrdinalIgnoreCase);
        }

        private static string BuildEndpointKey(CertificateInventoryEntry entry) {
            var host = entry.ResolvedHost ?? entry.Host;
            var port = entry.Port > 0 ? entry.Port : 443;
            return $"{host}:{port}";
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
            return string.Empty;
        }

        private static string BuildCertificateId(CertificateInventoryEntry entry) {
            if (!string.IsNullOrWhiteSpace(entry.CertificateThumbprint)) {
                return entry.CertificateThumbprint!;
            }

            var subject = entry.CertificateSubject ?? string.Empty;
            var issuer = entry.CertificateIssuerNormalized ?? entry.CertificateIssuerOrganization ?? entry.CertificateIssuer ?? string.Empty;
            var notBefore = entry.NotBeforeUtc?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty;
            var notAfter = entry.NotAfterUtc?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty;
            return $"{subject}|{issuer}|{notBefore}|{notAfter}";
        }

        private static List<string> BuildChangeKinds(CertificateInventoryEndpointDrift row) {
            var kinds = new List<string>();
            if (row.CertificateChanged) {
                kinds.Add("certificate");
            }
            if (row.IssuerChanged) {
                kinds.Add("issuer");
            }
            if (row.ExpiryChanged) {
                kinds.Add("expiry");
            }
            if (row.ServiceChanged) {
                kinds.Add("service");
            }
            if (row.AuthenticationProfileChanged) {
                kinds.Add("auth-profile");
            }
            if (row.ChainSourceChanged) {
                kinds.Add("chain-source");
            }
            return kinds;
        }

        private static string ClassifyDriftSeverity(CertificateInventoryEndpointDrift row) {
            if (row.ChangeKinds.Count == 0) {
                return "None";
            }

            if (row.AuthenticationProfileChanged) {
                return "High";
            }

            if (row.CertificateChanged && row.IssuerChanged) {
                return "High";
            }

            if (row.ServiceChanged || row.ChainSourceChanged || row.CertificateChanged || row.IssuerChanged) {
                return "Medium";
            }

            if (row.ExpiryChanged) {
                return "Low";
            }

            return "Low";
        }
    }
}
