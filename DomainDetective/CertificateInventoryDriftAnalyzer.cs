using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace DomainDetective {
    /// <summary>
    /// Endpoint-level drift summary over persisted certificate inventory snapshots.
    /// <para>Aggregate counts are calculated before <see cref="Endpoints"/> is capped by max endpoints.</para>
    /// </summary>
    public sealed class CertificateInventoryDriftSummary {
        /// <summary>Gets or sets the snapshot count value.</summary>
        public int SnapshotCount { get; set; }
        /// <summary>Gets or sets the endpoint count value.</summary>
        public int EndpointCount { get; set; }
        /// <summary>Gets or sets the endpoints matching filters value.</summary>
        public int EndpointsMatchingFilters { get; set; }
        /// <summary>Gets or sets the endpoints excluded by changed only value.</summary>
        public int EndpointsExcludedByChangedOnly { get; set; }
        /// <summary>Gets or sets the endpoints excluded by minimum severity value.</summary>
        public int EndpointsExcludedByMinimumSeverity { get; set; }
        /// <summary>Gets or sets the endpoints excluded by change kind filter value.</summary>
        public int EndpointsExcludedByChangeKindFilter { get; set; }
        /// <summary>Gets or sets the endpoints excluded by filters value.</summary>
        public int EndpointsExcludedByFilters { get; set; }
        /// <summary>Gets or sets the endpoints truncated by max endpoints value.</summary>
        public int EndpointsTruncatedByMaxEndpoints { get; set; }
        /// <summary>Gets or sets the applied change kinds value.</summary>
        public List<string> AppliedChangeKinds { get; set; } = new();
        /// <summary>Gets or sets the applied change kind match mode value.</summary>
        public string AppliedChangeKindMatchMode { get; set; } = "Any";
        /// <summary>Gets or sets the endpoints with any change value.</summary>
        public int EndpointsWithAnyChange { get; set; }
        /// <summary>Gets or sets the endpoints with high severity drift value.</summary>
        public int EndpointsWithHighSeverityDrift { get; set; }
        /// <summary>Gets or sets the endpoints with medium severity drift value.</summary>
        public int EndpointsWithMediumSeverityDrift { get; set; }
        /// <summary>Gets or sets the endpoints with low severity drift value.</summary>
        public int EndpointsWithLowSeverityDrift { get; set; }
        /// <summary>Gets or sets the endpoints with certificate change value.</summary>
        public int EndpointsWithCertificateChange { get; set; }
        /// <summary>Gets or sets the endpoints with issuer change value.</summary>
        public int EndpointsWithIssuerChange { get; set; }
        /// <summary>Gets or sets the endpoints with expiry change value.</summary>
        public int EndpointsWithExpiryChange { get; set; }
        /// <summary>Gets or sets the endpoints with service change value.</summary>
        public int EndpointsWithServiceChange { get; set; }
        /// <summary>Gets or sets the endpoints with authentication profile change value.</summary>
        public int EndpointsWithAuthenticationProfileChange { get; set; }
        /// <summary>Gets or sets the endpoints with chain source change value.</summary>
        public int EndpointsWithChainSourceChange { get; set; }
        /// <summary>Gets or sets the endpoints value.</summary>
        public List<CertificateInventoryEndpointDrift> Endpoints { get; set; } = new();
    }

    /// <summary>
    /// Drift details for one endpoint over time.
    /// </summary>
    public sealed class CertificateInventoryEndpointDrift {
        /// <summary>Gets or sets the host value.</summary>
        public string Host { get; set; } = string.Empty;
        /// <summary>Gets or sets the port value.</summary>
        public int Port { get; set; }
        /// <summary>Gets or sets the service value.</summary>
        public string Service { get; set; } = string.Empty;
        /// <summary>Gets or sets the first seen utc value.</summary>
        public DateTimeOffset? FirstSeenUtc { get; set; }
        /// <summary>Gets or sets the last seen utc value.</summary>
        public DateTimeOffset? LastSeenUtc { get; set; }
        /// <summary>Gets or sets the observation count value.</summary>
        public int ObservationCount { get; set; }
        /// <summary>Gets or sets the distinct certificate count value.</summary>
        public int DistinctCertificateCount { get; set; }
        /// <summary>Gets or sets the previous certificate id value.</summary>
        public string? PreviousCertificateId { get; set; }
        /// <summary>Gets or sets the current certificate id value.</summary>
        public string? CurrentCertificateId { get; set; }
        /// <summary>Gets or sets the previous issuer value.</summary>
        public string? PreviousIssuer { get; set; }
        /// <summary>Gets or sets the current issuer value.</summary>
        public string? CurrentIssuer { get; set; }
        /// <summary>Gets or sets the previous not after utc value.</summary>
        public DateTimeOffset? PreviousNotAfterUtc { get; set; }
        /// <summary>Gets or sets the current not after utc value.</summary>
        public DateTimeOffset? CurrentNotAfterUtc { get; set; }
        /// <summary>Gets or sets the certificate changed value.</summary>
        public bool CertificateChanged { get; set; }
        /// <summary>Gets or sets the issuer changed value.</summary>
        public bool IssuerChanged { get; set; }
        /// <summary>Gets or sets the expiry changed value.</summary>
        public bool ExpiryChanged { get; set; }
        /// <summary>Gets or sets the service changed value.</summary>
        public bool ServiceChanged { get; set; }
        /// <summary>Gets or sets the previous authentication profile value.</summary>
        public string? PreviousAuthenticationProfile { get; set; }
        /// <summary>Gets or sets the current authentication profile value.</summary>
        public string? CurrentAuthenticationProfile { get; set; }
        /// <summary>Gets or sets the authentication profile changed value.</summary>
        public bool AuthenticationProfileChanged { get; set; }
        /// <summary>Gets or sets the previous chain source value.</summary>
        public string? PreviousChainSource { get; set; }
        /// <summary>Gets or sets the current chain source value.</summary>
        public string? CurrentChainSource { get; set; }
        /// <summary>Gets or sets the chain source changed value.</summary>
        public bool ChainSourceChanged { get; set; }
        /// <summary>Gets or sets the drift severity value.</summary>
        public string DriftSeverity { get; set; } = "None";
        /// <summary>Gets or sets the change kinds value.</summary>
        public List<string> ChangeKinds { get; set; } = new();
        /// <summary>Gets or sets the last changed at utc value.</summary>
        public DateTimeOffset? LastChangedAtUtc { get; set; }
    }

    /// <summary>
    /// Computes per-endpoint certificate drift from persisted snapshots.
    /// </summary>
    public static class CertificateInventoryDriftAnalyzer {
        private const string DriftSeverityNone = "None";
        private const string DriftSeverityHigh = "High";
        private const string DriftSeverityMedium = "Medium";
        private const string DriftSeverityLow = "Low";
        private const string ChangeKindCertificate = "certificate";
        private const string ChangeKindIssuer = "issuer";
        private const string ChangeKindExpiry = "expiry";
        private const string ChangeKindService = "service";
        private const string ChangeKindAuthProfile = "auth-profile";
        private const string ChangeKindChainSource = "chain-source";
        private const string ChangeKindMatchAny = "Any";
        private const string ChangeKindMatchAll = "All";

        private sealed class Observation {
            public DateTimeOffset CapturedAtUtc { get; init; }
            public CertificateInventoryEntry Entry { get; init; } = null!;
        }

        /// <summary>
        /// Builds endpoint-level drift summary across certificate inventory snapshots.
        /// </summary>
        /// <param name="snapshots">Snapshots to evaluate for endpoint drift.</param>
        /// <param name="changedOnly">When true, only endpoints with at least one detected change are included.</param>
        /// <param name="maxEndpoints">Maximum number of drift rows to return. Values below 0 are clamped to 0.</param>
        /// <param name="minimumSeverity">Optional minimum severity threshold. Accepted values: none, low, medium, high.</param>
        /// <param name="requiredChangeKinds">Optional change-kind filters.</param>
        /// <param name="changeKindMatchMode">Optional change-kind match mode: any or all.</param>
        /// <returns>Calculated drift summary and endpoint rows.</returns>
        public static CertificateInventoryDriftSummary BuildDrift(
            IEnumerable<CertificateInventorySnapshot>? snapshots,
            bool changedOnly = false,
            int maxEndpoints = 200,
            string? minimumSeverity = null,
            IEnumerable<string>? requiredChangeKinds = null,
            string? changeKindMatchMode = null) {
            var summary = new CertificateInventoryDriftSummary();
            var grouped = new Dictionary<string, List<Observation>>(StringComparer.OrdinalIgnoreCase);
            var minimumSeverityRank = ParseMinimumSeverityRank(minimumSeverity);
            var normalizedChangeKinds = ParseRequiredChangeKinds(requiredChangeKinds);
            var normalizedChangeKindSet = new HashSet<string>(normalizedChangeKinds, StringComparer.OrdinalIgnoreCase);
            var normalizedChangeKindMatchMode = ParseChangeKindMatchMode(changeKindMatchMode);
            summary.AppliedChangeKinds.AddRange(normalizedChangeKinds);
            summary.AppliedChangeKindMatchMode = normalizedChangeKindMatchMode;

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
                    summary.EndpointsExcludedByChangedOnly++;
                    continue;
                }

                if (GetSeverityRank(row.DriftSeverity) < minimumSeverityRank) {
                    summary.EndpointsExcludedByMinimumSeverity++;
                    continue;
                }

                if (normalizedChangeKindSet.Count > 0) {
                    var include = true;
                    if (normalizedChangeKindMatchMode.Equals(ChangeKindMatchAll, StringComparison.OrdinalIgnoreCase)) {
                        var rowChangeKindSet = new HashSet<string>(row.ChangeKinds, StringComparer.OrdinalIgnoreCase);
                        include = normalizedChangeKindSet.All(kind => rowChangeKindSet.Contains(kind));
                    } else {
                        include = row.ChangeKinds.Any(kind => normalizedChangeKindSet.Contains(kind));
                    }
                    if (!include) {
                        summary.EndpointsExcludedByChangeKindFilter++;
                        continue;
                    }
                }

                driftRows.Add(row);
            }

            summary.EndpointCount = grouped.Count;
            summary.EndpointsMatchingFilters = driftRows.Count;
            summary.EndpointsExcludedByFilters =
                summary.EndpointsExcludedByChangedOnly +
                summary.EndpointsExcludedByMinimumSeverity +
                summary.EndpointsExcludedByChangeKindFilter;
            summary.EndpointsWithCertificateChange = driftRows.Count(row => row.CertificateChanged);
            summary.EndpointsWithIssuerChange = driftRows.Count(row => row.IssuerChanged);
            summary.EndpointsWithExpiryChange = driftRows.Count(row => row.ExpiryChanged);
            summary.EndpointsWithServiceChange = driftRows.Count(row => row.ServiceChanged);
            summary.EndpointsWithAuthenticationProfileChange = driftRows.Count(row => row.AuthenticationProfileChanged);
            summary.EndpointsWithChainSourceChange = driftRows.Count(row => row.ChainSourceChanged);
            summary.EndpointsWithAnyChange = driftRows.Count(row => row.ChangeKinds.Count > 0);
            summary.EndpointsWithHighSeverityDrift = driftRows.Count(row => row.DriftSeverity.Equals(DriftSeverityHigh, StringComparison.OrdinalIgnoreCase));
            summary.EndpointsWithMediumSeverityDrift = driftRows.Count(row => row.DriftSeverity.Equals(DriftSeverityMedium, StringComparison.OrdinalIgnoreCase));
            summary.EndpointsWithLowSeverityDrift = driftRows.Count(row => row.DriftSeverity.Equals(DriftSeverityLow, StringComparison.OrdinalIgnoreCase));
            var effectiveMaxEndpoints = Math.Max(0, maxEndpoints);
            summary.EndpointsTruncatedByMaxEndpoints = Math.Max(0, driftRows.Count - effectiveMaxEndpoints);

            summary.Endpoints = driftRows
                .OrderByDescending(row => row.LastChangedAtUtc ?? DateTimeOffset.MinValue)
                .ThenBy(row => row.Host, StringComparer.OrdinalIgnoreCase)
                .ThenBy(row => row.Port)
                .Take(effectiveMaxEndpoints)
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
            return CertificateInventoryEndpointKey.Build(entry, includeServiceDimension: false);
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
                kinds.Add(ChangeKindCertificate);
            }
            if (row.IssuerChanged) {
                kinds.Add(ChangeKindIssuer);
            }
            if (row.ExpiryChanged) {
                kinds.Add(ChangeKindExpiry);
            }
            if (row.ServiceChanged) {
                kinds.Add(ChangeKindService);
            }
            if (row.AuthenticationProfileChanged) {
                kinds.Add(ChangeKindAuthProfile);
            }
            if (row.ChainSourceChanged) {
                kinds.Add(ChangeKindChainSource);
            }
            return kinds;
        }

        private static string ClassifyDriftSeverity(CertificateInventoryEndpointDrift row) {
            if (row.ChangeKinds.Count == 0) {
                return DriftSeverityNone;
            }

            if (row.AuthenticationProfileChanged) {
                return DriftSeverityHigh;
            }

            if (row.CertificateChanged && row.IssuerChanged) {
                return DriftSeverityHigh;
            }

            if (row.ServiceChanged || row.ChainSourceChanged || row.CertificateChanged || row.IssuerChanged) {
                return DriftSeverityMedium;
            }

            return DriftSeverityLow;
        }

        private static int ParseMinimumSeverityRank(string? minimumSeverity) {
            if (!TryNormalizeSeverity(minimumSeverity, out var normalized)) {
                throw new ArgumentException("minimumSeverity must be one of: None, Low, Medium, High.", nameof(minimumSeverity));
            }

            if (string.IsNullOrWhiteSpace(normalized)) {
                return GetSeverityRank(DriftSeverityNone);
            }

            return GetSeverityRank(normalized!);
        }

        /// <summary>
        /// Attempts to normalize severity text to one of the canonical values: None, Low, Medium, High.
        /// </summary>
        /// <param name="value">Input severity text; null/whitespace is treated as no explicit filter.</param>
        /// <param name="normalized">Canonical severity value, or null when no explicit severity was provided.</param>
        /// <returns><c>true</c> when input is empty or a recognized severity value; otherwise <c>false</c>.</returns>
        public static bool TryNormalizeSeverity(string? value, out string? normalized) {
            normalized = null;
            if (string.IsNullOrWhiteSpace(value)) {
                return true;
            }

            var trimmed = value!.Trim();
            if (trimmed.Equals(DriftSeverityNone, StringComparison.OrdinalIgnoreCase)) {
                normalized = DriftSeverityNone;
                return true;
            }
            if (trimmed.Equals(DriftSeverityLow, StringComparison.OrdinalIgnoreCase)) {
                normalized = DriftSeverityLow;
                return true;
            }
            if (trimmed.Equals(DriftSeverityMedium, StringComparison.OrdinalIgnoreCase)) {
                normalized = DriftSeverityMedium;
                return true;
            }
            if (trimmed.Equals(DriftSeverityHigh, StringComparison.OrdinalIgnoreCase)) {
                normalized = DriftSeverityHigh;
                return true;
            }
            return false;
        }

        /// <summary>
        /// Attempts to normalize change-kind text to one of the canonical values:
        /// certificate, issuer, expiry, service, auth-profile, chain-source.
        /// </summary>
        /// <param name="value">Input change-kind text.</param>
        /// <param name="normalized">Canonical change-kind value when recognized; otherwise null.</param>
        /// <returns><c>true</c> when input is a recognized change kind; otherwise <c>false</c>.</returns>
        public static bool TryNormalizeChangeKind(string? value, out string? normalized) {
            normalized = null;
            if (string.IsNullOrWhiteSpace(value)) {
                return false;
            }

            var trimmed = value!.Trim();
            if (trimmed.Equals(ChangeKindCertificate, StringComparison.OrdinalIgnoreCase)) {
                normalized = ChangeKindCertificate;
                return true;
            }
            if (trimmed.Equals(ChangeKindIssuer, StringComparison.OrdinalIgnoreCase)) {
                normalized = ChangeKindIssuer;
                return true;
            }
            if (trimmed.Equals(ChangeKindExpiry, StringComparison.OrdinalIgnoreCase) ||
                trimmed.Equals("expiration", StringComparison.OrdinalIgnoreCase)) {
                normalized = ChangeKindExpiry;
                return true;
            }
            if (trimmed.Equals(ChangeKindService, StringComparison.OrdinalIgnoreCase)) {
                normalized = ChangeKindService;
                return true;
            }
            if (trimmed.Equals(ChangeKindAuthProfile, StringComparison.OrdinalIgnoreCase) ||
                trimmed.Equals("authprofile", StringComparison.OrdinalIgnoreCase) ||
                trimmed.Equals("authenticationprofile", StringComparison.OrdinalIgnoreCase)) {
                normalized = ChangeKindAuthProfile;
                return true;
            }
            if (trimmed.Equals(ChangeKindChainSource, StringComparison.OrdinalIgnoreCase) ||
                trimmed.Equals("chainsource", StringComparison.OrdinalIgnoreCase)) {
                normalized = ChangeKindChainSource;
                return true;
            }
            return false;
        }

        /// <summary>
        /// Attempts to normalize change-kind match mode to one of the canonical values: Any or All.
        /// </summary>
        /// <param name="value">Input match mode text; null/whitespace defaults to Any.</param>
        /// <param name="normalized">Canonical match mode value when recognized.</param>
        /// <returns><c>true</c> when input is empty or a recognized mode; otherwise <c>false</c>.</returns>
        public static bool TryNormalizeChangeKindMatchMode(string? value, out string normalized) {
            normalized = ChangeKindMatchAny;
            if (string.IsNullOrWhiteSpace(value)) {
                return true;
            }

            var trimmed = value!.Trim();
            if (trimmed.Equals(ChangeKindMatchAny, StringComparison.OrdinalIgnoreCase)) {
                normalized = ChangeKindMatchAny;
                return true;
            }
            if (trimmed.Equals(ChangeKindMatchAll, StringComparison.OrdinalIgnoreCase)) {
                normalized = ChangeKindMatchAll;
                return true;
            }

            return false;
        }

        private static int GetSeverityRank(string severity) {
            if (severity.Equals(DriftSeverityNone, StringComparison.OrdinalIgnoreCase)) {
                return 0;
            }
            if (severity.Equals(DriftSeverityLow, StringComparison.OrdinalIgnoreCase)) {
                return 1;
            }
            if (severity.Equals(DriftSeverityMedium, StringComparison.OrdinalIgnoreCase)) {
                return 2;
            }
            if (severity.Equals(DriftSeverityHigh, StringComparison.OrdinalIgnoreCase)) {
                return 3;
            }
            throw new ArgumentException("severity must be one of: None, Low, Medium, High.", nameof(severity));
        }

        private static List<string> ParseRequiredChangeKinds(IEnumerable<string>? requiredChangeKinds) {
            var normalized = new List<string>();
            if (requiredChangeKinds == null) {
                return normalized;
            }

            var dedupe = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var raw in requiredChangeKinds) {
                if (!TryNormalizeChangeKind(raw, out var normalizedChangeKind) || string.IsNullOrWhiteSpace(normalizedChangeKind)) {
                    throw new ArgumentException(
                        "requiredChangeKinds must contain only: certificate, issuer, expiry, service, auth-profile, chain-source.",
                        nameof(requiredChangeKinds));
                }

                var normalizedValue = normalizedChangeKind!;
                if (dedupe.Add(normalizedValue)) {
                    normalized.Add(normalizedValue);
                }
            }

            return normalized;
        }

        private static string ParseChangeKindMatchMode(string? changeKindMatchMode) {
            if (!TryNormalizeChangeKindMatchMode(changeKindMatchMode, out var normalized)) {
                throw new ArgumentException("changeKindMatchMode must be one of: Any, All.", nameof(changeKindMatchMode));
            }

            return normalized;
        }
    }
}
