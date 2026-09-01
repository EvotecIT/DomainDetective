using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace DomainDetective {
    /// <summary>
    /// Point-in-time diff summary between two certificate inventory snapshots.
    /// </summary>
    public sealed class CertificateInventoryDiffSummary {
        /// <summary>Gets or sets the requested previous captured at utc value.</summary>
        public DateTimeOffset? RequestedPreviousCapturedAtUtc { get; set; }
        /// <summary>Gets or sets the requested current captured at utc value.</summary>
        public DateTimeOffset? RequestedCurrentCapturedAtUtc { get; set; }
        /// <summary>Gets or sets the previous captured at utc value.</summary>
        public DateTimeOffset? PreviousCapturedAtUtc { get; set; }
        /// <summary>Gets or sets the current captured at utc value.</summary>
        public DateTimeOffset? CurrentCapturedAtUtc { get; set; }
        /// <summary>Gets or sets the previous endpoint count value.</summary>
        public int PreviousEndpointCount { get; set; }
        /// <summary>Gets or sets the current endpoint count value.</summary>
        public int CurrentEndpointCount { get; set; }
        /// <summary>Gets or sets the added count value.</summary>
        public int AddedCount { get; set; }
        /// <summary>Gets or sets the removed count value.</summary>
        public int RemovedCount { get; set; }
        /// <summary>Gets or sets the changed count value.</summary>
        public int ChangedCount { get; set; }
        /// <summary>Gets or sets the unchanged count value.</summary>
        public int UnchangedCount { get; set; }
        /// <summary>Gets or sets the warnings value.</summary>
        public List<string> Warnings { get; set; } = new();
        /// <summary>Gets or sets the endpoints value.</summary>
        public List<CertificateInventoryEndpointDiff> Endpoints { get; set; } = new();
    }

    /// <summary>
    /// Endpoint-level diff details.
    /// </summary>
    public sealed class CertificateInventoryEndpointDiff {
        /// <summary>Gets or sets the host value.</summary>
        public string Host { get; set; } = string.Empty;
        /// <summary>Gets or sets the port value.</summary>
        public int Port { get; set; }
        /// <summary>Gets or sets the normalized probe vantage value.</summary>
        public string ProbeVantage { get; set; } = CertificateInventoryProbeVantage.Default;
        /// <summary>Gets or sets the status value.</summary>
        public string Status { get; set; } = "Unchanged";
        /// <summary>Gets or sets the previous service value.</summary>
        public string? PreviousService { get; set; }
        /// <summary>Gets or sets the current service value.</summary>
        public string? CurrentService { get; set; }
        /// <summary>Gets or sets the previous issuer value.</summary>
        public string? PreviousIssuer { get; set; }
        /// <summary>Gets or sets the current issuer value.</summary>
        public string? CurrentIssuer { get; set; }
        /// <summary>Gets or sets the previous root value.</summary>
        public string? PreviousRoot { get; set; }
        /// <summary>Gets or sets the current root value.</summary>
        public string? CurrentRoot { get; set; }
        /// <summary>Gets or sets the previous thumbprint value.</summary>
        public string? PreviousThumbprint { get; set; }
        /// <summary>Gets or sets the current thumbprint value.</summary>
        public string? CurrentThumbprint { get; set; }
        /// <summary>Gets or sets the previous not after utc value.</summary>
        public DateTimeOffset? PreviousNotAfterUtc { get; set; }
        /// <summary>Gets or sets the current not after utc value.</summary>
        public DateTimeOffset? CurrentNotAfterUtc { get; set; }
        /// <summary>Gets or sets the previous valid value.</summary>
        public bool? PreviousValid { get; set; }
        /// <summary>Gets or sets the current valid value.</summary>
        public bool? CurrentValid { get; set; }
        /// <summary>Gets or sets the previous chain complete value.</summary>
        public bool? PreviousChainComplete { get; set; }
        /// <summary>Gets or sets the current chain complete value.</summary>
        public bool? CurrentChainComplete { get; set; }
        /// <summary>Gets or sets the previous hostname match value.</summary>
        public bool? PreviousHostnameMatch { get; set; }
        /// <summary>Gets or sets the current hostname match value.</summary>
        public bool? CurrentHostnameMatch { get; set; }
        /// <summary>Gets or sets the change reasons value.</summary>
        public List<string> ChangeReasons { get; set; } = new();
    }

    /// <summary>
    /// Builds endpoint-level diffs between selected certificate inventory snapshots.
    /// </summary>
    public static class CertificateInventoryDiffAnalyzer {
        /// <summary>Builds diff.</summary>
        public static CertificateInventoryDiffSummary BuildDiff(
            IEnumerable<CertificateInventorySnapshot>? snapshots,
            DateTimeOffset? previousCapturedAtUtc = null,
            DateTimeOffset? currentCapturedAtUtc = null,
            bool includeUnchanged = false,
            int maxEndpoints = 500) {
            var summary = new CertificateInventoryDiffSummary {
                RequestedPreviousCapturedAtUtc = previousCapturedAtUtc,
                RequestedCurrentCapturedAtUtc = currentCapturedAtUtc
            };
            var ordered = (snapshots ?? Array.Empty<CertificateInventorySnapshot>())
                .Where(snapshot => snapshot != null)
                .OrderBy(snapshot => snapshot.CapturedAtUtc)
                .ToList();
            if (ordered.Count == 0) {
                return summary;
            }

            var current = ResolveCurrentSnapshot(ordered, currentCapturedAtUtc, out var usedCurrentFallback);
            CertificateInventorySnapshot? previous;
            if (previousCapturedAtUtc.HasValue) {
                previous = ResolveSnapshotAtOrBefore(ordered, previousCapturedAtUtc.Value);
            } else {
                previous = ResolvePreviousSnapshot(ordered, current);
            }

            if (currentCapturedAtUtc.HasValue && usedCurrentFallback) {
                summary.Warnings.Add(
                    $"Requested current snapshot at or before {currentCapturedAtUtc.Value.UtcDateTime:yyyy-MM-dd HH:mm:ss} UTC was not found; using latest snapshot {current.CapturedAtUtc.UtcDateTime:yyyy-MM-dd HH:mm:ss} UTC.");
            }
            if (previousCapturedAtUtc.HasValue && previous == null) {
                summary.Warnings.Add(
                    $"Requested previous snapshot at or before {previousCapturedAtUtc.Value.UtcDateTime:yyyy-MM-dd HH:mm:ss} UTC was not found.");
            }

            summary.CurrentCapturedAtUtc = current?.CapturedAtUtc;
            summary.PreviousCapturedAtUtc = previous?.CapturedAtUtc;

            var previousMap = BuildEndpointMap(previous);
            var currentMap = BuildEndpointMap(current);
            summary.PreviousEndpointCount = previousMap.Count;
            summary.CurrentEndpointCount = currentMap.Count;

            var keys = new HashSet<string>(previousMap.Keys, StringComparer.OrdinalIgnoreCase);
            keys.UnionWith(currentMap.Keys);

            var rows = new List<CertificateInventoryEndpointDiff>(keys.Count);
            foreach (var key in keys) {
                var hasPrevious = previousMap.TryGetValue(key, out var before);
                var hasCurrent = currentMap.TryGetValue(key, out var after);

                var row = new CertificateInventoryEndpointDiff();
                if (hasCurrent) {
                    row.Host = after!.ResolvedHost ?? after.Host;
                    row.Port = NormalizePort(after.Port);
                    row.ProbeVantage = CertificateInventoryProbeVantage.Normalize(after.ProbeVantage);
                } else if (hasPrevious) {
                    row.Host = before!.ResolvedHost ?? before.Host;
                    row.Port = NormalizePort(before.Port);
                    row.ProbeVantage = CertificateInventoryProbeVantage.Normalize(before.ProbeVantage);
                }

                if (!hasPrevious && hasCurrent) {
                    row.Status = "Added";
                    summary.AddedCount++;
                    FillAfter(row, after!);
                    row.ChangeReasons.Add("EndpointAdded");
                    rows.Add(row);
                    continue;
                }

                if (hasPrevious && !hasCurrent) {
                    row.Status = "Removed";
                    summary.RemovedCount++;
                    FillBefore(row, before!);
                    row.ChangeReasons.Add("EndpointRemoved");
                    rows.Add(row);
                    continue;
                }

                FillBefore(row, before!);
                FillAfter(row, after!);
                CollectChangeReasons(row, before!, after!);
                if (row.ChangeReasons.Count == 0) {
                    row.Status = "Unchanged";
                    summary.UnchangedCount++;
                    if (includeUnchanged) {
                        rows.Add(row);
                    }
                } else {
                    row.Status = "Changed";
                    summary.ChangedCount++;
                    rows.Add(row);
                }
            }

            summary.Endpoints = rows
                .OrderBy(row => StatusOrder(row.Status))
                .ThenBy(row => row.Host, StringComparer.OrdinalIgnoreCase)
                .ThenBy(row => row.Port)
                .ThenBy(row => row.ProbeVantage, StringComparer.OrdinalIgnoreCase)
                .Take(Math.Max(0, maxEndpoints))
                .ToList();
            return summary;
        }

        private static CertificateInventorySnapshot ResolveCurrentSnapshot(
            IReadOnlyList<CertificateInventorySnapshot> ordered,
            DateTimeOffset? currentCapturedAtUtc,
            out bool usedFallbackToLatest) {
            if (!currentCapturedAtUtc.HasValue) {
                usedFallbackToLatest = false;
                return ordered[ordered.Count - 1];
            }

            var selected = ResolveSnapshotAtOrBefore(ordered, currentCapturedAtUtc.Value);
            if (selected != null) {
                usedFallbackToLatest = false;
                return selected;
            }

            usedFallbackToLatest = true;
            return ordered[ordered.Count - 1];
        }

        private static CertificateInventorySnapshot? ResolvePreviousSnapshot(
            IReadOnlyList<CertificateInventorySnapshot> ordered,
            CertificateInventorySnapshot? current) {
            if (current == null) {
                return null;
            }

            var index = -1;
            for (var i = 0; i < ordered.Count; i++) {
                if (ReferenceEquals(ordered[i], current)) {
                    index = i;
                    break;
                }
            }
            if (index <= 0) {
                return null;
            }

            return ordered[index - 1];
        }

        private static CertificateInventorySnapshot? ResolveSnapshotAtOrBefore(
            IReadOnlyList<CertificateInventorySnapshot> ordered,
            DateTimeOffset targetUtc) {
            for (var i = ordered.Count - 1; i >= 0; i--) {
                if (ordered[i].CapturedAtUtc <= targetUtc) {
                    return ordered[i];
                }
            }

            return null;
        }

        private static Dictionary<string, CertificateInventoryEntry> BuildEndpointMap(CertificateInventorySnapshot? snapshot) {
            var map = new Dictionary<string, CertificateInventoryEntry>(StringComparer.OrdinalIgnoreCase);
            if (snapshot?.Entries == null) {
                return map;
            }

            foreach (var entry in snapshot.Entries) {
                if (entry == null) {
                    continue;
                }

                map[BuildEndpointKey(entry)] = entry;
            }

            return map;
        }

        private static string BuildEndpointKey(CertificateInventoryEntry entry) {
            return CertificateInventoryEndpointKey.Build(entry) + "|" + CertificateInventoryProbeVantage.Normalize(entry.ProbeVantage);
        }

        private static int NormalizePort(int port) {
            return port > 0 ? port : 443;
        }

        private static void FillBefore(CertificateInventoryEndpointDiff row, CertificateInventoryEntry entry) {
            row.PreviousService = PickService(entry);
            row.PreviousIssuer = PickIssuer(entry);
            row.PreviousRoot = PickRoot(entry);
            row.PreviousThumbprint = entry.CertificateThumbprint;
            row.PreviousNotAfterUtc = entry.NotAfterUtc;
            row.PreviousValid = entry.Valid;
            row.PreviousChainComplete = entry.ChainComplete;
            row.PreviousHostnameMatch = entry.HostnameMatch;
        }

        private static void FillAfter(CertificateInventoryEndpointDiff row, CertificateInventoryEntry entry) {
            row.CurrentService = PickService(entry);
            row.CurrentIssuer = PickIssuer(entry);
            row.CurrentRoot = PickRoot(entry);
            row.CurrentThumbprint = entry.CertificateThumbprint;
            row.CurrentNotAfterUtc = entry.NotAfterUtc;
            row.CurrentValid = entry.Valid;
            row.CurrentChainComplete = entry.ChainComplete;
            row.CurrentHostnameMatch = entry.HostnameMatch;
        }

        private static void CollectChangeReasons(
            CertificateInventoryEndpointDiff row,
            CertificateInventoryEntry before,
            CertificateInventoryEntry after) {
            if (!EquivalentThumbprint(before.CertificateThumbprint, after.CertificateThumbprint)) {
                row.ChangeReasons.Add("Certificate");
            }

            if (!EquivalentCaseInsensitive(PickIssuer(before), PickIssuer(after))) {
                row.ChangeReasons.Add("Issuer");
            }

            if (!EquivalentCaseInsensitive(PickRoot(before), PickRoot(after))) {
                row.ChangeReasons.Add("Root");
            }

            if (!EquivalentDate(before.NotAfterUtc, after.NotAfterUtc)) {
                row.ChangeReasons.Add("Expiry");
            }

            if (!EquivalentCaseInsensitive(PickService(before), PickService(after))) {
                row.ChangeReasons.Add("Service");
            }

            if (before.Valid != after.Valid) {
                row.ChangeReasons.Add("Valid");
            }

            if (before.ChainComplete != after.ChainComplete) {
                row.ChangeReasons.Add("Chain");
            }

            if (before.HostnameMatch != after.HostnameMatch) {
                row.ChangeReasons.Add("Hostname");
            }
        }

        private static bool EquivalentThumbprint(string? left, string? right) {
            return NormalizeThumbprint(left).Equals(NormalizeThumbprint(right), StringComparison.OrdinalIgnoreCase);
        }

        private static string NormalizeThumbprint(string? value) {
            if (string.IsNullOrWhiteSpace(value)) {
                return string.Empty;
            }

            var chars = value.Where(c => !char.IsWhiteSpace(c) && c != ':').ToArray();
            return new string(chars).Trim().ToUpperInvariant();
        }

        private static bool EquivalentCaseInsensitive(string? left, string? right) {
            return string.Equals(left ?? string.Empty, right ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        }

        private static bool EquivalentDate(DateTimeOffset? left, DateTimeOffset? right) {
            var l = left?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty;
            var r = right?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty;
            return string.Equals(l, r, StringComparison.Ordinal);
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
            return string.Empty;
        }

        private static string PickRoot(CertificateInventoryEntry entry) {
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
            return string.Empty;
        }

        private static int StatusOrder(string status) {
            return status switch {
                "Changed" => 0,
                "Added" => 1,
                "Removed" => 2,
                _ => 3
            };
        }
    }
}
