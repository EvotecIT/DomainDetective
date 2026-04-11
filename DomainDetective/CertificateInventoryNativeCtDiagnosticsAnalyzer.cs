using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective {
    /// <summary>
    /// Query options for native CT ingestion diagnostics persisted with inventory snapshots.
    /// </summary>
    public sealed class CertificateInventoryNativeCtDiagnosticsQuery {
        /// <summary>Only include snapshots captured since this UTC date/time.</summary>
        public DateTimeOffset? SinceUtc { get; set; }

        /// <summary>Only include snapshots captured up to this UTC date/time.</summary>
        public DateTimeOffset? UntilUtc { get; set; }

        /// <summary>Only evaluate the latest snapshot after date filtering.</summary>
        public bool LatestSnapshotOnly { get; set; }

        /// <summary>Optional state filter(s): Succeeded, Failed, CircuitOpen.</summary>
        public List<string> States { get; } = new();

        /// <summary>Optional contains filter applied to diagnostic log URL.</summary>
        public string? LogUrlContains { get; set; }

        /// <summary>Optional contains filter applied to diagnostic scope.</summary>
        public string? ScopeContains { get; set; }

        /// <summary>When true, only diagnostics currently marked as circuit open are returned.</summary>
        public bool CircuitOpenOnly { get; set; }

        /// <summary>When true, only diagnostics with non-empty failure messages are returned.</summary>
        public bool FailureOnly { get; set; }

        /// <summary>Optional minimum LagBefore value.</summary>
        public long? LagBeforeMin { get; set; }

        /// <summary>Optional maximum LagBefore value.</summary>
        public long? LagBeforeMax { get; set; }

        /// <summary>Optional minimum LagAfter value.</summary>
        public long? LagAfterMin { get; set; }

        /// <summary>Optional maximum LagAfter value.</summary>
        public long? LagAfterMax { get; set; }

        /// <summary>Maximum number of matched rows returned in <see cref="CertificateInventoryNativeCtDiagnosticsResult.Entries"/>.</summary>
        public int MaxResults { get; set; } = 2000;
    }

    /// <summary>
    /// One observed native CT diagnostic entry with snapshot timestamp context.
    /// </summary>
    public sealed class CertificateInventoryNativeCtDiagnosticObservedEntry {
        /// <summary>Gets or sets the captured at utc value.</summary>
        public DateTimeOffset CapturedAtUtc { get; set; }
        /// <summary>Gets or sets the entry value.</summary>
        public NativeCtLogDiagnosticEntry Entry { get; set; } = new();
    }

    /// <summary>
    /// Query result for native CT diagnostics across persisted snapshots.
    /// </summary>
    public sealed class CertificateInventoryNativeCtDiagnosticsResult {
        /// <summary>Gets or sets the since utc value.</summary>
        public DateTimeOffset? SinceUtc { get; set; }
        /// <summary>Gets or sets the until utc value.</summary>
        public DateTimeOffset? UntilUtc { get; set; }
        /// <summary>Gets or sets the loaded snapshot count value.</summary>
        public int LoadedSnapshotCount { get; set; }
        /// <summary>Gets or sets the skipped snapshot count by until utc value.</summary>
        public int SkippedSnapshotCountByUntilUtc { get; set; }
        /// <summary>Gets or sets the scanned snapshot count value.</summary>
        public int ScannedSnapshotCount { get; set; }
        /// <summary>Gets or sets the scanned diagnostic count value.</summary>
        public int ScannedDiagnosticCount { get; set; }
        /// <summary>Gets or sets the matched diagnostic count value.</summary>
        public int MatchedDiagnosticCount { get; set; }
        /// <summary>Gets or sets the matched lag after max value.</summary>
        public long? MatchedLagAfterMax { get; set; }
        /// <summary>Gets or sets the entries truncated by max results value.</summary>
        public int EntriesTruncatedByMaxResults { get; set; }
        /// <summary>Gets or sets the truncated value.</summary>
        public bool Truncated { get; set; }
        /// <summary>Gets or sets the alert evaluation value.</summary>
        public CertificateInventoryNativeCtDiagnosticsAlertEvaluation? AlertEvaluation { get; set; }
        /// <summary>Gets the matched by state value.</summary>
        public Dictionary<string, int> MatchedByState { get; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Gets the entries value.</summary>
        public List<CertificateInventoryNativeCtDiagnosticObservedEntry> Entries { get; } = new();
    }

    /// <summary>
    /// Analyzer for native CT diagnostics persisted with certificate inventory snapshots.
    /// </summary>
    public static class CertificateInventoryNativeCtDiagnosticsAnalyzer {
        /// <summary>Executes the query operation.</summary>
        public static CertificateInventoryNativeCtDiagnosticsResult Query(
            IEnumerable<CertificateInventorySnapshot>? snapshots,
            CertificateInventoryNativeCtDiagnosticsQuery? query = null) {
            var effectiveQuery = query ?? new CertificateInventoryNativeCtDiagnosticsQuery();
            var result = new CertificateInventoryNativeCtDiagnosticsResult {
                SinceUtc = effectiveQuery.SinceUtc,
                UntilUtc = effectiveQuery.UntilUtc
            };

            var maxResults = Math.Max(0, effectiveQuery.MaxResults);
            var stateFilter = BuildStateFilter(effectiveQuery.States);
            var now = DateTimeOffset.UtcNow;

            var loadedSnapshots = (snapshots ?? Array.Empty<CertificateInventorySnapshot>())
                .OrderByDescending(snapshot => snapshot.CapturedAtUtc)
                .ToList();
            result.LoadedSnapshotCount = loadedSnapshots.Count;

            var scannedSnapshots = new List<CertificateInventorySnapshot>(loadedSnapshots.Count);
            foreach (var snapshot in loadedSnapshots) {
                if (effectiveQuery.UntilUtc.HasValue && snapshot.CapturedAtUtc > effectiveQuery.UntilUtc.Value) {
                    result.SkippedSnapshotCountByUntilUtc++;
                    continue;
                }

                scannedSnapshots.Add(snapshot);
            }

            if (effectiveQuery.LatestSnapshotOnly && scannedSnapshots.Count > 1) {
                scannedSnapshots = scannedSnapshots.Take(1).ToList();
            }
            result.ScannedSnapshotCount = scannedSnapshots.Count;

            foreach (var snapshot in scannedSnapshots) {
                var diagnostics = ResolveDiagnostics(snapshot);
                foreach (var diagnostic in diagnostics) {
                    result.ScannedDiagnosticCount++;
                    if (!MatchesQuery(diagnostic, effectiveQuery, stateFilter, now)) {
                        continue;
                    }

                    result.MatchedDiagnosticCount++;
                    IncrementState(result.MatchedByState, diagnostic.State);
                    if (diagnostic.LagAfter.HasValue) {
                        if (!result.MatchedLagAfterMax.HasValue || diagnostic.LagAfter.Value > result.MatchedLagAfterMax.Value) {
                            result.MatchedLagAfterMax = diagnostic.LagAfter.Value;
                        }
                    }
                    if (result.Entries.Count >= maxResults) {
                        result.Truncated = true;
                        continue;
                    }

                    result.Entries.Add(new CertificateInventoryNativeCtDiagnosticObservedEntry {
                        CapturedAtUtc = snapshot.CapturedAtUtc,
                        Entry = CloneDiagnostic(diagnostic)
                    });
                }
            }

            result.EntriesTruncatedByMaxResults = result.MatchedDiagnosticCount - result.Entries.Count;
            return result;
        }

        private static bool MatchesQuery(
            NativeCtLogDiagnosticEntry diagnostic,
            CertificateInventoryNativeCtDiagnosticsQuery query,
            HashSet<string>? stateFilter,
            DateTimeOffset now) {
            if (diagnostic == null) {
                return false;
            }

            var state = CertificateInventoryNativeCtDiagnosticsParsing.NormalizeState(diagnostic.State);
            if (stateFilter != null && stateFilter.Count > 0 && !stateFilter.Contains(state)) {
                return false;
            }

            if (query.CircuitOpenOnly) {
                var isCircuitOpen = string.Equals(state, "CircuitOpen", StringComparison.OrdinalIgnoreCase) ||
                                    (diagnostic.CircuitOpenUntilUtc.HasValue && diagnostic.CircuitOpenUntilUtc.Value > now);
                if (!isCircuitOpen) {
                    return false;
                }
            }

            if (query.FailureOnly && string.IsNullOrWhiteSpace(diagnostic.Failure)) {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(query.LogUrlContains)) {
                var needle = query.LogUrlContains!.Trim();
                var haystack = diagnostic.LogUrl ?? string.Empty;
                if (haystack.IndexOf(needle, StringComparison.OrdinalIgnoreCase) < 0) {
                    return false;
                }
            }

            if (!string.IsNullOrWhiteSpace(query.ScopeContains)) {
                var needle = query.ScopeContains!.Trim();
                var haystack = diagnostic.Scope ?? string.Empty;
                if (haystack.IndexOf(needle, StringComparison.OrdinalIgnoreCase) < 0) {
                    return false;
                }
            }

            if (query.LagBeforeMin.HasValue && (!diagnostic.LagBefore.HasValue || diagnostic.LagBefore.Value < query.LagBeforeMin.Value)) {
                return false;
            }
            if (query.LagBeforeMax.HasValue && (!diagnostic.LagBefore.HasValue || diagnostic.LagBefore.Value > query.LagBeforeMax.Value)) {
                return false;
            }
            if (query.LagAfterMin.HasValue && (!diagnostic.LagAfter.HasValue || diagnostic.LagAfter.Value < query.LagAfterMin.Value)) {
                return false;
            }
            if (query.LagAfterMax.HasValue && (!diagnostic.LagAfter.HasValue || diagnostic.LagAfter.Value > query.LagAfterMax.Value)) {
                return false;
            }

            return true;
        }

        private static IReadOnlyList<NativeCtLogDiagnosticEntry> ResolveDiagnostics(CertificateInventorySnapshot snapshot) {
            return CertificateInventoryNativeCtDiagnosticsParsing.ResolveDiagnostics(snapshot);
        }

        private static string NormalizeState(string? value) {
            return CertificateInventoryNativeCtDiagnosticsParsing.NormalizeState(value);
        }

        private static HashSet<string>? BuildStateFilter(IReadOnlyCollection<string> states) {
            if (states == null || states.Count == 0) {
                return null;
            }

            var filter = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var state in states) {
                if (string.IsNullOrWhiteSpace(state)) {
                    continue;
                }

                filter.Add(NormalizeState(state));
            }

            return filter.Count == 0 ? null : filter;
        }

        private static void IncrementState(IDictionary<string, int> map, string? state) {
            var key = NormalizeState(state);
            map[key] = map.TryGetValue(key, out var count) ? count + 1 : 1;
        }

        private static NativeCtLogDiagnosticEntry CloneDiagnostic(NativeCtLogDiagnosticEntry entry) {
            return new NativeCtLogDiagnosticEntry {
                Scope = entry.Scope,
                SharedIngestion = entry.SharedIngestion,
                State = entry.State,
                LogUrl = entry.LogUrl,
                TreeSize = entry.TreeSize,
                LastProcessedIndex = entry.LastProcessedIndex,
                LagBefore = entry.LagBefore,
                LagAfter = entry.LagAfter,
                CircuitOpenUntilUtc = entry.CircuitOpenUntilUtc,
                Failure = entry.Failure
            };
        }
    }
}
