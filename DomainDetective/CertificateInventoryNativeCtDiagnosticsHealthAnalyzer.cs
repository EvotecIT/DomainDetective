using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective {
    /// <summary>
    /// Query options for CT diagnostics health timeline built from persisted inventory snapshots.
    /// </summary>
    public sealed class CertificateInventoryNativeCtDiagnosticsHealthQuery {
        /// <summary>Gets or sets the since utc value.</summary>
        public DateTimeOffset? SinceUtc { get; set; }
        /// <summary>Gets or sets the until utc value.</summary>
        public DateTimeOffset? UntilUtc { get; set; }
        /// <summary>Gets or sets the latest snapshot only value.</summary>
        public bool LatestSnapshotOnly { get; set; }
        /// <summary>Gets or sets the max snapshots value.</summary>
        public int MaxSnapshots { get; set; } = 200;
        /// <summary>Gets or sets the alert thresholds value.</summary>
        public CertificateInventoryNativeCtDiagnosticsAlertThresholds AlertThresholds { get; set; } = new();
    }

    /// <summary>
    /// Per-snapshot CT diagnostics health row.
    /// </summary>
    public sealed class CertificateInventoryNativeCtDiagnosticsHealthRow {
        /// <summary>Gets or sets the captured at utc value.</summary>
        public DateTimeOffset CapturedAtUtc { get; set; }
        /// <summary>Gets or sets the diagnostic count value.</summary>
        public int DiagnosticCount { get; set; }
        /// <summary>Gets or sets the failed count value.</summary>
        public int FailedCount { get; set; }
        /// <summary>Gets or sets the circuit open count value.</summary>
        public int CircuitOpenCount { get; set; }
        /// <summary>Gets or sets the highest lag after value.</summary>
        public long? HighestLagAfter { get; set; }
        /// <summary>Gets or sets the status value.</summary>
        public string Status { get; set; } = "Unknown";
        /// <summary>Gets or sets the threshold breached value.</summary>
        public bool ThresholdBreached { get; set; }
        /// <summary>Gets or sets the breaches value.</summary>
        public List<string> Breaches { get; set; } = new();
    }

    /// <summary>
    /// CT diagnostics health timeline and current status summary.
    /// </summary>
    public sealed class CertificateInventoryNativeCtDiagnosticsHealthSummary {
        /// <summary>Gets or sets the since utc value.</summary>
        public DateTimeOffset? SinceUtc { get; set; }
        /// <summary>Gets or sets the until utc value.</summary>
        public DateTimeOffset? UntilUtc { get; set; }
        /// <summary>Gets or sets the loaded snapshot count value.</summary>
        public int LoadedSnapshotCount { get; set; }
        /// <summary>Gets or sets the excluded by until count value.</summary>
        public int ExcludedByUntilCount { get; set; }
        /// <summary>Gets or sets the returned snapshot count value.</summary>
        public int ReturnedSnapshotCount { get; set; }
        /// <summary>Gets or sets the breached snapshot count value.</summary>
        public int BreachedSnapshotCount { get; set; }
        /// <summary>Gets or sets the latest snapshot captured at utc value.</summary>
        public DateTimeOffset? LatestSnapshotCapturedAtUtc { get; set; }
        /// <summary>Gets or sets the latest status value.</summary>
        public string LatestStatus { get; set; } = "NoData";
        /// <summary>Gets or sets the last breach captured at utc value.</summary>
        public DateTimeOffset? LastBreachCapturedAtUtc { get; set; }
        /// <summary>Gets or sets the latest breach messages value.</summary>
        public List<string> LatestBreachMessages { get; set; } = new();
        /// <summary>Gets or sets the alert thresholds value.</summary>
        public CertificateInventoryNativeCtDiagnosticsAlertThresholds AlertThresholds { get; set; } = new();
        /// <summary>Gets or sets the snapshots value.</summary>
        public List<CertificateInventoryNativeCtDiagnosticsHealthRow> Snapshots { get; set; } = new();
    }

    /// <summary>
    /// Builds CT diagnostics health timeline from persisted inventory snapshots.
    /// </summary>
    public static class CertificateInventoryNativeCtDiagnosticsHealthAnalyzer {
        /// <summary>Executes the build operation.</summary>
        public static CertificateInventoryNativeCtDiagnosticsHealthSummary Build(
            IEnumerable<CertificateInventorySnapshot>? snapshots,
            CertificateInventoryNativeCtDiagnosticsHealthQuery? query = null) {
            var effectiveQuery = query ?? new CertificateInventoryNativeCtDiagnosticsHealthQuery();
            var summary = new CertificateInventoryNativeCtDiagnosticsHealthSummary {
                SinceUtc = effectiveQuery.SinceUtc,
                UntilUtc = effectiveQuery.UntilUtc,
                AlertThresholds = new CertificateInventoryNativeCtDiagnosticsAlertThresholds {
                    MaxFailedDiagnostics = effectiveQuery.AlertThresholds.MaxFailedDiagnostics,
                    MaxCircuitOpenDiagnostics = effectiveQuery.AlertThresholds.MaxCircuitOpenDiagnostics,
                    MaxLagAfter = effectiveQuery.AlertThresholds.MaxLagAfter
                }
            };

            var ordered = (snapshots ?? Array.Empty<CertificateInventorySnapshot>())
                .OrderByDescending(snapshot => snapshot.CapturedAtUtc)
                .ToList();
            summary.LoadedSnapshotCount = ordered.Count;

            var filtered = ordered
                .Where(snapshot => !effectiveQuery.UntilUtc.HasValue || snapshot.CapturedAtUtc <= effectiveQuery.UntilUtc.Value)
                .ToList();
            summary.ExcludedByUntilCount = summary.LoadedSnapshotCount - filtered.Count;

            if (effectiveQuery.LatestSnapshotOnly && filtered.Count > 1) {
                filtered = filtered.Take(1).ToList();
            }

            var maxSnapshots = Math.Max(0, effectiveQuery.MaxSnapshots);
            if (maxSnapshots > 0 && filtered.Count > maxSnapshots) {
                filtered = filtered.Take(maxSnapshots).ToList();
            } else if (maxSnapshots == 0) {
                filtered.Clear();
            }

            var now = DateTimeOffset.UtcNow;
            foreach (var snapshot in filtered) {
                var row = BuildRow(snapshot, effectiveQuery.AlertThresholds, now);
                summary.Snapshots.Add(row);
                if (row.ThresholdBreached) {
                    summary.BreachedSnapshotCount++;
                    if (!summary.LastBreachCapturedAtUtc.HasValue || summary.LastBreachCapturedAtUtc.Value < row.CapturedAtUtc) {
                        summary.LastBreachCapturedAtUtc = row.CapturedAtUtc;
                    }
                }
            }

            summary.ReturnedSnapshotCount = summary.Snapshots.Count;
            if (summary.Snapshots.Count > 0) {
                var latest = summary.Snapshots[0];
                summary.LatestSnapshotCapturedAtUtc = latest.CapturedAtUtc;
                summary.LatestStatus = latest.Status;
                summary.LatestBreachMessages = latest.Breaches.ToList();
            }

            return summary;
        }

        private static CertificateInventoryNativeCtDiagnosticsHealthRow BuildRow(
            CertificateInventorySnapshot snapshot,
            CertificateInventoryNativeCtDiagnosticsAlertThresholds thresholds,
            DateTimeOffset now) {
            var diagnostics = CertificateInventoryNativeCtDiagnosticsParsing.ResolveDiagnostics(snapshot);
            var result = new CertificateInventoryNativeCtDiagnosticsResult();
            foreach (var diagnostic in diagnostics) {
                if (diagnostic == null) {
                    continue;
                }

                result.ScannedDiagnosticCount++;
                result.MatchedDiagnosticCount++;
                if (diagnostic.LagAfter.HasValue &&
                    (!result.MatchedLagAfterMax.HasValue || diagnostic.LagAfter.Value > result.MatchedLagAfterMax.Value)) {
                    result.MatchedLagAfterMax = diagnostic.LagAfter.Value;
                }
                var state = CertificateInventoryNativeCtDiagnosticsParsing.NormalizeState(diagnostic.State);
                result.MatchedByState[state] = result.MatchedByState.TryGetValue(state, out var count) ? count + 1 : 1;
                result.Entries.Add(new CertificateInventoryNativeCtDiagnosticObservedEntry {
                    CapturedAtUtc = snapshot.CapturedAtUtc,
                    Entry = diagnostic
                });
            }

            var evaluation = CertificateInventoryNativeCtDiagnosticsAlerts.Evaluate(result, thresholds, now);
            var diagnosticCount = diagnostics.Count;
            var row = new CertificateInventoryNativeCtDiagnosticsHealthRow {
                CapturedAtUtc = snapshot.CapturedAtUtc,
                DiagnosticCount = diagnosticCount,
                FailedCount = evaluation.FailedDiagnostics,
                CircuitOpenCount = evaluation.CircuitOpenDiagnostics,
                HighestLagAfter = evaluation.HighestLagAfter,
                ThresholdBreached = evaluation.HasBreach,
                Breaches = evaluation.BreachMessages.ToList()
            };
            row.Status = ResolveStatus(row);
            return row;
        }

        private static string ResolveStatus(CertificateInventoryNativeCtDiagnosticsHealthRow row) {
            if (row.DiagnosticCount <= 0) {
                return "NoDiagnostics";
            }
            if (row.ThresholdBreached) {
                return "Breached";
            }
            if (row.FailedCount > 0 || row.CircuitOpenCount > 0) {
                return "Warning";
            }
            return "Healthy";
        }
    }
}
