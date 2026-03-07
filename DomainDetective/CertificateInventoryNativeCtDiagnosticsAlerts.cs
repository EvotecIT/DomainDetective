using System;
using System.Collections.Generic;

namespace DomainDetective {
    /// <summary>
    /// Thresholds used to evaluate native CT diagnostics for alerting.
    /// </summary>
    public sealed class CertificateInventoryNativeCtDiagnosticsAlertThresholds {
        /// <summary>Maximum allowed number of diagnostics in Failed state.</summary>
        public int? MaxFailedDiagnostics { get; set; }

        /// <summary>Maximum allowed number of diagnostics in CircuitOpen state.</summary>
        public int? MaxCircuitOpenDiagnostics { get; set; }

        /// <summary>Maximum allowed LagAfter value among matched diagnostics.</summary>
        public long? MaxLagAfter { get; set; }

        /// <summary>True when at least one threshold is configured.</summary>
        public bool HasAnyThreshold {
            get {
                return MaxFailedDiagnostics.HasValue || MaxCircuitOpenDiagnostics.HasValue || MaxLagAfter.HasValue;
            }
        }
    }

    /// <summary>
    /// Alerting evaluation outcome for native CT diagnostics.
    /// </summary>
    public sealed class CertificateInventoryNativeCtDiagnosticsAlertEvaluation {
        /// <summary>The threshold used for failed diagnostics, when configured.</summary>
        public int? MaxFailedDiagnosticsThreshold { get; set; }

        /// <summary>The threshold used for circuit-open diagnostics, when configured.</summary>
        public int? MaxCircuitOpenDiagnosticsThreshold { get; set; }

        /// <summary>The threshold used for LagAfter, when configured.</summary>
        public long? MaxLagAfterThreshold { get; set; }

        /// <summary>Total matched diagnostics in Failed state.</summary>
        public int FailedDiagnostics { get; set; }

        /// <summary>Total matched diagnostics in CircuitOpen state.</summary>
        public int CircuitOpenDiagnostics { get; set; }

        /// <summary>Highest LagAfter value across matched diagnostics, when present.</summary>
        public long? HighestLagAfter { get; set; }

        /// <summary>True when failed diagnostics exceed configured threshold.</summary>
        public bool FailedDiagnosticsThresholdBreached { get; set; }

        /// <summary>True when circuit-open diagnostics exceed configured threshold.</summary>
        public bool CircuitOpenDiagnosticsThresholdBreached { get; set; }

        /// <summary>True when highest LagAfter exceeds configured threshold.</summary>
        public bool LagAfterThresholdBreached { get; set; }

        /// <summary>True when any threshold has been breached.</summary>
        public bool HasBreach {
            get {
                return FailedDiagnosticsThresholdBreached ||
                       CircuitOpenDiagnosticsThresholdBreached ||
                       LagAfterThresholdBreached;
            }
        }

        /// <summary>Human-readable breach messages.</summary>
        public List<string> BreachMessages { get; } = new();
    }

    /// <summary>
    /// Evaluates native CT diagnostics query results against alert thresholds.
    /// </summary>
    public static class CertificateInventoryNativeCtDiagnosticsAlerts {
        /// <summary>
        /// Evaluates query result metrics against configured thresholds.
        /// </summary>
        /// <param name="result">Diagnostics query result to evaluate.</param>
        /// <param name="thresholds">Configured alert thresholds.</param>
        /// <param name="utcNow">Optional UTC now override used for circuit-open inference.</param>
        /// <returns>Alert evaluation details with breach indicators and messages.</returns>
        public static CertificateInventoryNativeCtDiagnosticsAlertEvaluation Evaluate(
            CertificateInventoryNativeCtDiagnosticsResult? result,
            CertificateInventoryNativeCtDiagnosticsAlertThresholds? thresholds,
            DateTimeOffset? utcNow = null) {
            var evaluation = new CertificateInventoryNativeCtDiagnosticsAlertEvaluation();
            if (result == null) {
                return evaluation;
            }

            evaluation.FailedDiagnostics = GetStateCount(result.MatchedByState, "Failed");
            evaluation.CircuitOpenDiagnostics = GetStateCount(result.MatchedByState, "CircuitOpen");
            evaluation.HighestLagAfter = result.MatchedLagAfterMax ?? ResolveMaxLagAfterFromEntries(result);

            var now = utcNow ?? DateTimeOffset.UtcNow;
            var inferredCircuitOpenCount = CountInferredCircuitOpen(result, now);
            if (inferredCircuitOpenCount > evaluation.CircuitOpenDiagnostics) {
                evaluation.CircuitOpenDiagnostics = inferredCircuitOpenCount;
            }

            if (thresholds == null || !thresholds.HasAnyThreshold) {
                return evaluation;
            }

            evaluation.MaxFailedDiagnosticsThreshold = thresholds.MaxFailedDiagnostics;
            evaluation.MaxCircuitOpenDiagnosticsThreshold = thresholds.MaxCircuitOpenDiagnostics;
            evaluation.MaxLagAfterThreshold = thresholds.MaxLagAfter;

            if (thresholds.MaxFailedDiagnostics.HasValue &&
                evaluation.FailedDiagnostics > thresholds.MaxFailedDiagnostics.Value) {
                evaluation.FailedDiagnosticsThresholdBreached = true;
                evaluation.BreachMessages.Add(
                    $"Failed diagnostics ({evaluation.FailedDiagnostics}) exceeded threshold ({thresholds.MaxFailedDiagnostics.Value}).");
            }

            if (thresholds.MaxCircuitOpenDiagnostics.HasValue &&
                evaluation.CircuitOpenDiagnostics > thresholds.MaxCircuitOpenDiagnostics.Value) {
                evaluation.CircuitOpenDiagnosticsThresholdBreached = true;
                evaluation.BreachMessages.Add(
                    $"Circuit-open diagnostics ({evaluation.CircuitOpenDiagnostics}) exceeded threshold ({thresholds.MaxCircuitOpenDiagnostics.Value}).");
            }

            if (thresholds.MaxLagAfter.HasValue &&
                evaluation.HighestLagAfter.HasValue &&
                evaluation.HighestLagAfter.Value > thresholds.MaxLagAfter.Value) {
                evaluation.LagAfterThresholdBreached = true;
                evaluation.BreachMessages.Add(
                    $"Highest LagAfter ({evaluation.HighestLagAfter.Value}) exceeded threshold ({thresholds.MaxLagAfter.Value}).");
            }

            return evaluation;
        }

        private static int GetStateCount(IReadOnlyDictionary<string, int> countsByState, string state) {
            if (countsByState == null || string.IsNullOrWhiteSpace(state)) {
                return 0;
            }

            return countsByState.TryGetValue(state, out var value) ? value : 0;
        }

        private static int CountInferredCircuitOpen(CertificateInventoryNativeCtDiagnosticsResult result, DateTimeOffset now) {
            var count = 0;
            var entries = result.Entries ?? new List<CertificateInventoryNativeCtDiagnosticObservedEntry>();
            foreach (var observed in entries) {
                var entry = observed.Entry;
                if (entry == null) {
                    continue;
                }

                if (entry.CircuitOpenUntilUtc.HasValue && entry.CircuitOpenUntilUtc.Value > now) {
                    count++;
                }
            }

            return count;
        }

        private static long? ResolveMaxLagAfterFromEntries(CertificateInventoryNativeCtDiagnosticsResult result) {
            long? max = null;
            var entries = result.Entries ?? new List<CertificateInventoryNativeCtDiagnosticObservedEntry>();
            foreach (var observed in entries) {
                var entry = observed.Entry;
                if (entry?.LagAfter == null) {
                    continue;
                }

                if (!max.HasValue || entry.LagAfter.Value > max.Value) {
                    max = entry.LagAfter.Value;
                }
            }

            return max;
        }
    }
}
