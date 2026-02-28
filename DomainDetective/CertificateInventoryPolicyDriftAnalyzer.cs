using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective {
    /// <summary>
    /// Point-in-time policy drift summary between two certificate inventory snapshots.
    /// </summary>
    public sealed class CertificateInventoryPolicyDriftSummary {
        public string BaselineProfile { get; set; } = "Balanced";
        public int SnapshotCount { get; set; }
        public DateTimeOffset? PreviousCapturedAtUtc { get; set; }
        public DateTimeOffset? CurrentCapturedAtUtc { get; set; }
        public int PreviousEndpointCount { get; set; }
        public int CurrentEndpointCount { get; set; }
        public int EndpointCount { get; set; }
        public int PreviousViolationEndpointCount { get; set; }
        public int CurrentViolationEndpointCount { get; set; }
        public int AddedViolationEndpointCount { get; set; }
        public int ResolvedViolationEndpointCount { get; set; }
        public int IncreasedViolationEndpointCount { get; set; }
        public int DecreasedViolationEndpointCount { get; set; }
        public int UnchangedViolationEndpointCount { get; set; }
        public int EndpointsWithAnyPolicyChange { get; set; }
        public int EndpointsMatchingFilters { get; set; }
        public int EndpointsExcludedByChangedOnly { get; set; }
        public int EndpointsTruncatedByMaxEndpoints { get; set; }
        public bool Truncated { get; set; }
        public Dictionary<string, int> NewViolationCodeCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> ResolvedViolationCodeCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public List<CertificateInventoryEndpointPolicyDrift> Endpoints { get; set; } = new();
    }

    /// <summary>
    /// Endpoint-level policy drift details.
    /// </summary>
    public sealed class CertificateInventoryEndpointPolicyDrift {
        public string Host { get; set; } = string.Empty;
        public int Port { get; set; }
        public string Status { get; set; } = "Unchanged";
        public bool? PreviousCompliant { get; set; }
        public bool? CurrentCompliant { get; set; }
        public int PreviousViolationCount { get; set; }
        public int CurrentViolationCount { get; set; }
        public string PreviousMaxViolationSeverity { get; set; } = "None";
        public string CurrentMaxViolationSeverity { get; set; } = "None";
        public int PreviousRiskScore { get; set; }
        public int CurrentRiskScore { get; set; }
        public string PreviousRiskSeverity { get; set; } = "None";
        public string CurrentRiskSeverity { get; set; } = "None";
        public string? PreviousIssuer { get; set; }
        public string? CurrentIssuer { get; set; }
        public DateTimeOffset? PreviousNotAfterUtc { get; set; }
        public DateTimeOffset? CurrentNotAfterUtc { get; set; }
        public List<string> PreviousViolationCodes { get; set; } = new();
        public List<string> CurrentViolationCodes { get; set; } = new();
        public List<string> NewViolationCodes { get; set; } = new();
        public List<string> ResolvedViolationCodes { get; set; } = new();
        public List<string> ChangeKinds { get; set; } = new();
    }

    /// <summary>
    /// Builds endpoint-level policy drift between selected certificate inventory snapshots.
    /// </summary>
    public static class CertificateInventoryPolicyDriftAnalyzer {
        private static readonly Dictionary<string, int> SeverityRanks =
            new(StringComparer.OrdinalIgnoreCase) {
                ["None"] = 0,
                ["Low"] = 1,
                ["Medium"] = 2,
                ["High"] = 3,
                ["Critical"] = 4
            };

        public static CertificateInventoryPolicyDriftSummary BuildDrift(
            IEnumerable<CertificateInventorySnapshot>? snapshots,
            string? baselineProfile = "Balanced",
            DateTimeOffset? previousCapturedAtUtc = null,
            DateTimeOffset? currentCapturedAtUtc = null,
            bool changedOnly = true,
            int maxEndpoints = 300,
            CertificateInventoryPolicyOverrides? policyOverrides = null) {
            if (maxEndpoints < 0) {
                throw new ArgumentOutOfRangeException(nameof(maxEndpoints), "maxEndpoints must be 0 or greater.");
            }

            var effectiveProfile = string.IsNullOrWhiteSpace(baselineProfile) ? "Balanced" : baselineProfile!;
            if (!CertificateInventoryPolicyAnalyzer.TryResolveBaselineProfile(effectiveProfile, out var normalizedBaselineProfile)) {
                throw new ArgumentException(
                    $"baselineProfile must be one of: {CertificateInventoryPolicyAnalyzer.BaselineProfileAcceptedValues}.",
                    nameof(baselineProfile));
            }

            var summary = new CertificateInventoryPolicyDriftSummary {
                BaselineProfile = normalizedBaselineProfile
            };

            var ordered = (snapshots ?? Array.Empty<CertificateInventorySnapshot>())
                .Where(snapshot => snapshot != null)
                .OrderBy(snapshot => snapshot.CapturedAtUtc)
                .ToList();
            summary.SnapshotCount = ordered.Count;
            if (ordered.Count == 0) {
                return summary;
            }

            var current = ResolveCurrentSnapshot(ordered, currentCapturedAtUtc);
            var previous = previousCapturedAtUtc.HasValue
                ? ResolveSnapshotAtOrBefore(ordered, previousCapturedAtUtc.Value)
                : ResolvePreviousSnapshot(ordered, current);

            summary.CurrentCapturedAtUtc = current?.CapturedAtUtc;
            summary.PreviousCapturedAtUtc = previous?.CapturedAtUtc;

            var previousMap = BuildEndpointPolicyMap(previous, normalizedBaselineProfile, policyOverrides);
            var currentMap = BuildEndpointPolicyMap(current, normalizedBaselineProfile, policyOverrides);

            summary.PreviousEndpointCount = previousMap.Count;
            summary.CurrentEndpointCount = currentMap.Count;
            summary.PreviousViolationEndpointCount = previousMap.Values.Count(endpoint => !endpoint.Compliant);
            summary.CurrentViolationEndpointCount = currentMap.Values.Count(endpoint => !endpoint.Compliant);

            var keys = new HashSet<string>(previousMap.Keys, StringComparer.OrdinalIgnoreCase);
            keys.UnionWith(currentMap.Keys);
            summary.EndpointCount = keys.Count;

            var allRows = new List<CertificateInventoryEndpointPolicyDrift>(keys.Count);
            foreach (var key in keys) {
                var hasPrevious = previousMap.TryGetValue(key, out var before);
                var hasCurrent = currentMap.TryGetValue(key, out var after);
                var row = BuildRow(before, after, hasPrevious, hasCurrent);
                allRows.Add(row);

                if (!hasPrevious && hasCurrent) {
                    if (after != null && !after.Compliant) {
                        summary.AddedViolationEndpointCount++;
                    }
                } else if (hasPrevious && !hasCurrent) {
                    if (before != null && !before.Compliant) {
                        summary.ResolvedViolationEndpointCount++;
                    }
                } else {
                    var previousCompliant = before == null || before.Compliant;
                    var currentCompliant = after == null || after.Compliant;
                    if (previousCompliant && !currentCompliant) {
                        summary.AddedViolationEndpointCount++;
                    }
                    if (!previousCompliant && currentCompliant) {
                        summary.ResolvedViolationEndpointCount++;
                    }

                    if (row.CurrentViolationCount > row.PreviousViolationCount) {
                        summary.IncreasedViolationEndpointCount++;
                    } else if (row.CurrentViolationCount < row.PreviousViolationCount) {
                        summary.DecreasedViolationEndpointCount++;
                    } else if (row.CurrentViolationCount > 0) {
                        summary.UnchangedViolationEndpointCount++;
                    }
                }

                if (row.ChangeKinds.Count > 0 || !string.Equals(row.Status, "Unchanged", StringComparison.OrdinalIgnoreCase)) {
                    summary.EndpointsWithAnyPolicyChange++;
                }

                foreach (var code in row.NewViolationCodes) {
                    Increment(summary.NewViolationCodeCounts, code);
                }
                foreach (var code in row.ResolvedViolationCodes) {
                    Increment(summary.ResolvedViolationCodeCounts, code);
                }
            }

            var filteredRows = new List<CertificateInventoryEndpointPolicyDrift>(allRows.Count);
            foreach (var row in allRows) {
                var hasPolicyChange = row.ChangeKinds.Count > 0 || !string.Equals(row.Status, "Unchanged", StringComparison.OrdinalIgnoreCase);
                if (changedOnly && !hasPolicyChange) {
                    summary.EndpointsExcludedByChangedOnly++;
                    continue;
                }

                filteredRows.Add(row);
            }

            summary.EndpointsMatchingFilters = filteredRows.Count;
            summary.EndpointsTruncatedByMaxEndpoints = Math.Max(0, summary.EndpointsMatchingFilters - maxEndpoints);
            summary.Truncated = summary.EndpointsTruncatedByMaxEndpoints > 0;
            summary.Endpoints = filteredRows
                .OrderBy(row => StatusOrder(row.Status))
                .ThenByDescending(row => Math.Max(GetSeverityRank(row.PreviousMaxViolationSeverity), GetSeverityRank(row.CurrentMaxViolationSeverity)))
                .ThenByDescending(row => row.NewViolationCodes.Count + row.ResolvedViolationCodes.Count)
                .ThenBy(row => row.Host, StringComparer.OrdinalIgnoreCase)
                .ThenBy(row => row.Port)
                .Take(maxEndpoints)
                .ToList();

            return summary;
        }

        private static CertificateInventorySnapshot? ResolveCurrentSnapshot(
            IReadOnlyList<CertificateInventorySnapshot> ordered,
            DateTimeOffset? currentCapturedAtUtc) {
            if (!currentCapturedAtUtc.HasValue) {
                return ordered[ordered.Count - 1];
            }

            return ResolveSnapshotAtOrBefore(ordered, currentCapturedAtUtc.Value) ?? ordered[ordered.Count - 1];
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

        private static Dictionary<string, CertificateInventoryEndpointPolicy> BuildEndpointPolicyMap(
            CertificateInventorySnapshot? snapshot,
            string normalizedBaselineProfile,
            CertificateInventoryPolicyOverrides? policyOverrides) {
            var map = new Dictionary<string, CertificateInventoryEndpointPolicy>(StringComparer.OrdinalIgnoreCase);
            if (snapshot == null) {
                return map;
            }

            var policy = CertificateInventoryPolicyAnalyzer.BuildPolicy(
                new[] { snapshot },
                baselineProfile: normalizedBaselineProfile,
                includeCompliant: true,
                maxEndpoints: int.MaxValue,
                policyOverrides: policyOverrides);

            foreach (var endpoint in policy.Endpoints) {
                map[BuildEndpointKey(endpoint)] = endpoint;
            }

            return map;
        }

        private static CertificateInventoryEndpointPolicyDrift BuildRow(
            CertificateInventoryEndpointPolicy? before,
            CertificateInventoryEndpointPolicy? after,
            bool hasPrevious,
            bool hasCurrent) {
            var row = new CertificateInventoryEndpointPolicyDrift();
            var source = after ?? before;
            if (source != null) {
                row.Host = source.Host;
                row.Port = source.Port;
            }

            if (!hasPrevious && hasCurrent) {
                row.Status = "Added";
                PopulateCurrent(row, after);
                row.NewViolationCodes = row.CurrentViolationCodes.ToList();
                row.ChangeKinds.Add("endpoint");
                if (row.NewViolationCodes.Count > 0) {
                    row.ChangeKinds.Add("violations");
                }
                return row;
            }

            if (hasPrevious && !hasCurrent) {
                row.Status = "Removed";
                PopulatePrevious(row, before);
                row.ResolvedViolationCodes = row.PreviousViolationCodes.ToList();
                row.ChangeKinds.Add("endpoint");
                if (row.ResolvedViolationCodes.Count > 0) {
                    row.ChangeKinds.Add("violations");
                }
                return row;
            }

            row.Status = "Unchanged";
            PopulatePrevious(row, before);
            PopulateCurrent(row, after);
            BuildChangeDetails(row);
            if (row.ChangeKinds.Count > 0) {
                row.Status = "Changed";
            }

            return row;
        }

        private static void PopulatePrevious(CertificateInventoryEndpointPolicyDrift row, CertificateInventoryEndpointPolicy? endpoint) {
            if (endpoint == null) {
                return;
            }

            row.PreviousCompliant = endpoint.Compliant;
            row.PreviousViolationCount = endpoint.ViolationCount;
            row.PreviousMaxViolationSeverity = endpoint.MaxViolationSeverity;
            row.PreviousRiskScore = endpoint.RiskScore;
            row.PreviousRiskSeverity = endpoint.RiskSeverity;
            row.PreviousIssuer = endpoint.Issuer;
            row.PreviousNotAfterUtc = endpoint.NotAfterUtc;
            row.PreviousViolationCodes = endpoint.Violations
                .Select(violation => violation.Code)
                .Where(code => !string.IsNullOrWhiteSpace(code))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(code => code, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private static void PopulateCurrent(CertificateInventoryEndpointPolicyDrift row, CertificateInventoryEndpointPolicy? endpoint) {
            if (endpoint == null) {
                return;
            }

            row.CurrentCompliant = endpoint.Compliant;
            row.CurrentViolationCount = endpoint.ViolationCount;
            row.CurrentMaxViolationSeverity = endpoint.MaxViolationSeverity;
            row.CurrentRiskScore = endpoint.RiskScore;
            row.CurrentRiskSeverity = endpoint.RiskSeverity;
            row.CurrentIssuer = endpoint.Issuer;
            row.CurrentNotAfterUtc = endpoint.NotAfterUtc;
            row.CurrentViolationCodes = endpoint.Violations
                .Select(violation => violation.Code)
                .Where(code => !string.IsNullOrWhiteSpace(code))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(code => code, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private static void BuildChangeDetails(CertificateInventoryEndpointPolicyDrift row) {
            var previousCodeSet = new HashSet<string>(row.PreviousViolationCodes, StringComparer.OrdinalIgnoreCase);
            var currentCodeSet = new HashSet<string>(row.CurrentViolationCodes, StringComparer.OrdinalIgnoreCase);

            row.NewViolationCodes = row.CurrentViolationCodes
                .Where(code => !previousCodeSet.Contains(code))
                .OrderBy(code => code, StringComparer.OrdinalIgnoreCase)
                .ToList();
            row.ResolvedViolationCodes = row.PreviousViolationCodes
                .Where(code => !currentCodeSet.Contains(code))
                .OrderBy(code => code, StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (row.PreviousCompliant != row.CurrentCompliant) {
                row.ChangeKinds.Add("compliance");
            }

            if (row.PreviousViolationCount != row.CurrentViolationCount ||
                row.NewViolationCodes.Count > 0 ||
                row.ResolvedViolationCodes.Count > 0) {
                row.ChangeKinds.Add("violations");
            }

            if (!string.Equals(row.PreviousMaxViolationSeverity, row.CurrentMaxViolationSeverity, StringComparison.OrdinalIgnoreCase)) {
                row.ChangeKinds.Add("severity");
            }

            if (row.PreviousRiskScore != row.CurrentRiskScore ||
                !string.Equals(row.PreviousRiskSeverity, row.CurrentRiskSeverity, StringComparison.OrdinalIgnoreCase)) {
                row.ChangeKinds.Add("risk");
            }

            if (!string.Equals(row.PreviousIssuer, row.CurrentIssuer, StringComparison.OrdinalIgnoreCase)) {
                row.ChangeKinds.Add("issuer");
            }

            if (!Nullable.Equals(row.PreviousNotAfterUtc, row.CurrentNotAfterUtc)) {
                row.ChangeKinds.Add("expiry");
            }
        }

        private static string BuildEndpointKey(CertificateInventoryEndpointPolicy endpoint) {
            return $"{endpoint.Host}:{endpoint.Port}";
        }

        private static int StatusOrder(string status) {
            if (string.Equals(status, "Added", StringComparison.OrdinalIgnoreCase)) {
                return 0;
            }
            if (string.Equals(status, "Changed", StringComparison.OrdinalIgnoreCase)) {
                return 1;
            }
            if (string.Equals(status, "Removed", StringComparison.OrdinalIgnoreCase)) {
                return 2;
            }

            return 3;
        }

        private static int GetSeverityRank(string? severity) {
            if (string.IsNullOrWhiteSpace(severity)) {
                return 0;
            }

            var key = severity!.Trim();
            return SeverityRanks.TryGetValue(key, out var rank) ? rank : 0;
        }

        private static void Increment(Dictionary<string, int> counters, string key) {
            if (string.IsNullOrWhiteSpace(key)) {
                return;
            }

            counters[key] = counters.TryGetValue(key, out var count) ? count + 1 : 1;
        }
    }
}
