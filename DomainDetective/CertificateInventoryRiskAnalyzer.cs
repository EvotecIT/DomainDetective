using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective {
    /// <summary>
    /// Risk posture summary over persisted certificate inventory snapshots.
    /// </summary>
    public sealed class CertificateInventoryRiskSummary {
        public int SnapshotCount { get; set; }
        public int EndpointCount { get; set; }
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public int MediumCount { get; set; }
        public int LowCount { get; set; }
        public int NoRiskCount { get; set; }
        public double AverageScore { get; set; }
        public Dictionary<string, int> ReasonCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public List<CertificateInventoryEndpointRisk> Endpoints { get; set; } = new();
    }

    /// <summary>
    /// Endpoint-level certificate risk details.
    /// </summary>
    public sealed class CertificateInventoryEndpointRisk {
        public string Host { get; set; } = string.Empty;
        public int Port { get; set; }
        public string Service { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public string RootIssuer { get; set; } = string.Empty;
        /// <summary>Certificate validity start timestamp from the observed endpoint certificate.</summary>
        public DateTimeOffset? NotBeforeUtc { get; set; }
        public DateTimeOffset? NotAfterUtc { get; set; }
        public int? DaysToExpire { get; set; }
        public int Score { get; set; }
        public string Severity { get; set; } = "None";
        public bool Valid { get; set; }
        public bool Expired { get; set; }
        /// <summary>
        /// True when <see cref="NotBeforeUtc"/> is in the future at risk-evaluation time.
        /// This is derived from timestamps and does not rely on the persisted <see cref="Valid"/> flag.
        /// </summary>
        public bool NotYetValid { get; set; }
        public bool ChainComplete { get; set; }
        public bool HostnameMatch { get; set; }
        public bool IsReachable { get; set; }
        public bool IsSelfSigned { get; set; }
        public bool IsKnownCertificateAuthority { get; set; }
        public bool AllowsServerAuthentication { get; set; }
        public bool WeakKey { get; set; }
        public bool Sha1Signature { get; set; }
        public bool PresentInCtLogs { get; set; }
        public List<string> Reasons { get; set; } = new();
    }

    /// <summary>
    /// Computes endpoint-level risk posture from persisted inventory snapshots.
    /// </summary>
    public static class CertificateInventoryRiskAnalyzer {
        private sealed class LatestEntryState {
            public DateTimeOffset CapturedAtUtc { get; init; }
            public CertificateInventoryEntry Entry { get; init; } = null!;
        }

        public static CertificateInventoryRiskSummary BuildRisk(
            IEnumerable<CertificateInventorySnapshot>? snapshots,
            bool includeNoRisk = false,
            int expiringWithinDays = 30,
            int criticalExpiringWithinDays = 7,
            int maxEndpoints = 300) {
            var summary = new CertificateInventoryRiskSummary();
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
            var now = DateTimeOffset.UtcNow;
            var normalizedExpiringDays = Math.Max(0, expiringWithinDays);
            var normalizedCriticalDays = Math.Max(0, criticalExpiringWithinDays);
            if (normalizedCriticalDays > normalizedExpiringDays) {
                normalizedCriticalDays = normalizedExpiringDays;
            }

            var rows = new List<CertificateInventoryEndpointRisk>(latestByEndpoint.Count);
            var totalScore = 0d;
            foreach (var latest in latestByEndpoint.Values) {
                var row = BuildEndpointRisk(latest.Entry, now, normalizedExpiringDays, normalizedCriticalDays);
                totalScore += row.Score;

                IncrementSeverity(summary, row.Severity);
                foreach (var reason in row.Reasons) {
                    Increment(summary.ReasonCounts, reason);
                }

                if (!includeNoRisk && row.Score <= 0) {
                    continue;
                }

                rows.Add(row);
            }

            if (summary.EndpointCount > 0) {
                summary.AverageScore = Math.Round(totalScore / summary.EndpointCount, 2);
            }

            summary.Endpoints = rows
                .OrderByDescending(row => row.Score)
                .ThenBy(row => row.DaysToExpire ?? int.MaxValue)
                .ThenBy(row => row.Host, StringComparer.OrdinalIgnoreCase)
                .ThenBy(row => row.Port)
                .Take(Math.Max(0, maxEndpoints))
                .ToList();

            return summary;
        }

        private static CertificateInventoryEndpointRisk BuildEndpointRisk(
            CertificateInventoryEntry entry,
            DateTimeOffset now,
            int expiringWithinDays,
            int criticalExpiringWithinDays) {
            var row = new CertificateInventoryEndpointRisk {
                Host = entry.ResolvedHost ?? entry.Host,
                Port = entry.Port > 0 ? entry.Port : 443,
                Service = string.IsNullOrWhiteSpace(entry.Service)
                    ? CertificateServiceClassifier.GuessService(entry.Scheme ?? "https", entry.Port)
                    : entry.Service!,
                Issuer = PickIssuer(entry),
                RootIssuer = PickRoot(entry),
                NotBeforeUtc = entry.NotBeforeUtc,
                NotAfterUtc = entry.NotAfterUtc,
                Valid = entry.Valid,
                Expired = entry.Expired,
                ChainComplete = entry.ChainComplete,
                HostnameMatch = entry.HostnameMatch,
                IsReachable = entry.IsReachable,
                IsSelfSigned = entry.IsSelfSigned,
                IsKnownCertificateAuthority = entry.IsKnownCertificateAuthority,
                AllowsServerAuthentication = entry.AllowsServerAuthentication,
                WeakKey = entry.WeakKey,
                Sha1Signature = entry.Sha1Signature,
                PresentInCtLogs = entry.PresentInCtLogs
            };

            var score = 0;
            if (!row.IsReachable) {
                score += 60;
                row.Reasons.Add("EndpointUnreachable");
            }

            if (row.NotBeforeUtc.HasValue && row.NotBeforeUtc.Value > now) {
                row.NotYetValid = true;
                score += 60;
                row.Reasons.Add("CertificateNotYetValid");
            }

            if (row.NotAfterUtc.HasValue) {
                row.DaysToExpire = (int)Math.Floor((row.NotAfterUtc.Value - now).TotalDays);
            }

            if (row.Expired || (row.NotAfterUtc.HasValue && row.NotAfterUtc.Value <= now)) {
                score += 100;
                row.Reasons.Add("CertificateExpired");
            } else if (row.DaysToExpire.HasValue) {
                if (row.DaysToExpire.Value <= criticalExpiringWithinDays) {
                    score += 50;
                    row.Reasons.Add("CertificateExpiringCritical");
                } else if (row.DaysToExpire.Value <= expiringWithinDays) {
                    score += 25;
                    row.Reasons.Add("CertificateExpiringSoon");
                }
            }

            // Keep the generic validation failure reason alongside specific root causes
            // (for example NotYetValid) so broad dashboards can still aggregate by validation.
            if (!row.Valid && row.IsReachable) {
                score += 45;
                row.Reasons.Add("CertificateValidationFailed");
            }

            if (!row.ChainComplete && row.IsReachable && !row.IsSelfSigned) {
                score += 35;
                row.Reasons.Add("ChainIncomplete");
            }

            if (!row.HostnameMatch && row.IsReachable) {
                score += 35;
                row.Reasons.Add("HostnameMismatch");
            }

            if (!row.AllowsServerAuthentication && row.IsReachable) {
                score += 40;
                row.Reasons.Add("MissingServerAuthEku");
            }

            if (row.IsSelfSigned) {
                score += 30;
                row.Reasons.Add("SelfSignedCertificate");
            }

            if (row.WeakKey) {
                score += 35;
                row.Reasons.Add("WeakKey");
            }

            if (row.Sha1Signature) {
                score += 40;
                row.Reasons.Add("Sha1Signature");
            }

            if (!row.IsKnownCertificateAuthority && !row.IsSelfSigned && row.IsReachable) {
                score += 10;
                row.Reasons.Add("UnknownAuthority");
            }

            if (!row.PresentInCtLogs && row.IsKnownCertificateAuthority && row.IsReachable) {
                score += 10;
                row.Reasons.Add("CtNotObserved");
            }

            row.Score = Math.Max(0, Math.Min(100, score));
            row.Severity = PickSeverity(row.Score);
            return row;
        }

        private static void Increment(Dictionary<string, int> counters, string key) {
            if (string.IsNullOrWhiteSpace(key)) {
                return;
            }

            counters[key] = counters.TryGetValue(key, out var count) ? count + 1 : 1;
        }

        private static void IncrementSeverity(CertificateInventoryRiskSummary summary, string severity) {
            if (string.Equals(severity, "Critical", StringComparison.OrdinalIgnoreCase)) {
                summary.CriticalCount++;
            } else if (string.Equals(severity, "High", StringComparison.OrdinalIgnoreCase)) {
                summary.HighCount++;
            } else if (string.Equals(severity, "Medium", StringComparison.OrdinalIgnoreCase)) {
                summary.MediumCount++;
            } else if (string.Equals(severity, "Low", StringComparison.OrdinalIgnoreCase)) {
                summary.LowCount++;
            } else {
                summary.NoRiskCount++;
            }
        }

        private static string PickSeverity(int score) {
            if (score >= 85) {
                return "Critical";
            }
            if (score >= 60) {
                return "High";
            }
            if (score >= 30) {
                return "Medium";
            }
            if (score > 0) {
                return "Low";
            }

            return "None";
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
            return "Unknown";
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
            return "Unknown";
        }
    }
}
