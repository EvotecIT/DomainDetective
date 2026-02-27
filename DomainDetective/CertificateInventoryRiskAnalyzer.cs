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
        /// <summary>Number of endpoints that matched row-level filters before max-endpoint limiting.</summary>
        public int MatchedEndpointCount { get; set; }
        /// <summary>Number of matched endpoints omitted because of max-endpoint limiting.</summary>
        public int EndpointsTruncatedByMaxEndpoints { get; set; }
        /// <summary>True when matched endpoint rows were truncated by max-endpoint limiting.</summary>
        public bool Truncated { get; set; }
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
        public string CertificateThumbprint { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public string RootIssuer { get; set; } = string.Empty;
        public string AuthorityFamily { get; set; } = string.Empty;
        public string RootAuthorityFamily { get; set; } = string.Empty;
        /// <summary>Certificate validity start timestamp in UTC from the observed endpoint certificate.</summary>
        public DateTimeOffset? NotBeforeUtc { get; set; }
        public DateTimeOffset? NotAfterUtc { get; set; }
        /// <summary>Days until certificate validity start when <see cref="NotYetValid"/> is true; otherwise null.</summary>
        public int? DaysUntilValid { get; set; }
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
        public bool AllowsClientAuthentication { get; set; }
        public bool AllowsSecureEmail { get; set; }
        public string AuthenticationProfile { get; set; } = CertificateAuthenticationProfileClassifier.NoEkuExtension;
        /// <summary>Primary chain source observed for this endpoint certificate (for example tls-handshake).</summary>
        public string ChainSource { get; set; } = string.Empty;
        /// <summary>Observed chain sources for this endpoint certificate (primary plus historical).</summary>
        public List<string> ChainSources { get; set; } = new();
        /// <summary>Observed CT/discovery sources (for example crt.sh, shodan, censys).</summary>
        public List<string> CtDiscoverySources { get; set; } = new();
        /// <summary>Observed CT template/configuration errors.</summary>
        public List<string> CtTemplateFormatErrors { get; set; } = new();
        public bool WeakKey { get; set; }
        public bool Sha1Signature { get; set; }
        public bool PresentInCtLogs { get; set; }
        public List<string> Reasons { get; set; } = new();
    }

    /// <summary>
    /// Computes endpoint-level risk posture from persisted inventory snapshots.
    /// </summary>
    public static class CertificateInventoryRiskAnalyzer {
        private static readonly IReadOnlyList<(string Name, int Score)> SeverityThresholds = new[] {
            ("None", 0),
            ("Low", 1),
            ("Medium", 30),
            ("High", 60),
            ("Critical", 85)
        };

        public static readonly string MinimumSeverityAcceptedValues =
            string.Join(", ", SeverityThresholds.Select(level => level.Name));

        private static readonly Dictionary<string, int> SeverityScoreThresholds =
            SeverityThresholds.ToDictionary(level => level.Name, level => level.Score, StringComparer.OrdinalIgnoreCase);

        private sealed class LatestEntryState {
            public DateTimeOffset CapturedAtUtc { get; init; }
            public CertificateInventoryEntry Entry { get; init; } = null!;
        }

        /// <summary>
        /// Attempts to resolve a severity label to its minimum score threshold.
        /// Returns false for null/empty input and unrecognized labels.
        /// </summary>
        public static bool TryResolveMinimumSeverity(string? severity, out int minimumScore, out string normalizedSeverity) {
            minimumScore = 0;
            normalizedSeverity = string.Empty;
            if (severity == null) {
                return false;
            }

            var candidate = severity.Trim();
            if (candidate.Length == 0) {
                return false;
            }

            foreach (var pair in SeverityScoreThresholds) {
                if (string.Equals(pair.Key, candidate, StringComparison.OrdinalIgnoreCase)) {
                    minimumScore = pair.Value;
                    normalizedSeverity = pair.Key;
                    return true;
                }
            }

            return false;
        }

        public static CertificateInventoryRiskSummary BuildRisk(
            IEnumerable<CertificateInventorySnapshot>? snapshots,
            bool includeNoRisk = false,
            int expiringWithinDays = 30,
            int criticalExpiringWithinDays = 7,
            int maxEndpoints = 300,
            string? minimumSeverity = null,
            string? reasonContains = null,
            string? issuerContains = null,
            string? authorityFamilyEquals = null,
            string? rootAuthorityFamilyEquals = null,
            string? ctSourceContains = null,
            string? ctTemplateErrorContains = null,
            string? chainSourceContains = null,
            string? thumbprintEquals = null,
            bool serverAuthOnly = false,
            bool clientAuthOnly = false,
            bool secureEmailOnly = false) {
            var summary = new CertificateInventoryRiskSummary();
            var latestByEndpoint = new Dictionary<string, LatestEntryState>(StringComparer.OrdinalIgnoreCase);
            var hasMinimumSeverity = TryResolveMinimumSeverity(minimumSeverity, out var minimumSeverityScore, out _);
            if (!string.IsNullOrWhiteSpace(minimumSeverity) && !hasMinimumSeverity) {
                throw new ArgumentException($"minimumSeverity must be one of: {MinimumSeverityAcceptedValues}.", nameof(minimumSeverity));
            }
            var hasReasonFilter = !string.IsNullOrWhiteSpace(reasonContains);
            var reasonNeedle = hasReasonFilter ? reasonContains!.Trim() : string.Empty;
            var hasIssuerFilter = !string.IsNullOrWhiteSpace(issuerContains);
            var issuerNeedle = hasIssuerFilter ? issuerContains!.Trim() : string.Empty;
            var hasAuthorityFamilyFilter = !string.IsNullOrWhiteSpace(authorityFamilyEquals);
            var authorityFamilyExpected = hasAuthorityFamilyFilter ? authorityFamilyEquals!.Trim() : string.Empty;
            var hasRootAuthorityFamilyFilter = !string.IsNullOrWhiteSpace(rootAuthorityFamilyEquals);
            var rootAuthorityFamilyExpected = hasRootAuthorityFamilyFilter ? rootAuthorityFamilyEquals!.Trim() : string.Empty;
            var hasCtSourceFilter = !string.IsNullOrWhiteSpace(ctSourceContains);
            var ctSourceNeedle = hasCtSourceFilter ? ctSourceContains!.Trim() : string.Empty;
            var hasCtTemplateErrorFilter = !string.IsNullOrWhiteSpace(ctTemplateErrorContains);
            var ctTemplateErrorNeedle = hasCtTemplateErrorFilter ? ctTemplateErrorContains!.Trim() : string.Empty;
            var hasChainSourceFilter = !string.IsNullOrWhiteSpace(chainSourceContains);
            var chainSourceNeedle = hasChainSourceFilter ? chainSourceContains!.Trim() : string.Empty;
            var hasThumbprintFilter = !string.IsNullOrWhiteSpace(thumbprintEquals);
            var thumbprintExpected = hasThumbprintFilter ? thumbprintEquals!.Trim() : string.Empty;
            // Intentionally keep includeNoRisk evaluation first; minimum severity then narrows rows further.
            // Example: includeNoRisk=true with minimumSeverity=Low still excludes score=0 endpoints.

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
                if (hasMinimumSeverity && row.Score < minimumSeverityScore) {
                    continue;
                }
                if (hasReasonFilter) {
                    // Like minimum severity, reason filtering only narrows returned endpoint rows.
                    // Summary counts/reason distributions stay computed across the full endpoint set.
                    var matchesReason = row.Reasons.Any(reason =>
                        reason.IndexOf(reasonNeedle, StringComparison.OrdinalIgnoreCase) >= 0);
                    if (!matchesReason) {
                        continue;
                    }
                }
                if (hasIssuerFilter) {
                    // Like minimum severity and reason filtering, issuer filtering only narrows returned endpoint rows.
                    // Summary counts/reason distributions stay computed across the full endpoint set.
                    var matchesIssuer =
                        row.Issuer.IndexOf(issuerNeedle, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        row.RootIssuer.IndexOf(issuerNeedle, StringComparison.OrdinalIgnoreCase) >= 0;
                    if (!matchesIssuer) {
                        continue;
                    }
                }
                if (hasAuthorityFamilyFilter) {
                    if (!string.Equals(row.AuthorityFamily, authorityFamilyExpected, StringComparison.OrdinalIgnoreCase)) {
                        continue;
                    }
                }
                if (hasRootAuthorityFamilyFilter) {
                    if (!string.Equals(row.RootAuthorityFamily, rootAuthorityFamilyExpected, StringComparison.OrdinalIgnoreCase)) {
                        continue;
                    }
                }
                // Source filters only narrow returned endpoint rows.
                // Summary counts/reason distributions stay computed across the full endpoint set.
                if (hasCtSourceFilter) {
                    var matchesCtSource = row.CtDiscoverySources.Any(source =>
                        source.IndexOf(ctSourceNeedle, StringComparison.OrdinalIgnoreCase) >= 0);
                    if (!matchesCtSource) {
                        continue;
                    }
                }
                if (hasCtTemplateErrorFilter) {
                    var matchesCtTemplateError = row.CtTemplateFormatErrors.Any(templateError =>
                        templateError.IndexOf(ctTemplateErrorNeedle, StringComparison.OrdinalIgnoreCase) >= 0);
                    if (!matchesCtTemplateError) {
                        continue;
                    }
                }
                if (hasChainSourceFilter) {
                    // Check primary source separately: ChainSources represents observed source history
                    // and may not include the primary ChainSource value.
                    var matchesChainSource =
                        row.ChainSource.IndexOf(chainSourceNeedle, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        row.ChainSources.Any(source =>
                            source.IndexOf(chainSourceNeedle, StringComparison.OrdinalIgnoreCase) >= 0);
                    if (!matchesChainSource) {
                        continue;
                    }
                }
                if (hasThumbprintFilter &&
                    !string.Equals(row.CertificateThumbprint, thumbprintExpected, StringComparison.OrdinalIgnoreCase)) {
                    continue;
                }
                // Auth-usage filters only narrow returned endpoint rows.
                // Summary counts/reason distributions stay computed across the full endpoint set.
                if (serverAuthOnly && !row.AllowsServerAuthentication) {
                    continue;
                }
                if (clientAuthOnly && !row.AllowsClientAuthentication) {
                    continue;
                }
                if (secureEmailOnly && !row.AllowsSecureEmail) {
                    continue;
                }

                rows.Add(row);
            }

            if (summary.EndpointCount > 0) {
                summary.AverageScore = Math.Round(totalScore / summary.EndpointCount, 2);
            }

            var normalizedMaxEndpoints = Math.Max(0, maxEndpoints);
            summary.MatchedEndpointCount = rows.Count;
            summary.EndpointsTruncatedByMaxEndpoints = Math.Max(0, summary.MatchedEndpointCount - normalizedMaxEndpoints);
            summary.Truncated = summary.EndpointsTruncatedByMaxEndpoints > 0;

            summary.Endpoints = rows
                .OrderByDescending(row => row.Score)
                .ThenBy(row => row.DaysUntilValid ?? int.MaxValue)
                .ThenBy(row => row.DaysToExpire ?? int.MaxValue)
                .ThenBy(row => row.Host, StringComparer.OrdinalIgnoreCase)
                .ThenBy(row => row.Port)
                .Take(normalizedMaxEndpoints)
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
                CertificateThumbprint = entry.CertificateThumbprint?.Trim() ?? string.Empty,
                Issuer = PickIssuer(entry),
                RootIssuer = PickRoot(entry),
                AuthorityFamily = entry.CertificateAuthorityFamily ?? string.Empty,
                RootAuthorityFamily = entry.CertificateRootAuthorityFamily ?? string.Empty,
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
                AllowsClientAuthentication = entry.AllowsClientAuthentication,
                AllowsSecureEmail = entry.AllowsSecureEmail,
                AuthenticationProfile = CertificateInventoryEntryHelpers.ResolveAuthenticationProfile(entry),
                ChainSource = entry.CertificateChainSource?.Trim() ?? string.Empty,
                ChainSources = NormalizeDistinctValues(entry.CertificateChainSources),
                CtDiscoverySources = NormalizeDistinctValues(entry.CtDiscoverySources),
                CtTemplateFormatErrors = NormalizeDistinctValues(entry.CtTemplateFormatErrors),
                WeakKey = entry.WeakKey,
                Sha1Signature = entry.Sha1Signature,
                PresentInCtLogs = entry.PresentInCtLogs
            };

            var score = 0;
            if (!row.IsReachable) {
                score += 60;
                row.Reasons.Add("EndpointUnreachable");
            }

            // Derive this from timestamps so future-dated certificates are flagged consistently,
            // even when upstream snapshots incorrectly persist Valid=true.
            if (row.NotBeforeUtc.HasValue && row.NotBeforeUtc.Value > now) {
                row.NotYetValid = true;
                row.DaysUntilValid = Math.Max(0, (int)Math.Ceiling((row.NotBeforeUtc.Value - now).TotalDays));
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

        private static List<string> NormalizeDistinctValues(IEnumerable<string>? values) {
            if (values == null) {
                return new List<string>();
            }

            return values
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => value.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
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
