using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective {
    /// <summary>
    /// Explicit violation codes returned by <see cref="CertificateInventoryPolicyAnalyzer"/>.
    /// </summary>
    public static class CertificateInventoryPolicyViolationCodes {
        public const string EndpointUnreachable = "Policy.Endpoint.Unreachable";
        public const string CertificateNotYetValid = "Policy.Certificate.NotYetValid";
        public const string CertificateExpired = "Policy.Certificate.Expired";
        public const string CertificateExpiringSoon = "Policy.Certificate.ExpiringSoon";
        public const string CertificateValidationFailed = "Policy.Certificate.ValidationFailed";
        public const string ChainIncomplete = "Policy.Certificate.ChainIncomplete";
        public const string HostnameMismatch = "Policy.Certificate.HostnameMismatch";
        public const string MissingServerAuthEku = "Policy.Certificate.MissingServerAuthEku";
        public const string ClientAuthEkuPresent = "Policy.Certificate.ClientAuthEkuPresent";
        public const string SecureEmailEkuPresent = "Policy.Certificate.SecureEmailEkuPresent";
        public const string SelfSignedCertificate = "Policy.Certificate.SelfSigned";
        public const string WeakKey = "Policy.Certificate.WeakKey";
        public const string Sha1Signature = "Policy.Certificate.Sha1Signature";
        public const string UnknownAuthority = "Policy.Certificate.UnknownAuthority";
        public const string UnknownRootAuthority = "Policy.Certificate.UnknownRootAuthority";
        public const string CtNotObserved = "Policy.Certificate.CtNotObserved";
        public const string ReuseEndpointFanout = "Policy.Certificate.Reuse.EndpointFanout";
        public const string ReuseCrossService = "Policy.Certificate.Reuse.CrossService";
        public const string ReuseCrossPort = "Policy.Certificate.Reuse.CrossPort";
    }

    /// <summary>
    /// Policy posture summary over persisted certificate inventory snapshots.
    /// </summary>
    public sealed class CertificateInventoryPolicySummary {
        public string BaselineProfile { get; set; } = "Balanced";
        public int SnapshotCount { get; set; }
        public int EndpointCount { get; set; }
        /// <summary>Number of endpoint rows matching include/exclude filters before max-endpoint limiting.</summary>
        public int MatchedEndpointCount { get; set; }
        /// <summary>Number of matched endpoint rows omitted by max-endpoint limiting.</summary>
        public int EndpointsTruncatedByMaxEndpoints { get; set; }
        /// <summary>True when matched endpoint rows were truncated by max-endpoint limiting.</summary>
        public bool Truncated { get; set; }
        public int ViolationEndpointCount { get; set; }
        public int CompliantEndpointCount { get; set; }
        public int TotalViolationCount { get; set; }
        public int CriticalViolationCount { get; set; }
        public int HighViolationCount { get; set; }
        public int MediumViolationCount { get; set; }
        public int LowViolationCount { get; set; }
        public Dictionary<string, int> ViolationCodeCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public List<CertificateInventoryEndpointPolicy> Endpoints { get; set; } = new();
    }

    /// <summary>
    /// Endpoint-level policy details.
    /// </summary>
    public sealed class CertificateInventoryEndpointPolicy {
        public string Host { get; set; } = string.Empty;
        public int Port { get; set; }
        public string Service { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public string RootIssuer { get; set; } = string.Empty;
        public DateTimeOffset? NotBeforeUtc { get; set; }
        public DateTimeOffset? NotAfterUtc { get; set; }
        public int? DaysUntilValid { get; set; }
        public int? DaysToExpire { get; set; }
        public int RiskScore { get; set; }
        public string RiskSeverity { get; set; } = "None";
        public bool Valid { get; set; }
        public bool Expired { get; set; }
        public bool NotYetValid { get; set; }
        public bool ChainComplete { get; set; }
        public bool HostnameMatch { get; set; }
        public bool IsReachable { get; set; }
        public bool IsSelfSigned { get; set; }
        public bool IsKnownCertificateAuthority { get; set; }
        public bool IsKnownRootCertificateAuthority { get; set; }
        public bool PresentInCtLogs { get; set; }
        public bool WeakKey { get; set; }
        public bool Sha1Signature { get; set; }
        public bool AllowsServerAuthentication { get; set; }
        public bool AllowsClientAuthentication { get; set; }
        public bool AllowsSecureEmail { get; set; }
        public string AuthenticationProfile { get; set; } = string.Empty;
        public int CertificateReuseEndpointCount { get; set; }
        public int CertificateReuseDistinctServiceCount { get; set; }
        public int CertificateReuseDistinctPortCount { get; set; }
        public bool Compliant { get; set; }
        public int ViolationCount { get; set; }
        public string MaxViolationSeverity { get; set; } = "None";
        public List<string> RiskReasons { get; set; } = new();
        public List<CertificateInventoryPolicyViolation> Violations { get; set; } = new();
    }

    /// <summary>
    /// A single policy violation for one endpoint.
    /// </summary>
    public sealed class CertificateInventoryPolicyViolation {
        public string Code { get; set; } = string.Empty;
        public string Severity { get; set; } = "Low";
        public string Message { get; set; } = string.Empty;
    }

    /// <summary>
    /// Evaluates certificate inventory endpoints against baseline policy profiles.
    /// </summary>
    public static class CertificateInventoryPolicyAnalyzer {
        private sealed class BaselineProfileDefinition {
            public int RenewalWindowDays { get; init; }
            public int MaxReuseEndpointCount { get; init; }
            public string ExpiringSoonSeverity { get; init; } = "Medium";
            public string ReuseEndpointFanoutSeverity { get; init; } = "Medium";
            public string CrossReuseSeverity { get; init; } = "Medium";
            public bool FlagUnknownAuthority { get; init; }
            public bool FlagUnknownRootAuthority { get; init; }
            public bool RequireCtForKnownAuthority { get; init; }
            public bool FlagClientAuthUsage { get; init; }
            public bool FlagSecureEmailUsage { get; init; }
            public bool FlagCrossServiceReuse { get; init; }
            public bool FlagCrossPortReuse { get; init; }
        }

        private static readonly Dictionary<string, BaselineProfileDefinition> BaselineProfileDefinitions =
            new(StringComparer.OrdinalIgnoreCase) {
                ["Strict"] = new BaselineProfileDefinition {
                    RenewalWindowDays = 45,
                    MaxReuseEndpointCount = 3,
                    ExpiringSoonSeverity = "Medium",
                    ReuseEndpointFanoutSeverity = "Medium",
                    CrossReuseSeverity = "Medium",
                    FlagUnknownAuthority = true,
                    FlagUnknownRootAuthority = true,
                    RequireCtForKnownAuthority = true,
                    FlagClientAuthUsage = true,
                    FlagSecureEmailUsage = true,
                    FlagCrossServiceReuse = true,
                    FlagCrossPortReuse = true
                },
                ["Balanced"] = new BaselineProfileDefinition {
                    RenewalWindowDays = 30,
                    MaxReuseEndpointCount = 5,
                    ExpiringSoonSeverity = "Low",
                    ReuseEndpointFanoutSeverity = "Low",
                    CrossReuseSeverity = "Low",
                    FlagUnknownAuthority = true,
                    FlagUnknownRootAuthority = false,
                    RequireCtForKnownAuthority = true,
                    FlagClientAuthUsage = false,
                    FlagSecureEmailUsage = false,
                    FlagCrossServiceReuse = true,
                    FlagCrossPortReuse = false
                },
                ["Legacy"] = new BaselineProfileDefinition {
                    RenewalWindowDays = 14,
                    MaxReuseEndpointCount = 10,
                    ExpiringSoonSeverity = "Low",
                    ReuseEndpointFanoutSeverity = "Low",
                    CrossReuseSeverity = "Low",
                    FlagUnknownAuthority = false,
                    FlagUnknownRootAuthority = false,
                    RequireCtForKnownAuthority = false,
                    FlagClientAuthUsage = false,
                    FlagSecureEmailUsage = false,
                    FlagCrossServiceReuse = false,
                    FlagCrossPortReuse = false
                }
            };

        private static readonly Dictionary<string, int> SeverityRanks =
            new(StringComparer.OrdinalIgnoreCase) {
                ["None"] = 0,
                ["Low"] = 1,
                ["Medium"] = 2,
                ["High"] = 3,
                ["Critical"] = 4
            };

        public static readonly string BaselineProfileAcceptedValues =
            string.Join(", ", BaselineProfileDefinitions.Keys);

        /// <summary>
        /// Attempts to resolve a baseline profile label to a known profile.
        /// Returns false for null/empty input and unrecognized labels.
        /// </summary>
        public static bool TryResolveBaselineProfile(string? baselineProfile, out string normalizedBaselineProfile) {
            normalizedBaselineProfile = string.Empty;
            if (baselineProfile == null) {
                return false;
            }

            var candidate = baselineProfile.Trim();
            if (candidate.Length == 0) {
                return false;
            }

            foreach (var profile in BaselineProfileDefinitions.Keys) {
                if (string.Equals(profile, candidate, StringComparison.OrdinalIgnoreCase)) {
                    normalizedBaselineProfile = profile;
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Builds endpoint-level policy posture from persisted inventory snapshots.
        /// </summary>
        public static CertificateInventoryPolicySummary BuildPolicy(
            IEnumerable<CertificateInventorySnapshot>? snapshots,
            string? baselineProfile = "Balanced",
            bool includeCompliant = false,
            int maxEndpoints = 300) {
            if (maxEndpoints < 0) {
                throw new ArgumentOutOfRangeException(nameof(maxEndpoints), "maxEndpoints must be 0 or greater.");
            }

            var effectiveProfile = string.IsNullOrWhiteSpace(baselineProfile) ? "Balanced" : baselineProfile!;
            if (!TryResolveBaselineProfile(effectiveProfile, out var normalizedBaselineProfile)) {
                throw new ArgumentException($"baselineProfile must be one of: {BaselineProfileAcceptedValues}.", nameof(baselineProfile));
            }

            var profile = BaselineProfileDefinitions[normalizedBaselineProfile];
            var risk = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                maxEndpoints: int.MaxValue);

            var summary = new CertificateInventoryPolicySummary {
                BaselineProfile = normalizedBaselineProfile,
                SnapshotCount = risk.SnapshotCount,
                EndpointCount = risk.EndpointCount
            };

            var rows = new List<CertificateInventoryEndpointPolicy>(risk.Endpoints.Count);
            foreach (var endpoint in risk.Endpoints) {
                var row = EvaluateEndpoint(endpoint, profile);

                if (!row.Compliant) {
                    summary.ViolationEndpointCount++;
                    foreach (var violation in row.Violations) {
                        Increment(summary.ViolationCodeCounts, violation.Code);
                        IncrementSeverity(summary, violation.Severity);
                        summary.TotalViolationCount++;
                    }
                }

                if (includeCompliant || !row.Compliant) {
                    rows.Add(row);
                }
            }

            summary.CompliantEndpointCount = Math.Max(0, summary.EndpointCount - summary.ViolationEndpointCount);
            summary.MatchedEndpointCount = rows.Count;
            summary.EndpointsTruncatedByMaxEndpoints = Math.Max(0, summary.MatchedEndpointCount - maxEndpoints);
            summary.Truncated = summary.EndpointsTruncatedByMaxEndpoints > 0;
            summary.Endpoints = rows
                .OrderByDescending(row => GetSeverityRank(row.MaxViolationSeverity))
                .ThenByDescending(row => row.ViolationCount)
                .ThenByDescending(row => row.RiskScore)
                .ThenBy(row => row.DaysUntilValid ?? int.MaxValue)
                .ThenBy(row => row.DaysToExpire ?? int.MaxValue)
                .ThenBy(row => row.Host, StringComparer.OrdinalIgnoreCase)
                .ThenBy(row => row.Port)
                .Take(maxEndpoints)
                .ToList();

            return summary;
        }

        private static CertificateInventoryEndpointPolicy EvaluateEndpoint(
            CertificateInventoryEndpointRisk endpoint,
            BaselineProfileDefinition profile) {
            var row = new CertificateInventoryEndpointPolicy {
                Host = endpoint.Host,
                Port = endpoint.Port,
                Service = endpoint.Service,
                Issuer = endpoint.Issuer,
                RootIssuer = endpoint.RootIssuer,
                NotBeforeUtc = endpoint.NotBeforeUtc,
                NotAfterUtc = endpoint.NotAfterUtc,
                DaysUntilValid = endpoint.DaysUntilValid,
                DaysToExpire = endpoint.DaysToExpire,
                RiskScore = endpoint.Score,
                RiskSeverity = endpoint.Severity,
                Valid = endpoint.Valid,
                Expired = endpoint.Expired,
                NotYetValid = endpoint.NotYetValid,
                ChainComplete = endpoint.ChainComplete,
                HostnameMatch = endpoint.HostnameMatch,
                IsReachable = endpoint.IsReachable,
                IsSelfSigned = endpoint.IsSelfSigned,
                IsKnownCertificateAuthority = endpoint.IsKnownCertificateAuthority,
                IsKnownRootCertificateAuthority = endpoint.IsKnownRootCertificateAuthority,
                PresentInCtLogs = endpoint.PresentInCtLogs,
                WeakKey = endpoint.WeakKey,
                Sha1Signature = endpoint.Sha1Signature,
                AllowsServerAuthentication = endpoint.AllowsServerAuthentication,
                AllowsClientAuthentication = endpoint.AllowsClientAuthentication,
                AllowsSecureEmail = endpoint.AllowsSecureEmail,
                AuthenticationProfile = endpoint.AuthenticationProfile,
                CertificateReuseEndpointCount = endpoint.CertificateReuseEndpointCount,
                CertificateReuseDistinctServiceCount = endpoint.CertificateReuseDistinctServiceCount,
                CertificateReuseDistinctPortCount = endpoint.CertificateReuseDistinctPortCount,
                RiskReasons = endpoint.Reasons.ToList()
            };

            if (!row.IsReachable) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.EndpointUnreachable,
                    "Critical",
                    "Endpoint is unreachable during certificate collection.");
            }

            if (row.NotYetValid) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.CertificateNotYetValid,
                    "Critical",
                    "Certificate validity window starts in the future.");
            }

            if (row.Expired) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.CertificateExpired,
                    "Critical",
                    "Certificate is expired.");
            } else if (row.DaysToExpire.HasValue && row.DaysToExpire.Value >= 0 && row.DaysToExpire.Value <= profile.RenewalWindowDays) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.CertificateExpiringSoon,
                    profile.ExpiringSoonSeverity,
                    $"Certificate expires within {profile.RenewalWindowDays} days.");
            }

            if (!row.Valid && row.IsReachable) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.CertificateValidationFailed,
                    "High",
                    "Certificate validation failed for reachable endpoint.");
            }

            if (!row.ChainComplete && row.IsReachable && !row.IsSelfSigned) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.ChainIncomplete,
                    "High",
                    "Certificate chain appears incomplete.");
            }

            if (!row.HostnameMatch && row.IsReachable) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.HostnameMismatch,
                    "High",
                    "Certificate subject/SAN does not match requested hostname.");
            }

            if (!row.AllowsServerAuthentication && row.IsReachable) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.MissingServerAuthEku,
                    "High",
                    "Certificate is missing Server Authentication EKU usage.");
            }

            if (row.IsSelfSigned) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.SelfSignedCertificate,
                    "High",
                    "Endpoint uses a self-signed certificate.");
            }

            if (row.WeakKey) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.WeakKey,
                    "High",
                    "Certificate key strength is below policy expectations.");
            }

            if (row.Sha1Signature) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.Sha1Signature,
                    "High",
                    "Certificate uses SHA-1 signature algorithm.");
            }

            if (profile.FlagUnknownAuthority && row.IsReachable && !row.IsSelfSigned && !row.IsKnownCertificateAuthority) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.UnknownAuthority,
                    "Medium",
                    "Certificate issuer is not recognized as a known public CA.");
            }

            if (profile.FlagUnknownRootAuthority && row.IsReachable && !row.IsSelfSigned && !row.IsKnownRootCertificateAuthority) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.UnknownRootAuthority,
                    "Medium",
                    "Certificate root issuer is not recognized as a known public root CA.");
            }

            if (profile.RequireCtForKnownAuthority && row.IsReachable && row.IsKnownCertificateAuthority && !row.PresentInCtLogs) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.CtNotObserved,
                    "Medium",
                    "Certificate was not observed in certificate transparency sources.");
            }

            if (profile.FlagClientAuthUsage && row.AllowsClientAuthentication) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.ClientAuthEkuPresent,
                    "Medium",
                    "Certificate allows Client Authentication EKU under strict baseline.");
            }

            if (profile.FlagSecureEmailUsage && row.AllowsSecureEmail) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.SecureEmailEkuPresent,
                    "Low",
                    "Certificate allows Secure Email EKU under strict baseline.");
            }

            if (row.CertificateReuseEndpointCount > profile.MaxReuseEndpointCount) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.ReuseEndpointFanout,
                    profile.ReuseEndpointFanoutSeverity,
                    $"Certificate is reused by {row.CertificateReuseEndpointCount} endpoints (policy max {profile.MaxReuseEndpointCount}).");
            }

            if (profile.FlagCrossServiceReuse && row.CertificateReuseDistinctServiceCount > 1) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.ReuseCrossService,
                    profile.CrossReuseSeverity,
                    "Certificate is reused across multiple services.");
            }

            if (profile.FlagCrossPortReuse && row.CertificateReuseDistinctPortCount > 1) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.ReuseCrossPort,
                    profile.CrossReuseSeverity,
                    "Certificate is reused across multiple ports.");
            }

            row.ViolationCount = row.Violations.Count;
            row.MaxViolationSeverity = PickMaxSeverity(row.Violations);
            row.Compliant = row.ViolationCount == 0;
            return row;
        }

        private static void AddViolation(
            List<CertificateInventoryPolicyViolation> violations,
            string code,
            string severity,
            string message) {
            if (violations.Any(existing => string.Equals(existing.Code, code, StringComparison.OrdinalIgnoreCase))) {
                return;
            }

            violations.Add(new CertificateInventoryPolicyViolation {
                Code = code,
                Severity = NormalizeSeverity(severity),
                Message = message
            });
        }

        private static string PickMaxSeverity(IEnumerable<CertificateInventoryPolicyViolation> violations) {
            var maxSeverity = "None";
            var maxRank = 0;
            foreach (var violation in violations ?? Enumerable.Empty<CertificateInventoryPolicyViolation>()) {
                var severity = NormalizeSeverity(violation.Severity);
                var rank = GetSeverityRank(severity);
                if (rank > maxRank) {
                    maxRank = rank;
                    maxSeverity = severity;
                }
            }

            return maxSeverity;
        }

        private static string NormalizeSeverity(string? severity) {
            if (string.IsNullOrWhiteSpace(severity)) {
                return "Low";
            }

            foreach (var key in SeverityRanks.Keys) {
                if (string.Equals(key, severity, StringComparison.OrdinalIgnoreCase)) {
                    return key;
                }
            }

            return "Low";
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

        private static void IncrementSeverity(CertificateInventoryPolicySummary summary, string severity) {
            if (string.Equals(severity, "Critical", StringComparison.OrdinalIgnoreCase)) {
                summary.CriticalViolationCount++;
            } else if (string.Equals(severity, "High", StringComparison.OrdinalIgnoreCase)) {
                summary.HighViolationCount++;
            } else if (string.Equals(severity, "Medium", StringComparison.OrdinalIgnoreCase)) {
                summary.MediumViolationCount++;
            } else {
                summary.LowViolationCount++;
            }
        }
    }
}
