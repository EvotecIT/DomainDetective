using System;
using System.Collections.Generic;
using System.Globalization;
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
        /// <summary>Number of distinct certificate identities observed across latest endpoints.</summary>
        public int UniqueCertificateIdentityCount { get; set; }
        /// <summary>Number of distinct certificate identities used by more than one endpoint.</summary>
        public int ReusedCertificateIdentityCount { get; set; }
        /// <summary>Percentage of distinct certificate identities reused by more than one endpoint.</summary>
        public double ReusedCertificateIdentityPercentage { get; set; }
        /// <summary>Number of endpoints whose certificate identity is reused by at least one other endpoint.</summary>
        public int EndpointsWithReusedCertificateCount { get; set; }
        /// <summary>Percentage of endpoints whose certificate identity is reused by at least one other endpoint.</summary>
        public double EndpointsWithReusedCertificatePercentage { get; set; }
        /// <summary>Number of distinct certificate identities reused across more than one distinct service.</summary>
        public int CrossServiceReusedCertificateIdentityCount { get; set; }
        /// <summary>Percentage of distinct certificate identities reused across more than one distinct service.</summary>
        public double CrossServiceReusedCertificateIdentityPercentage { get; set; }
        /// <summary>Number of distinct certificate identities reused across more than one distinct port.</summary>
        public int CrossPortReusedCertificateIdentityCount { get; set; }
        /// <summary>Percentage of distinct certificate identities reused across more than one distinct port.</summary>
        public double CrossPortReusedCertificateIdentityPercentage { get; set; }
        /// <summary>Number of endpoints whose certificate identity is reused across more than one distinct service.</summary>
        public int EndpointsWithCrossServiceReuseCount { get; set; }
        /// <summary>Percentage of endpoints whose certificate identity is reused across more than one distinct service.</summary>
        public double EndpointsWithCrossServiceReusePercentage { get; set; }
        /// <summary>Number of endpoints whose certificate identity is reused across more than one distinct port.</summary>
        public int EndpointsWithCrossPortReuseCount { get; set; }
        /// <summary>Percentage of endpoints whose certificate identity is reused across more than one distinct port.</summary>
        public double EndpointsWithCrossPortReusePercentage { get; set; }
        /// <summary>Maximum endpoint fan-out observed for a single certificate identity.</summary>
        public int MaxCertificateReuseEndpointCount { get; set; }
        /// <summary>Maximum distinct service spread observed for a single certificate identity.</summary>
        public int MaxCertificateReuseDistinctServiceCount { get; set; }
        /// <summary>Maximum distinct port spread observed for a single certificate identity.</summary>
        public int MaxCertificateReuseDistinctPortCount { get; set; }
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
        public string CertificateRootThumbprint { get; set; } = string.Empty;
        public string CertificateSerialNumber { get; set; } = string.Empty;
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
        public int ChainLength { get; set; }
        public int IntermediateCount { get; set; }
        public bool HostnameMatch { get; set; }
        public bool IsReachable { get; set; }
        public bool IsSelfSigned { get; set; }
        public bool IsKnownCertificateAuthority { get; set; }
        public bool IsKnownRootCertificateAuthority { get; set; }
        /// <summary>How many endpoints currently reuse the same certificate identity.</summary>
        public int CertificateReuseEndpointCount { get; set; }
        /// <summary>How many distinct services currently reuse the same certificate identity.</summary>
        public int CertificateReuseDistinctServiceCount { get; set; }
        /// <summary>How many distinct ports currently reuse the same certificate identity.</summary>
        public int CertificateReuseDistinctPortCount { get; set; }
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
    public static partial class CertificateInventoryRiskAnalyzer {
        private static readonly IReadOnlyList<(string Name, int Score)> SeverityThresholds = new[] {
            ("None", 0),
            ("Low", 1),
            ("Medium", 30),
            ("High", 60),
            ("Critical", 85)
        };

        private sealed class RiskProfileDefaults {
            public string? MinimumSeverity { get; init; }
            public bool? ExpiredOnly { get; init; }
            public bool? NotYetValidOnly { get; init; }
            public bool? CurrentlyValidOnly { get; init; }
            public int? DaysToExpireMin { get; init; }
            public int? DaysToExpireMax { get; init; }
            public int? DaysUntilValidMin { get; init; }
            public int? DaysUntilValidMax { get; init; }
        }

        private static readonly Dictionary<string, RiskProfileDefaults> RiskProfileDefinitions =
            new(StringComparer.OrdinalIgnoreCase) {
                ["Renewal14d"] = new RiskProfileDefaults {
                    CurrentlyValidOnly = true,
                    DaysToExpireMin = 0,
                    DaysToExpireMax = 14
                },
                ["Renewal30d"] = new RiskProfileDefaults {
                    CurrentlyValidOnly = true,
                    DaysToExpireMin = 0,
                    DaysToExpireMax = 30
                },
                ["FutureNotYetValid"] = new RiskProfileDefaults {
                    NotYetValidOnly = true,
                    DaysUntilValidMin = 0
                },
                ["Expired"] = new RiskProfileDefaults {
                    ExpiredOnly = true
                },
                ["HighRiskActive"] = new RiskProfileDefaults {
                    CurrentlyValidOnly = true,
                    MinimumSeverity = "High"
                }
            };

        public static readonly string MinimumSeverityAcceptedValues =
            string.Join(", ", SeverityThresholds.Select(level => level.Name));

        public static readonly string RiskProfileAcceptedValues =
            string.Join(", ", RiskProfileDefinitions.Keys);

        private static readonly Dictionary<string, int> SeverityScoreThresholds =
            SeverityThresholds.ToDictionary(level => level.Name, level => level.Score, StringComparer.OrdinalIgnoreCase);

        private sealed class LatestEntryState {
            public DateTimeOffset CapturedAtUtc { get; init; }
            public CertificateInventoryEntry Entry { get; init; } = null!;
        }

        private sealed class CertificateReuseStats {
            public int EndpointCount { get; init; }
            public int DistinctServiceCount { get; init; }
            public int DistinctPortCount { get; init; }
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

        /// <summary>
        /// Attempts to resolve a risk profile label to a known profile.
        /// Returns false for null/empty input and unrecognized labels.
        /// </summary>
        public static bool TryResolveRiskProfile(string? riskProfile, out string normalizedRiskProfile) {
            normalizedRiskProfile = string.Empty;
            if (riskProfile == null) {
                return false;
            }

            var candidate = riskProfile.Trim();
            if (candidate.Length == 0) {
                return false;
            }

            foreach (var profile in RiskProfileDefinitions.Keys) {
                if (string.Equals(profile, candidate, StringComparison.OrdinalIgnoreCase)) {
                    normalizedRiskProfile = profile;
                    return true;
                }
            }

            return false;
        }

    }
}
