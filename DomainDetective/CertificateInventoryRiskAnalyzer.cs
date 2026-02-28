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
    public static class CertificateInventoryRiskAnalyzer {
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

        public static CertificateInventoryRiskSummary BuildRisk(
            IEnumerable<CertificateInventorySnapshot>? snapshots,
            bool includeNoRisk = false,
            int expiringWithinDays = 30,
            int criticalExpiringWithinDays = 7,
            int maxEndpoints = 300,
            string? minimumSeverity = null,
            int? scoreMin = null,
            int? scoreMax = null,
            int? reasonCountMin = null,
            int? reasonCountMax = null,
            string? riskProfile = null,
            string? reasonContains = null,
            string? issuerContains = null,
            string? authorityFamilyEquals = null,
            string? rootAuthorityFamilyEquals = null,
            string? ctSourceContains = null,
            string? ctTemplateErrorContains = null,
            string? chainSourceContains = null,
            string? thumbprintEquals = null,
            string? rootThumbprintEquals = null,
            string? serialNumberEquals = null,
            string? hostContains = null,
            string? serviceEquals = null,
            int? portEquals = null,
            int? chainLengthMin = null,
            int? chainLengthMax = null,
            int? intermediateCountMin = null,
            int? intermediateCountMax = null,
            bool? ctObservedOnly = null,
            bool? chainCompleteOnly = null,
            bool? reachableOnly = null,
            bool? hostnameMatchOnly = null,
            bool? selfSignedOnly = null,
            bool? weakKeyOnly = null,
            bool? sha1SignatureOnly = null,
            bool? expiredOnly = null,
            bool? notYetValidOnly = null,
            bool? currentlyValidOnly = null,
            int? daysToExpireMin = null,
            int? daysToExpireMax = null,
            int? daysUntilValidMin = null,
            int? daysUntilValidMax = null,
            bool? knownAuthorityOnly = null,
            bool? knownRootAuthorityOnly = null,
            string? authenticationProfileEquals = null,
            bool serverAuthOnly = false,
            bool clientAuthOnly = false,
            bool secureEmailOnly = false,
            string[]? reasonAnyOf = null,
            string[]? reasonAllOf = null,
            string[]? issuerContainsAnyOf = null,
            string[]? issuerContainsAllOf = null,
            string? rootIssuerContains = null,
            string[]? rootIssuerContainsAnyOf = null,
            string[]? rootIssuerContainsAllOf = null,
            int? certificateReuseEndpointCountMin = null,
            int? certificateReuseEndpointCountMax = null,
            bool? certificateReuseCrossServiceOnly = null,
            int? certificateReuseDistinctServiceCountMin = null,
            int? certificateReuseDistinctServiceCountMax = null,
            int? certificateReuseDistinctPortCountMin = null,
            int? certificateReuseDistinctPortCountMax = null,
            bool? certificateReuseCrossPortOnly = null) {
            var summary = new CertificateInventoryRiskSummary();
            var latestByEndpoint = new Dictionary<string, LatestEntryState>(StringComparer.OrdinalIgnoreCase);

            var hasRiskProfile = TryResolveRiskProfile(riskProfile, out var normalizedRiskProfile);
            if (!string.IsNullOrWhiteSpace(riskProfile) && !hasRiskProfile) {
                throw new ArgumentException($"riskProfile must be one of: {RiskProfileAcceptedValues}.", nameof(riskProfile));
            }
            var profileDefaults = hasRiskProfile ? RiskProfileDefinitions[normalizedRiskProfile] : null;

            var effectiveMinimumSeverity = !string.IsNullOrWhiteSpace(minimumSeverity)
                ? minimumSeverity
                : profileDefaults?.MinimumSeverity;
            var effectiveExpiredOnly = expiredOnly ?? profileDefaults?.ExpiredOnly;
            var effectiveNotYetValidOnly = notYetValidOnly ?? profileDefaults?.NotYetValidOnly;
            var effectiveCurrentlyValidOnly = currentlyValidOnly ?? profileDefaults?.CurrentlyValidOnly;
            var effectiveDaysToExpireMin = daysToExpireMin ?? profileDefaults?.DaysToExpireMin;
            var effectiveDaysToExpireMax = daysToExpireMax ?? profileDefaults?.DaysToExpireMax;
            var effectiveDaysUntilValidMin = daysUntilValidMin ?? profileDefaults?.DaysUntilValidMin;
            var effectiveDaysUntilValidMax = daysUntilValidMax ?? profileDefaults?.DaysUntilValidMax;

            var hasMinimumSeverity = TryResolveMinimumSeverity(effectiveMinimumSeverity, out var minimumSeverityScore, out _);
            if (!string.IsNullOrWhiteSpace(effectiveMinimumSeverity) && !hasMinimumSeverity) {
                throw new ArgumentException($"minimumSeverity must be one of: {MinimumSeverityAcceptedValues}.", nameof(minimumSeverity));
            }
            var hasScoreMinFilter = scoreMin.HasValue;
            var scoreMinExpected = hasScoreMinFilter ? scoreMin!.Value : 0;
            if (hasScoreMinFilter && (scoreMinExpected < 0 || scoreMinExpected > 100)) {
                throw new ArgumentOutOfRangeException(nameof(scoreMin), "scoreMin must be between 0 and 100.");
            }
            var hasScoreMaxFilter = scoreMax.HasValue;
            var scoreMaxExpected = hasScoreMaxFilter ? scoreMax!.Value : 0;
            if (hasScoreMaxFilter && (scoreMaxExpected < 0 || scoreMaxExpected > 100)) {
                throw new ArgumentOutOfRangeException(nameof(scoreMax), "scoreMax must be between 0 and 100.");
            }
            if (hasScoreMinFilter && hasScoreMaxFilter && scoreMinExpected > scoreMaxExpected) {
                throw new ArgumentException("scoreMin cannot be greater than scoreMax.", nameof(scoreMin));
            }
            var hasReasonCountMinFilter = reasonCountMin.HasValue;
            var reasonCountMinExpected = hasReasonCountMinFilter ? reasonCountMin!.Value : 0;
            if (hasReasonCountMinFilter && reasonCountMinExpected < 0) {
                throw new ArgumentOutOfRangeException(nameof(reasonCountMin), "reasonCountMin must be 0 or greater.");
            }
            var hasReasonCountMaxFilter = reasonCountMax.HasValue;
            var reasonCountMaxExpected = hasReasonCountMaxFilter ? reasonCountMax!.Value : 0;
            if (hasReasonCountMaxFilter && reasonCountMaxExpected < 0) {
                throw new ArgumentOutOfRangeException(nameof(reasonCountMax), "reasonCountMax must be 0 or greater.");
            }
            if (hasReasonCountMinFilter && hasReasonCountMaxFilter && reasonCountMinExpected > reasonCountMaxExpected) {
                throw new ArgumentException("reasonCountMin cannot be greater than reasonCountMax.", nameof(reasonCountMin));
            }
            var hasCertificateReuseEndpointCountMinFilter = certificateReuseEndpointCountMin.HasValue;
            var certificateReuseEndpointCountMinExpected = hasCertificateReuseEndpointCountMinFilter ? certificateReuseEndpointCountMin!.Value : 0;
            if (hasCertificateReuseEndpointCountMinFilter && certificateReuseEndpointCountMinExpected < 1) {
                throw new ArgumentOutOfRangeException(nameof(certificateReuseEndpointCountMin), "certificateReuseEndpointCountMin must be 1 or greater.");
            }
            var hasCertificateReuseEndpointCountMaxFilter = certificateReuseEndpointCountMax.HasValue;
            var certificateReuseEndpointCountMaxExpected = hasCertificateReuseEndpointCountMaxFilter ? certificateReuseEndpointCountMax!.Value : 0;
            if (hasCertificateReuseEndpointCountMaxFilter && certificateReuseEndpointCountMaxExpected < 1) {
                throw new ArgumentOutOfRangeException(nameof(certificateReuseEndpointCountMax), "certificateReuseEndpointCountMax must be 1 or greater.");
            }
            if (hasCertificateReuseEndpointCountMinFilter &&
                hasCertificateReuseEndpointCountMaxFilter &&
                certificateReuseEndpointCountMinExpected > certificateReuseEndpointCountMaxExpected) {
                throw new ArgumentException(
                    "certificateReuseEndpointCountMin cannot be greater than certificateReuseEndpointCountMax.",
                    nameof(certificateReuseEndpointCountMin));
            }
            var hasCertificateReuseDistinctServiceCountMinFilter = certificateReuseDistinctServiceCountMin.HasValue;
            var certificateReuseDistinctServiceCountMinExpected = hasCertificateReuseDistinctServiceCountMinFilter ? certificateReuseDistinctServiceCountMin!.Value : 0;
            if (hasCertificateReuseDistinctServiceCountMinFilter && certificateReuseDistinctServiceCountMinExpected < 1) {
                throw new ArgumentOutOfRangeException(nameof(certificateReuseDistinctServiceCountMin), "certificateReuseDistinctServiceCountMin must be 1 or greater.");
            }
            var hasCertificateReuseDistinctServiceCountMaxFilter = certificateReuseDistinctServiceCountMax.HasValue;
            var certificateReuseDistinctServiceCountMaxExpected = hasCertificateReuseDistinctServiceCountMaxFilter ? certificateReuseDistinctServiceCountMax!.Value : 0;
            if (hasCertificateReuseDistinctServiceCountMaxFilter && certificateReuseDistinctServiceCountMaxExpected < 1) {
                throw new ArgumentOutOfRangeException(nameof(certificateReuseDistinctServiceCountMax), "certificateReuseDistinctServiceCountMax must be 1 or greater.");
            }
            if (hasCertificateReuseDistinctServiceCountMinFilter &&
                hasCertificateReuseDistinctServiceCountMaxFilter &&
                certificateReuseDistinctServiceCountMinExpected > certificateReuseDistinctServiceCountMaxExpected) {
                throw new ArgumentException(
                    "certificateReuseDistinctServiceCountMin cannot be greater than certificateReuseDistinctServiceCountMax.",
                    nameof(certificateReuseDistinctServiceCountMin));
            }
            var hasCertificateReuseDistinctPortCountMinFilter = certificateReuseDistinctPortCountMin.HasValue;
            var certificateReuseDistinctPortCountMinExpected = hasCertificateReuseDistinctPortCountMinFilter ? certificateReuseDistinctPortCountMin!.Value : 0;
            if (hasCertificateReuseDistinctPortCountMinFilter && certificateReuseDistinctPortCountMinExpected < 1) {
                throw new ArgumentOutOfRangeException(nameof(certificateReuseDistinctPortCountMin), "certificateReuseDistinctPortCountMin must be 1 or greater.");
            }
            var hasCertificateReuseDistinctPortCountMaxFilter = certificateReuseDistinctPortCountMax.HasValue;
            var certificateReuseDistinctPortCountMaxExpected = hasCertificateReuseDistinctPortCountMaxFilter ? certificateReuseDistinctPortCountMax!.Value : 0;
            if (hasCertificateReuseDistinctPortCountMaxFilter && certificateReuseDistinctPortCountMaxExpected < 1) {
                throw new ArgumentOutOfRangeException(nameof(certificateReuseDistinctPortCountMax), "certificateReuseDistinctPortCountMax must be 1 or greater.");
            }
            if (hasCertificateReuseDistinctPortCountMinFilter &&
                hasCertificateReuseDistinctPortCountMaxFilter &&
                certificateReuseDistinctPortCountMinExpected > certificateReuseDistinctPortCountMaxExpected) {
                throw new ArgumentException(
                    "certificateReuseDistinctPortCountMin cannot be greater than certificateReuseDistinctPortCountMax.",
                    nameof(certificateReuseDistinctPortCountMin));
            }
            var hasReasonFilter = !string.IsNullOrWhiteSpace(reasonContains);
            var reasonNeedle = hasReasonFilter ? reasonContains!.Trim() : string.Empty;
            var normalizedReasonAnyOf = NormalizeDistinctValues(reasonAnyOf);
            var hasReasonAnyOfFilter = normalizedReasonAnyOf.Count > 0;
            var reasonAnyOfSet = hasReasonAnyOfFilter
                ? new HashSet<string>(normalizedReasonAnyOf, StringComparer.OrdinalIgnoreCase)
                : null;
            var normalizedReasonAllOf = NormalizeDistinctValues(reasonAllOf);
            var hasReasonAllOfFilter = normalizedReasonAllOf.Count > 0;
            var reasonAllOfSet = hasReasonAllOfFilter
                ? new HashSet<string>(normalizedReasonAllOf, StringComparer.OrdinalIgnoreCase)
                : null;
            var hasIssuerFilter = !string.IsNullOrWhiteSpace(issuerContains);
            var issuerNeedle = hasIssuerFilter ? issuerContains!.Trim() : string.Empty;
            var normalizedIssuerContainsAnyOf = NormalizeDistinctValues(issuerContainsAnyOf);
            var hasIssuerAnyOfFilter = normalizedIssuerContainsAnyOf.Count > 0;
            var normalizedIssuerContainsAllOf = NormalizeDistinctValues(issuerContainsAllOf);
            var hasIssuerAllOfFilter = normalizedIssuerContainsAllOf.Count > 0;
            var hasRootIssuerFilter = !string.IsNullOrWhiteSpace(rootIssuerContains);
            var rootIssuerNeedle = hasRootIssuerFilter ? rootIssuerContains!.Trim() : string.Empty;
            var normalizedRootIssuerContainsAnyOf = NormalizeDistinctValues(rootIssuerContainsAnyOf);
            var hasRootIssuerAnyOfFilter = normalizedRootIssuerContainsAnyOf.Count > 0;
            var normalizedRootIssuerContainsAllOf = NormalizeDistinctValues(rootIssuerContainsAllOf);
            var hasRootIssuerAllOfFilter = normalizedRootIssuerContainsAllOf.Count > 0;
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
            var thumbprintExpected = hasThumbprintFilter ? NormalizeHexIdentifier(thumbprintEquals) : string.Empty;
            var hasRootThumbprintFilter = !string.IsNullOrWhiteSpace(rootThumbprintEquals);
            var rootThumbprintExpected = hasRootThumbprintFilter ? NormalizeHexIdentifier(rootThumbprintEquals) : string.Empty;
            var hasSerialNumberFilter = !string.IsNullOrWhiteSpace(serialNumberEquals);
            var serialNumberExpected = hasSerialNumberFilter ? NormalizeHexIdentifier(serialNumberEquals) : string.Empty;
            var hasHostFilter = !string.IsNullOrWhiteSpace(hostContains);
            var hostNeedle = hasHostFilter ? hostContains!.Trim() : string.Empty;
            var hasServiceFilter = !string.IsNullOrWhiteSpace(serviceEquals);
            var serviceExpected = hasServiceFilter ? serviceEquals!.Trim() : string.Empty;
            var hasPortFilter = portEquals.HasValue;
            var portExpected = hasPortFilter ? portEquals!.Value : 0;
            if (hasPortFilter && (portExpected <= 0 || portExpected > 65535)) {
                throw new ArgumentOutOfRangeException(nameof(portEquals), "portEquals must be between 1 and 65535.");
            }
            var hasChainLengthMinFilter = chainLengthMin.HasValue;
            var chainLengthMinExpected = hasChainLengthMinFilter ? chainLengthMin!.Value : 0;
            if (hasChainLengthMinFilter && chainLengthMinExpected < 0) {
                throw new ArgumentOutOfRangeException(nameof(chainLengthMin), "chainLengthMin must be 0 or greater.");
            }
            var hasChainLengthMaxFilter = chainLengthMax.HasValue;
            var chainLengthMaxExpected = hasChainLengthMaxFilter ? chainLengthMax!.Value : 0;
            if (hasChainLengthMaxFilter && chainLengthMaxExpected < 0) {
                throw new ArgumentOutOfRangeException(nameof(chainLengthMax), "chainLengthMax must be 0 or greater.");
            }
            if (hasChainLengthMinFilter && hasChainLengthMaxFilter && chainLengthMinExpected > chainLengthMaxExpected) {
                throw new ArgumentException("chainLengthMin cannot be greater than chainLengthMax.", nameof(chainLengthMin));
            }
            var hasIntermediateCountMinFilter = intermediateCountMin.HasValue;
            var intermediateCountMinExpected = hasIntermediateCountMinFilter ? intermediateCountMin!.Value : 0;
            if (hasIntermediateCountMinFilter && intermediateCountMinExpected < 0) {
                throw new ArgumentOutOfRangeException(nameof(intermediateCountMin), "intermediateCountMin must be 0 or greater.");
            }
            var hasIntermediateCountMaxFilter = intermediateCountMax.HasValue;
            var intermediateCountMaxExpected = hasIntermediateCountMaxFilter ? intermediateCountMax!.Value : 0;
            if (hasIntermediateCountMaxFilter && intermediateCountMaxExpected < 0) {
                throw new ArgumentOutOfRangeException(nameof(intermediateCountMax), "intermediateCountMax must be 0 or greater.");
            }
            if (hasIntermediateCountMinFilter && hasIntermediateCountMaxFilter && intermediateCountMinExpected > intermediateCountMaxExpected) {
                throw new ArgumentException("intermediateCountMin cannot be greater than intermediateCountMax.", nameof(intermediateCountMin));
            }
            var hasDaysToExpireMinFilter = effectiveDaysToExpireMin.HasValue;
            var daysToExpireMinExpected = hasDaysToExpireMinFilter ? effectiveDaysToExpireMin!.Value : 0;
            var hasDaysToExpireMaxFilter = effectiveDaysToExpireMax.HasValue;
            var daysToExpireMaxExpected = hasDaysToExpireMaxFilter ? effectiveDaysToExpireMax!.Value : 0;
            if (hasDaysToExpireMinFilter && hasDaysToExpireMaxFilter && daysToExpireMinExpected > daysToExpireMaxExpected) {
                throw new ArgumentException("daysToExpireMin cannot be greater than daysToExpireMax.", nameof(daysToExpireMin));
            }
            var hasDaysUntilValidMinFilter = effectiveDaysUntilValidMin.HasValue;
            var daysUntilValidMinExpected = hasDaysUntilValidMinFilter ? effectiveDaysUntilValidMin!.Value : 0;
            if (hasDaysUntilValidMinFilter && daysUntilValidMinExpected < 0) {
                throw new ArgumentOutOfRangeException(nameof(daysUntilValidMin), "daysUntilValidMin must be 0 or greater.");
            }
            var hasDaysUntilValidMaxFilter = effectiveDaysUntilValidMax.HasValue;
            var daysUntilValidMaxExpected = hasDaysUntilValidMaxFilter ? effectiveDaysUntilValidMax!.Value : 0;
            if (hasDaysUntilValidMaxFilter && daysUntilValidMaxExpected < 0) {
                throw new ArgumentOutOfRangeException(nameof(daysUntilValidMax), "daysUntilValidMax must be 0 or greater.");
            }
            if (hasDaysUntilValidMinFilter && hasDaysUntilValidMaxFilter && daysUntilValidMinExpected > daysUntilValidMaxExpected) {
                throw new ArgumentException("daysUntilValidMin cannot be greater than daysUntilValidMax.", nameof(daysUntilValidMin));
            }
            var hasAuthenticationProfileFilter = !string.IsNullOrWhiteSpace(authenticationProfileEquals);
            var authenticationProfileExpected = hasAuthenticationProfileFilter ? authenticationProfileEquals!.Trim() : string.Empty;
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
            var certificateReuseById = BuildCertificateReuseStats(latestByEndpoint.Values);
            summary.UniqueCertificateIdentityCount = certificateReuseById.Count;
            if (certificateReuseById.Count > 0) {
                summary.ReusedCertificateIdentityCount = certificateReuseById.Count(pair => pair.Value.EndpointCount > 1);
                summary.ReusedCertificateIdentityPercentage = Math.Round(
                    100d * summary.ReusedCertificateIdentityCount / summary.UniqueCertificateIdentityCount,
                    2);
                summary.EndpointsWithReusedCertificateCount = certificateReuseById.Values
                    .Where(stats => stats.EndpointCount > 1)
                    .Sum(stats => stats.EndpointCount);
                summary.CrossServiceReusedCertificateIdentityCount = certificateReuseById.Count(pair => pair.Value.DistinctServiceCount > 1);
                summary.CrossPortReusedCertificateIdentityCount = certificateReuseById.Count(pair => pair.Value.DistinctPortCount > 1);
                summary.CrossServiceReusedCertificateIdentityPercentage = Math.Round(
                    100d * summary.CrossServiceReusedCertificateIdentityCount / summary.UniqueCertificateIdentityCount,
                    2);
                summary.CrossPortReusedCertificateIdentityPercentage = Math.Round(
                    100d * summary.CrossPortReusedCertificateIdentityCount / summary.UniqueCertificateIdentityCount,
                    2);
                summary.EndpointsWithCrossServiceReuseCount = certificateReuseById.Values
                    .Where(stats => stats.DistinctServiceCount > 1)
                    .Sum(stats => stats.EndpointCount);
                summary.EndpointsWithCrossPortReuseCount = certificateReuseById.Values
                    .Where(stats => stats.DistinctPortCount > 1)
                    .Sum(stats => stats.EndpointCount);
                summary.MaxCertificateReuseEndpointCount = certificateReuseById.Values.Max(stats => stats.EndpointCount);
                summary.MaxCertificateReuseDistinctServiceCount = certificateReuseById.Values.Max(stats => stats.DistinctServiceCount);
                summary.MaxCertificateReuseDistinctPortCount = certificateReuseById.Values.Max(stats => stats.DistinctPortCount);
            }
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
                var certificateId = BuildCertificateId(latest.Entry);
                if (certificateReuseById.TryGetValue(certificateId, out var certificateReuseStats)) {
                    row.CertificateReuseEndpointCount = certificateReuseStats.EndpointCount;
                    row.CertificateReuseDistinctServiceCount = certificateReuseStats.DistinctServiceCount;
                    row.CertificateReuseDistinctPortCount = certificateReuseStats.DistinctPortCount;
                } else {
                    row.CertificateReuseEndpointCount = 1;
                    row.CertificateReuseDistinctServiceCount = 1;
                    row.CertificateReuseDistinctPortCount = 1;
                }
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
                if (hasScoreMinFilter && row.Score < scoreMinExpected) {
                    continue;
                }
                if (hasScoreMaxFilter && row.Score > scoreMaxExpected) {
                    continue;
                }
                var reasonCount = row.Reasons.Count;
                if (hasReasonCountMinFilter && reasonCount < reasonCountMinExpected) {
                    continue;
                }
                if (hasReasonCountMaxFilter && reasonCount > reasonCountMaxExpected) {
                    continue;
                }
                if (hasCertificateReuseEndpointCountMinFilter &&
                    row.CertificateReuseEndpointCount < certificateReuseEndpointCountMinExpected) {
                    continue;
                }
                if (hasCertificateReuseEndpointCountMaxFilter &&
                    row.CertificateReuseEndpointCount > certificateReuseEndpointCountMaxExpected) {
                    continue;
                }
                if (certificateReuseCrossServiceOnly.HasValue) {
                    var reuseCrossService = row.CertificateReuseDistinctServiceCount > 1;
                    if (reuseCrossService != certificateReuseCrossServiceOnly.Value) {
                        continue;
                    }
                }
                if (hasCertificateReuseDistinctServiceCountMinFilter &&
                    row.CertificateReuseDistinctServiceCount < certificateReuseDistinctServiceCountMinExpected) {
                    continue;
                }
                if (hasCertificateReuseDistinctServiceCountMaxFilter &&
                    row.CertificateReuseDistinctServiceCount > certificateReuseDistinctServiceCountMaxExpected) {
                    continue;
                }
                if (hasCertificateReuseDistinctPortCountMinFilter &&
                    row.CertificateReuseDistinctPortCount < certificateReuseDistinctPortCountMinExpected) {
                    continue;
                }
                if (hasCertificateReuseDistinctPortCountMaxFilter &&
                    row.CertificateReuseDistinctPortCount > certificateReuseDistinctPortCountMaxExpected) {
                    continue;
                }
                if (certificateReuseCrossPortOnly.HasValue) {
                    var reuseCrossPort = row.CertificateReuseDistinctPortCount > 1;
                    if (reuseCrossPort != certificateReuseCrossPortOnly.Value) {
                        continue;
                    }
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
                if (hasReasonAnyOfFilter) {
                    var matchesAnyReason = row.Reasons.Any(reason => reasonAnyOfSet!.Contains(reason));
                    if (!matchesAnyReason) {
                        continue;
                    }
                }
                if (hasReasonAllOfFilter) {
                    var rowReasonSet = new HashSet<string>(row.Reasons, StringComparer.OrdinalIgnoreCase);
                    var matchesAllReasons = reasonAllOfSet!.All(rowReasonSet.Contains);
                    if (!matchesAllReasons) {
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
                if (hasIssuerAnyOfFilter) {
                    var matchesAnyIssuer = normalizedIssuerContainsAnyOf.Any(needle =>
                        row.Issuer.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        row.RootIssuer.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0);
                    if (!matchesAnyIssuer) {
                        continue;
                    }
                }
                if (hasIssuerAllOfFilter) {
                    var matchesAllIssuer = normalizedIssuerContainsAllOf.All(needle =>
                        row.Issuer.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        row.RootIssuer.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0);
                    if (!matchesAllIssuer) {
                        continue;
                    }
                }
                if (hasRootIssuerFilter &&
                    row.RootIssuer.IndexOf(rootIssuerNeedle, StringComparison.OrdinalIgnoreCase) < 0) {
                    continue;
                }
                if (hasRootIssuerAnyOfFilter) {
                    var matchesRootIssuerAny = normalizedRootIssuerContainsAnyOf.Any(needle =>
                        row.RootIssuer.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0);
                    if (!matchesRootIssuerAny) {
                        continue;
                    }
                }
                if (hasRootIssuerAllOfFilter) {
                    var matchesRootIssuerAll = normalizedRootIssuerContainsAllOf.All(needle =>
                        row.RootIssuer.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0);
                    if (!matchesRootIssuerAll) {
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
                if (hasThumbprintFilter) {
                    var rowThumbprint = NormalizeHexIdentifier(row.CertificateThumbprint);
                    if (thumbprintExpected.Length == 0 ||
                        !string.Equals(rowThumbprint, thumbprintExpected, StringComparison.OrdinalIgnoreCase)) {
                        continue;
                    }
                }
                if (hasRootThumbprintFilter) {
                    var rowRootThumbprint = NormalizeHexIdentifier(row.CertificateRootThumbprint);
                    if (rootThumbprintExpected.Length == 0 ||
                        !string.Equals(rowRootThumbprint, rootThumbprintExpected, StringComparison.OrdinalIgnoreCase)) {
                        continue;
                    }
                }
                if (hasSerialNumberFilter) {
                    var rowSerialNumber = NormalizeHexIdentifier(row.CertificateSerialNumber);
                    if (serialNumberExpected.Length == 0 ||
                        !string.Equals(rowSerialNumber, serialNumberExpected, StringComparison.OrdinalIgnoreCase)) {
                        continue;
                    }
                }
                if (hasHostFilter && row.Host.IndexOf(hostNeedle, StringComparison.OrdinalIgnoreCase) < 0) {
                    continue;
                }
                if (hasServiceFilter && !string.Equals(row.Service, serviceExpected, StringComparison.OrdinalIgnoreCase)) {
                    continue;
                }
                if (hasPortFilter && row.Port != portExpected) {
                    continue;
                }
                if (hasChainLengthMinFilter && row.ChainLength < chainLengthMinExpected) {
                    continue;
                }
                if (hasChainLengthMaxFilter && row.ChainLength > chainLengthMaxExpected) {
                    continue;
                }
                if (hasIntermediateCountMinFilter && row.IntermediateCount < intermediateCountMinExpected) {
                    continue;
                }
                if (hasIntermediateCountMaxFilter && row.IntermediateCount > intermediateCountMaxExpected) {
                    continue;
                }
                if (ctObservedOnly.HasValue && row.PresentInCtLogs != ctObservedOnly.Value) {
                    continue;
                }
                if (chainCompleteOnly.HasValue && row.ChainComplete != chainCompleteOnly.Value) {
                    continue;
                }
                if (reachableOnly.HasValue && row.IsReachable != reachableOnly.Value) {
                    continue;
                }
                if (hostnameMatchOnly.HasValue && row.HostnameMatch != hostnameMatchOnly.Value) {
                    continue;
                }
                if (selfSignedOnly.HasValue && row.IsSelfSigned != selfSignedOnly.Value) {
                    continue;
                }
                if (weakKeyOnly.HasValue && row.WeakKey != weakKeyOnly.Value) {
                    continue;
                }
                if (sha1SignatureOnly.HasValue && row.Sha1Signature != sha1SignatureOnly.Value) {
                    continue;
                }
                if (effectiveExpiredOnly.HasValue && row.Expired != effectiveExpiredOnly.Value) {
                    continue;
                }
                if (effectiveNotYetValidOnly.HasValue && row.NotYetValid != effectiveNotYetValidOnly.Value) {
                    continue;
                }
                var currentlyValid = !row.Expired && !row.NotYetValid;
                if (effectiveCurrentlyValidOnly.HasValue && currentlyValid != effectiveCurrentlyValidOnly.Value) {
                    continue;
                }
                if (hasDaysToExpireMinFilter) {
                    if (!row.DaysToExpire.HasValue || row.DaysToExpire.Value < daysToExpireMinExpected) {
                        continue;
                    }
                }
                if (hasDaysToExpireMaxFilter) {
                    if (!row.DaysToExpire.HasValue || row.DaysToExpire.Value > daysToExpireMaxExpected) {
                        continue;
                    }
                }
                if (hasDaysUntilValidMinFilter) {
                    if (!row.DaysUntilValid.HasValue || row.DaysUntilValid.Value < daysUntilValidMinExpected) {
                        continue;
                    }
                }
                if (hasDaysUntilValidMaxFilter) {
                    if (!row.DaysUntilValid.HasValue || row.DaysUntilValid.Value > daysUntilValidMaxExpected) {
                        continue;
                    }
                }
                if (knownAuthorityOnly.HasValue && knownAuthorityOnly.Value != row.IsKnownCertificateAuthority) {
                    continue;
                }
                if (knownRootAuthorityOnly.HasValue && knownRootAuthorityOnly.Value != row.IsKnownRootCertificateAuthority) {
                    continue;
                }
                if (hasAuthenticationProfileFilter &&
                    !string.Equals(row.AuthenticationProfile, authenticationProfileExpected, StringComparison.OrdinalIgnoreCase)) {
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
                summary.EndpointsWithReusedCertificatePercentage = Math.Round(
                    100d * summary.EndpointsWithReusedCertificateCount / summary.EndpointCount,
                    2);
                summary.EndpointsWithCrossServiceReusePercentage = Math.Round(
                    100d * summary.EndpointsWithCrossServiceReuseCount / summary.EndpointCount,
                    2);
                summary.EndpointsWithCrossPortReusePercentage = Math.Round(
                    100d * summary.EndpointsWithCrossPortReuseCount / summary.EndpointCount,
                    2);
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
                CertificateRootThumbprint = entry.CertificateRootThumbprint?.Trim() ?? string.Empty,
                CertificateSerialNumber = entry.CertificateSerialNumber?.Trim() ?? string.Empty,
                Issuer = PickIssuer(entry),
                RootIssuer = PickRoot(entry),
                AuthorityFamily = entry.CertificateAuthorityFamily ?? string.Empty,
                RootAuthorityFamily = entry.CertificateRootAuthorityFamily ?? string.Empty,
                NotBeforeUtc = entry.NotBeforeUtc,
                NotAfterUtc = entry.NotAfterUtc,
                Valid = entry.Valid,
                Expired = entry.Expired,
                ChainComplete = entry.ChainComplete,
                ChainLength = Math.Max(0, entry.CertificateChainLength),
                IntermediateCount = Math.Max(0, entry.CertificateIntermediateCount),
                HostnameMatch = entry.HostnameMatch,
                IsReachable = entry.IsReachable,
                IsSelfSigned = entry.IsSelfSigned,
                IsKnownCertificateAuthority = entry.IsKnownCertificateAuthority,
                IsKnownRootCertificateAuthority = entry.IsKnownRootCertificateAuthority,
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

        private static Dictionary<string, CertificateReuseStats> BuildCertificateReuseStats(IEnumerable<LatestEntryState> latestStates) {
            var grouped = new Dictionary<string, List<CertificateInventoryEntry>>(StringComparer.OrdinalIgnoreCase);
            foreach (var latest in latestStates ?? Enumerable.Empty<LatestEntryState>()) {
                if (latest?.Entry == null) {
                    continue;
                }

                var certificateId = BuildCertificateId(latest.Entry);
                if (!grouped.TryGetValue(certificateId, out var entries)) {
                    entries = new List<CertificateInventoryEntry>();
                    grouped[certificateId] = entries;
                }
                entries.Add(latest.Entry);
            }

            var results = new Dictionary<string, CertificateReuseStats>(StringComparer.OrdinalIgnoreCase);
            foreach (var pair in grouped) {
                var entries = pair.Value;
                if (entries.Count == 0) {
                    continue;
                }

                var distinctServices = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var distinctPorts = new HashSet<int>();
                foreach (var entry in entries) {
                    distinctServices.Add(PickService(entry));
                    distinctPorts.Add(entry.Port > 0 ? entry.Port : 443);
                }

                results[pair.Key] = new CertificateReuseStats {
                    EndpointCount = entries.Count,
                    DistinctServiceCount = distinctServices.Count,
                    DistinctPortCount = distinctPorts.Count
                };
            }

            return results;
        }

        private static string BuildCertificateId(CertificateInventoryEntry entry) {
            if (!string.IsNullOrWhiteSpace(entry.CertificateThumbprint)) {
                return NormalizeHexIdentifier(entry.CertificateThumbprint);
            }

            var subject = entry.CertificateSubject ?? string.Empty;
            var issuer = PickIssuer(entry);
            var notBefore = entry.NotBeforeUtc?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty;
            var notAfter = entry.NotAfterUtc?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty;
            return $"{subject}|{issuer}|{notBefore}|{notAfter}";
        }

        private static string PickService(CertificateInventoryEntry entry) {
            if (!string.IsNullOrWhiteSpace(entry.Service)) {
                return entry.Service!;
            }

            return CertificateServiceClassifier.GuessService(entry.Scheme ?? "https", entry.Port);
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

        private static string NormalizeHexIdentifier(string? value) {
            if (string.IsNullOrWhiteSpace(value)) {
                return string.Empty;
            }

            var chars = value.Where(c => !char.IsWhiteSpace(c) && c != ':').ToArray();
            return new string(chars).Trim().ToUpperInvariant();
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
