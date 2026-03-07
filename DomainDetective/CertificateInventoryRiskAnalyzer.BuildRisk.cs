using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace DomainDetective {
    public static partial class CertificateInventoryRiskAnalyzer {
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

    }
}
