using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;
using PeriodicTimer = System.Threading.PeriodicTimer;

namespace DomainDetective {
    public partial class CertificateMonitor {
        public CertificateInventoryRiskSummary BuildInventoryRisk(
            DateTimeOffset? sinceUtc = null,
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
            var snapshots = LoadInventorySnapshots(sinceUtc);
            return CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk,
                expiringWithinDays,
                criticalExpiringWithinDays,
                maxEndpoints,
                minimumSeverity,
                scoreMin,
                scoreMax,
                reasonCountMin,
                reasonCountMax,
                riskProfile,
                reasonContains,
                issuerContains,
                authorityFamilyEquals,
                rootAuthorityFamilyEquals,
                ctSourceContains,
                ctTemplateErrorContains,
                chainSourceContains,
                thumbprintEquals,
                rootThumbprintEquals,
                serialNumberEquals,
                hostContains,
                serviceEquals,
                portEquals,
                chainLengthMin,
                chainLengthMax,
                intermediateCountMin,
                intermediateCountMax,
                ctObservedOnly,
                chainCompleteOnly,
                reachableOnly,
                hostnameMatchOnly,
                selfSignedOnly,
                weakKeyOnly,
                sha1SignatureOnly,
                expiredOnly,
                notYetValidOnly,
                currentlyValidOnly,
                daysToExpireMin,
                daysToExpireMax,
                daysUntilValidMin,
                daysUntilValidMax,
                knownAuthorityOnly,
                knownRootAuthorityOnly,
                authenticationProfileEquals,
                serverAuthOnly,
                clientAuthOnly,
                secureEmailOnly,
                reasonAnyOf,
                reasonAllOf,
                issuerContainsAnyOf,
                issuerContainsAllOf,
                rootIssuerContains,
                rootIssuerContainsAnyOf,
                rootIssuerContainsAllOf,
                certificateReuseEndpointCountMin,
                certificateReuseEndpointCountMax,
                certificateReuseCrossServiceOnly,
                certificateReuseDistinctServiceCountMin,
                certificateReuseDistinctServiceCountMax,
                certificateReuseDistinctPortCountMin,
                certificateReuseDistinctPortCountMax,
                certificateReuseCrossPortOnly);
        }

        /// <summary>Builds endpoint-level certificate policy posture from persisted inventory snapshots.</summary>
        /// <param name="sinceUtc">Optional lower bound for snapshot capture time.</param>
        /// <param name="baselineProfile">Policy baseline profile (Strict, Balanced, Legacy).</param>
        /// <param name="includeCompliant">When true, includes endpoints with no policy violations.</param>
        /// <param name="maxEndpoints">Maximum endpoint rows returned.</param>
        /// <param name="policyOverrides">Optional organization override rules for baseline/profile suppression.</param>
        public CertificateInventoryPolicySummary BuildInventoryPolicy(
            DateTimeOffset? sinceUtc = null,
            string? baselineProfile = "Balanced",
            bool includeCompliant = false,
            int maxEndpoints = 300,
            CertificateInventoryPolicyOverrides? policyOverrides = null) {
            var snapshots = LoadInventorySnapshots(sinceUtc);
            return CertificateInventoryPolicyAnalyzer.BuildPolicy(
                snapshots,
                baselineProfile,
                includeCompliant,
                maxEndpoints,
                policyOverrides);
        }

        /// <summary>Builds endpoint-level certificate policy drift between two persisted inventory snapshots.</summary>
        /// <param name="sinceUtc">Optional lower bound for snapshot capture time.</param>
        /// <param name="baselineProfile">Policy baseline profile (Strict, Balanced, Legacy).</param>
        /// <param name="previousCapturedAtUtc">Optional previous snapshot timestamp selector (selects latest snapshot at or before timestamp).</param>
        /// <param name="currentCapturedAtUtc">Optional current snapshot timestamp selector (selects latest snapshot at or before timestamp).</param>
        /// <param name="changedOnly">When true, only returns endpoint rows with detected policy drift.</param>
        /// <param name="maxEndpoints">Maximum endpoint rows returned.</param>
        /// <param name="policyOverrides">Optional organization override rules for baseline/profile suppression.</param>
        public CertificateInventoryPolicyDriftSummary BuildInventoryPolicyDrift(
            DateTimeOffset? sinceUtc = null,
            string? baselineProfile = "Balanced",
            DateTimeOffset? previousCapturedAtUtc = null,
            DateTimeOffset? currentCapturedAtUtc = null,
            bool changedOnly = true,
            int maxEndpoints = 300,
            CertificateInventoryPolicyOverrides? policyOverrides = null) {
            var allSnapshots = LoadInventorySnapshots();
            var snapshots = allSnapshots;
            if (sinceUtc.HasValue) {
                snapshots = allSnapshots
                    .Where(snapshot => snapshot.CapturedAtUtc >= sinceUtc.Value)
                    .ToList();
            }

            var summary = CertificateInventoryPolicyDriftAnalyzer.BuildDrift(
                snapshots,
                baselineProfile,
                previousCapturedAtUtc,
                currentCapturedAtUtc,
                changedOnly,
                maxEndpoints,
                policyOverrides);
            AppendPolicyDriftSinceUtcSelectorWarnings(summary, allSnapshots, sinceUtc, previousCapturedAtUtc, currentCapturedAtUtc);
            return summary;
        }

        private static void AppendPolicyDriftSinceUtcSelectorWarnings(
            CertificateInventoryPolicyDriftSummary summary,
            IReadOnlyList<CertificateInventorySnapshot> allSnapshots,
            DateTimeOffset? sinceUtc,
            DateTimeOffset? previousCapturedAtUtc,
            DateTimeOffset? currentCapturedAtUtc) {
            if (!sinceUtc.HasValue) {
                return;
            }

            if (!previousCapturedAtUtc.HasValue && !currentCapturedAtUtc.HasValue) {
                return;
            }

            if (allSnapshots.Count == 0) {
                return;
            }

            var sinceCutoff = sinceUtc.Value;
            if (previousCapturedAtUtc.HasValue) {
                var fullPrevious = ResolveSnapshotAtOrBefore(allSnapshots, previousCapturedAtUtc.Value);
                if (fullPrevious != null &&
                    fullPrevious.CapturedAtUtc < sinceCutoff &&
                    (!summary.PreviousCapturedAtUtc.HasValue || summary.PreviousCapturedAtUtc.Value != fullPrevious.CapturedAtUtc)) {
                    var warning = string.Format(
                        "Requested previous snapshot at or before {0:yyyy-MM-dd HH:mm:ss} UTC resolves to {1:yyyy-MM-dd HH:mm:ss} UTC, but --since-utc ({2:yyyy-MM-dd HH:mm:ss} UTC) excluded it.",
                        previousCapturedAtUtc.Value.UtcDateTime,
                        fullPrevious.CapturedAtUtc.UtcDateTime,
                        sinceCutoff.UtcDateTime);
                    ReplaceWarningIfMissing(
                        summary,
                        string.Format("Requested previous snapshot at or before {0:yyyy-MM-dd HH:mm:ss} UTC", previousCapturedAtUtc.Value.UtcDateTime),
                        warning);
                }
            }

            if (currentCapturedAtUtc.HasValue) {
                var fullCurrent = ResolveSnapshotAtOrBefore(allSnapshots, currentCapturedAtUtc.Value);
                if (fullCurrent != null &&
                    fullCurrent.CapturedAtUtc < sinceCutoff &&
                    (!summary.CurrentCapturedAtUtc.HasValue || summary.CurrentCapturedAtUtc.Value != fullCurrent.CapturedAtUtc)) {
                    var warning = string.Format(
                        "Requested current snapshot at or before {0:yyyy-MM-dd HH:mm:ss} UTC resolves to {1:yyyy-MM-dd HH:mm:ss} UTC, but --since-utc ({2:yyyy-MM-dd HH:mm:ss} UTC) excluded it.",
                        currentCapturedAtUtc.Value.UtcDateTime,
                        fullCurrent.CapturedAtUtc.UtcDateTime,
                        sinceCutoff.UtcDateTime);
                    ReplaceWarningIfMissing(
                        summary,
                        string.Format("Requested current snapshot at or before {0:yyyy-MM-dd HH:mm:ss} UTC", currentCapturedAtUtc.Value.UtcDateTime),
                        warning);
                }
            }
        }

        private static void ReplaceWarningIfMissing(
            CertificateInventoryPolicyDriftSummary summary,
            string warningPrefix,
            string warning) {
            if (!string.IsNullOrWhiteSpace(warningPrefix)) {
                for (var i = summary.Warnings.Count - 1; i >= 0; i--) {
                    var existing = summary.Warnings[i];
                    if (!string.IsNullOrWhiteSpace(existing) &&
                        existing.StartsWith(warningPrefix, StringComparison.OrdinalIgnoreCase)) {
                        summary.Warnings.RemoveAt(i);
                    }
                }
            }

            AddWarningIfMissing(summary, warning);
        }

        private static void AddWarningIfMissing(CertificateInventoryPolicyDriftSummary summary, string warning) {
            if (string.IsNullOrWhiteSpace(warning)) {
                return;
            }

            foreach (var existing in summary.Warnings) {
                if (string.Equals(existing, warning, StringComparison.OrdinalIgnoreCase)) {
                    return;
                }
            }

            summary.Warnings.Add(warning);
        }

        private static CertificateInventorySnapshot? ResolveSnapshotAtOrBefore(
            IReadOnlyList<CertificateInventorySnapshot> orderedSnapshots,
            DateTimeOffset targetUtc) {
            for (var i = orderedSnapshots.Count - 1; i >= 0; i--) {
                if (orderedSnapshots[i].CapturedAtUtc <= targetUtc) {
                    return orderedSnapshots[i];
                }
            }

            return null;
        }

        /// <summary>Builds certificate reuse and assignment mapping from persisted inventory snapshots.</summary>
        /// <param name="sinceUtc">Optional lower bound for snapshot capture time.</param>
        /// <param name="includeSingleEndpointCertificates">When true, includes certificates used by only one endpoint.</param>
        /// <param name="minEndpointCount">Minimum endpoint count required per certificate.</param>
        /// <param name="maxCertificates">Maximum certificate rows returned.</param>
        /// <param name="maxEndpointsPerCertificate">Maximum endpoint references returned per certificate row.</param>
        public CertificateInventoryReuseSummary BuildInventoryReuse(
            DateTimeOffset? sinceUtc = null,
            bool includeSingleEndpointCertificates = false,
            int minEndpointCount = 2,
            int maxCertificates = 300,
            int maxEndpointsPerCertificate = 30) {
            var snapshots = LoadInventorySnapshots(sinceUtc);
            return CertificateInventoryReuseAnalyzer.BuildReuse(
                snapshots,
                includeSingleEndpointCertificates,
                minEndpointCount,
                maxCertificates,
                maxEndpointsPerCertificate);
        }
    }
}
