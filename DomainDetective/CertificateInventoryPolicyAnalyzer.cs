using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective {
    /// <summary>
    /// Explicit violation codes returned by <see cref="CertificateInventoryPolicyAnalyzer"/>.
    /// </summary>
    public static class CertificateInventoryPolicyViolationCodes {
        /// <summary>Represents the endpoint unreachable value.</summary>
        public const string EndpointUnreachable = "Policy.Endpoint.Unreachable";
        /// <summary>Represents the certificate not yet valid value.</summary>
        public const string CertificateNotYetValid = "Policy.Certificate.NotYetValid";
        /// <summary>Represents the certificate expired value.</summary>
        public const string CertificateExpired = "Policy.Certificate.Expired";
        /// <summary>Represents the certificate expiring soon value.</summary>
        public const string CertificateExpiringSoon = "Policy.Certificate.ExpiringSoon";
        /// <summary>Represents the certificate validation failed value.</summary>
        public const string CertificateValidationFailed = "Policy.Certificate.ValidationFailed";
        /// <summary>Represents the chain incomplete value.</summary>
        public const string ChainIncomplete = "Policy.Certificate.ChainIncomplete";
        /// <summary>Represents the hostname mismatch value.</summary>
        public const string HostnameMismatch = "Policy.Certificate.HostnameMismatch";
        /// <summary>Represents the missing server auth eku value.</summary>
        public const string MissingServerAuthEku = "Policy.Certificate.MissingServerAuthEku";
        /// <summary>Represents the client auth eku present value.</summary>
        public const string ClientAuthEkuPresent = "Policy.Certificate.ClientAuthEkuPresent";
        /// <summary>Represents the secure email eku present value.</summary>
        public const string SecureEmailEkuPresent = "Policy.Certificate.SecureEmailEkuPresent";
        /// <summary>Represents the self signed certificate value.</summary>
        public const string SelfSignedCertificate = "Policy.Certificate.SelfSigned";
        /// <summary>Represents the weak key value.</summary>
        public const string WeakKey = "Policy.Certificate.WeakKey";
        /// <summary>Represents the sha1 signature value.</summary>
        public const string Sha1Signature = "Policy.Certificate.Sha1Signature";
        /// <summary>Represents the unknown authority value.</summary>
        public const string UnknownAuthority = "Policy.Certificate.UnknownAuthority";
        /// <summary>Represents the unknown root authority value.</summary>
        public const string UnknownRootAuthority = "Policy.Certificate.UnknownRootAuthority";
        /// <summary>Represents the ct not observed value.</summary>
        public const string CtNotObserved = "Policy.Certificate.CtNotObserved";
        /// <summary>Represents the reuse endpoint fanout value.</summary>
        public const string ReuseEndpointFanout = "Policy.Certificate.Reuse.EndpointFanout";
        /// <summary>Represents the reuse cross service value.</summary>
        public const string ReuseCrossService = "Policy.Certificate.Reuse.CrossService";
        /// <summary>Represents the reuse cross port value.</summary>
        public const string ReuseCrossPort = "Policy.Certificate.Reuse.CrossPort";
    }

    /// <summary>
    /// Policy posture summary over persisted certificate inventory snapshots.
    /// </summary>
    public sealed class CertificateInventoryPolicySummary {
        /// <summary>Gets or sets the baseline profile value.</summary>
        public string BaselineProfile { get; set; } = "Balanced";
        /// <summary>Gets or sets the snapshot count value.</summary>
        public int SnapshotCount { get; set; }
        /// <summary>Gets or sets the endpoint count value.</summary>
        public int EndpointCount { get; set; }
        /// <summary>Number of endpoint rows matching include/exclude filters before max-endpoint limiting.</summary>
        public int MatchedEndpointCount { get; set; }
        /// <summary>Number of matched endpoint rows omitted by max-endpoint limiting.</summary>
        public int EndpointsTruncatedByMaxEndpoints { get; set; }
        /// <summary>True when matched endpoint rows were truncated by max-endpoint limiting.</summary>
        public bool Truncated { get; set; }
        /// <summary>Gets or sets the violation endpoint count value.</summary>
        public int ViolationEndpointCount { get; set; }
        /// <summary>Gets or sets the compliant endpoint count value.</summary>
        public int CompliantEndpointCount { get; set; }
        /// <summary>Gets or sets the total violation count value.</summary>
        public int TotalViolationCount { get; set; }
        /// <summary>Gets or sets the critical violation count value.</summary>
        public int CriticalViolationCount { get; set; }
        /// <summary>Gets or sets the high violation count value.</summary>
        public int HighViolationCount { get; set; }
        /// <summary>Gets or sets the medium violation count value.</summary>
        public int MediumViolationCount { get; set; }
        /// <summary>Gets or sets the low violation count value.</summary>
        public int LowViolationCount { get; set; }
        /// <summary>Gets or sets the violation code counts value.</summary>
        public Dictionary<string, int> ViolationCodeCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Gets or sets the endpoints value.</summary>
        public List<CertificateInventoryEndpointPolicy> Endpoints { get; set; } = new();
    }

    /// <summary>
    /// Endpoint-level policy details.
    /// </summary>
    public sealed class CertificateInventoryEndpointPolicy {
        /// <summary>Gets or sets the host value.</summary>
        public string Host { get; set; } = string.Empty;
        /// <summary>Gets or sets the port value.</summary>
        public int Port { get; set; }
        /// <summary>Gets or sets the service value.</summary>
        public string Service { get; set; } = string.Empty;
        /// <summary>Gets or sets the issuer value.</summary>
        public string Issuer { get; set; } = string.Empty;
        /// <summary>Gets or sets the root issuer value.</summary>
        public string RootIssuer { get; set; } = string.Empty;
        /// <summary>Gets or sets the not before utc value.</summary>
        public DateTimeOffset? NotBeforeUtc { get; set; }
        /// <summary>Gets or sets the not after utc value.</summary>
        public DateTimeOffset? NotAfterUtc { get; set; }
        /// <summary>Gets or sets the days until valid value.</summary>
        public int? DaysUntilValid { get; set; }
        /// <summary>Gets or sets the days to expire value.</summary>
        public int? DaysToExpire { get; set; }
        /// <summary>Gets or sets the risk score value.</summary>
        public int RiskScore { get; set; }
        /// <summary>Gets or sets the risk severity value.</summary>
        public string RiskSeverity { get; set; } = "None";
        /// <summary>Gets or sets the valid value.</summary>
        public bool Valid { get; set; }
        /// <summary>Gets or sets the expired value.</summary>
        public bool Expired { get; set; }
        /// <summary>Gets or sets the not yet valid value.</summary>
        public bool NotYetValid { get; set; }
        /// <summary>Gets or sets the chain complete value.</summary>
        public bool ChainComplete { get; set; }
        /// <summary>Gets or sets the hostname match value.</summary>
        public bool HostnameMatch { get; set; }
        /// <summary>Gets or sets the is reachable value.</summary>
        public bool IsReachable { get; set; }
        /// <summary>Gets or sets the is self signed value.</summary>
        public bool IsSelfSigned { get; set; }
        /// <summary>Gets or sets the is known certificate authority value.</summary>
        public bool IsKnownCertificateAuthority { get; set; }
        /// <summary>Gets or sets the is known root certificate authority value.</summary>
        public bool IsKnownRootCertificateAuthority { get; set; }
        /// <summary>Gets or sets the present in ct logs value.</summary>
        public bool PresentInCtLogs { get; set; }
        /// <summary>Gets or sets the weak key value.</summary>
        public bool WeakKey { get; set; }
        /// <summary>Gets or sets the sha1 signature value.</summary>
        public bool Sha1Signature { get; set; }
        /// <summary>Gets or sets the allows server authentication value.</summary>
        public bool AllowsServerAuthentication { get; set; }
        /// <summary>Gets or sets the allows client authentication value.</summary>
        public bool AllowsClientAuthentication { get; set; }
        /// <summary>Gets or sets the allows secure email value.</summary>
        public bool AllowsSecureEmail { get; set; }
        /// <summary>Gets or sets the authentication profile value.</summary>
        public string AuthenticationProfile { get; set; } = string.Empty;
        /// <summary>Gets or sets the certificate reuse endpoint count value.</summary>
        public int CertificateReuseEndpointCount { get; set; }
        /// <summary>Gets or sets the certificate reuse distinct service count value.</summary>
        public int CertificateReuseDistinctServiceCount { get; set; }
        /// <summary>Gets or sets the certificate reuse distinct port count value.</summary>
        public int CertificateReuseDistinctPortCount { get; set; }
        /// <summary>Gets or sets the reuse policy scope value.</summary>
        public string ReusePolicyScope { get; set; } = "PublicAuthority";
        /// <summary>Gets or sets the effective max reuse endpoint count value.</summary>
        public int EffectiveMaxReuseEndpointCount { get; set; }
        /// <summary>Gets or sets the effective baseline profile value.</summary>
        public string EffectiveBaselineProfile { get; set; } = "Balanced";
        /// <summary>Gets or sets the suppressed violation codes value.</summary>
        public List<string> SuppressedViolationCodes { get; set; } = new();
        /// <summary>Gets or sets the applied policy override rules value.</summary>
        public List<string> AppliedPolicyOverrideRules { get; set; } = new();
        /// <summary>Gets or sets the compliant value.</summary>
        public bool Compliant { get; set; }
        /// <summary>Gets or sets the violation count value.</summary>
        public int ViolationCount { get; set; }
        /// <summary>Gets or sets the max violation severity value.</summary>
        public string MaxViolationSeverity { get; set; } = "None";
        /// <summary>Gets or sets the risk reasons value.</summary>
        public List<string> RiskReasons { get; set; } = new();
        /// <summary>Gets or sets the violations value.</summary>
        public List<CertificateInventoryPolicyViolation> Violations { get; set; } = new();
    }

    /// <summary>
    /// A single policy violation for one endpoint.
    /// </summary>
    public sealed class CertificateInventoryPolicyViolation {
        /// <summary>Gets or sets the code value.</summary>
        public string Code { get; set; } = string.Empty;
        /// <summary>Gets or sets the severity value.</summary>
        public string Severity { get; set; } = "Low";
        /// <summary>Gets or sets the message value.</summary>
        public string Message { get; set; } = string.Empty;
    }

    /// <summary>
    /// Evaluates certificate inventory endpoints against baseline policy profiles.
    /// </summary>
    public static class CertificateInventoryPolicyAnalyzer {
        private static readonly string[] BaselineProfileNames = { "Strict", "Balanced", "Legacy" };

        private sealed class BaselineProfileDefinition {
            public int RenewalWindowDays { get; set; }
            public int MaxReuseEndpointCount { get; set; }
            public int MaxKnownAuthorityReuseEndpointCount { get; set; }
            public int MaxPrivateAuthorityReuseEndpointCount { get; set; }
            public string ExpiringSoonSeverity { get; set; } = "Medium";
            public string ReuseEndpointFanoutSeverity { get; set; } = "Medium";
            public string CrossReuseSeverity { get; set; } = "Medium";
            public bool FlagUnknownAuthority { get; set; }
            public bool FlagUnknownRootAuthority { get; set; }
            public bool RequireCtForKnownAuthority { get; set; }
            public bool FlagClientAuthUsage { get; set; }
            public bool FlagSecureEmailUsage { get; set; }
            public bool FlagCrossServiceReuse { get; set; }
            public bool FlagCrossPortReuse { get; set; }
        }

        private static readonly Dictionary<string, BaselineProfileDefinition> BaselineProfileDefinitions =
            new(StringComparer.OrdinalIgnoreCase) {
                ["Strict"] = new BaselineProfileDefinition {
                    RenewalWindowDays = 45,
                    MaxReuseEndpointCount = 3,
                    MaxKnownAuthorityReuseEndpointCount = 3,
                    MaxPrivateAuthorityReuseEndpointCount = 12,
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
                    MaxKnownAuthorityReuseEndpointCount = 5,
                    MaxPrivateAuthorityReuseEndpointCount = 50,
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
                    MaxKnownAuthorityReuseEndpointCount = 10,
                    MaxPrivateAuthorityReuseEndpointCount = 200,
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

        /// <summary>Represents the baseline profile accepted values value.</summary>
        public static readonly string BaselineProfileAcceptedValues =
            string.Join(", ", BaselineProfileNames);

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

            foreach (var profile in BaselineProfileNames) {
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
            int maxEndpoints = 300,
            CertificateInventoryPolicyOverrides? policyOverrides = null) {
            if (maxEndpoints < 0) {
                throw new ArgumentOutOfRangeException(nameof(maxEndpoints), "maxEndpoints must be 0 or greater.");
            }

            var effectiveProfile = string.IsNullOrWhiteSpace(baselineProfile) ? "Balanced" : baselineProfile!;
            if (!TryResolveBaselineProfile(effectiveProfile, out var normalizedBaselineProfile)) {
                throw new ArgumentException($"baselineProfile must be one of: {BaselineProfileAcceptedValues}.", nameof(baselineProfile));
            }

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
                var resolvedOverride = policyOverrides?.ResolveForEndpoint(
                    endpoint.Host,
                    endpoint.Service,
                    endpoint.Port,
                    endpoint.Issuer,
                    endpoint.RootIssuer,
                    endpoint.AuthenticationProfile,
                    endpoint.IsKnownCertificateAuthority,
                    endpoint.IsKnownRootCertificateAuthority,
                    endpoint.PresentInCtLogs,
                    endpoint.IsSelfSigned,
                    endpoint.IsReachable,
                    normalizedBaselineProfile);

                var effectiveProfileName = resolvedOverride?.EffectiveBaselineProfile ?? normalizedBaselineProfile;
                if (!TryResolveBaselineProfile(effectiveProfileName, out var normalizedEffectiveProfileName)) {
                    throw new InvalidOperationException(
                        $"Policy override baseline profile '{effectiveProfileName}' must be one of: {BaselineProfileAcceptedValues}.");
                }

                var endpointProfile = ResolveEffectiveProfile(
                    BaselineProfileDefinitions[normalizedEffectiveProfileName],
                    resolvedOverride);
                var suppressedCodes = resolvedOverride?.SuppressedViolationCodes?.Count > 0
                    ? new HashSet<string>(resolvedOverride.SuppressedViolationCodes, StringComparer.OrdinalIgnoreCase)
                    : null;
                var appliedRules = resolvedOverride?.AppliedRuleNames ?? new List<string>();

                var row = EvaluateEndpoint(
                    endpoint,
                    endpointProfile,
                    normalizedEffectiveProfileName,
                    suppressedCodes,
                    appliedRules);

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

        private static BaselineProfileDefinition ResolveEffectiveProfile(
            BaselineProfileDefinition baseline,
            CertificateInventoryPolicyResolvedOverride? resolvedOverride) {
            return new BaselineProfileDefinition {
                RenewalWindowDays = resolvedOverride?.RenewalWindowDays ?? baseline.RenewalWindowDays,
                MaxReuseEndpointCount = resolvedOverride?.MaxReuseEndpointCount ?? baseline.MaxReuseEndpointCount,
                MaxKnownAuthorityReuseEndpointCount = resolvedOverride?.MaxKnownAuthorityReuseEndpointCount ??
                                                      resolvedOverride?.MaxReuseEndpointCount ??
                                                      baseline.MaxKnownAuthorityReuseEndpointCount,
                MaxPrivateAuthorityReuseEndpointCount = resolvedOverride?.MaxPrivateAuthorityReuseEndpointCount ??
                                                        resolvedOverride?.MaxReuseEndpointCount ??
                                                        baseline.MaxPrivateAuthorityReuseEndpointCount,
                ExpiringSoonSeverity = baseline.ExpiringSoonSeverity,
                ReuseEndpointFanoutSeverity = baseline.ReuseEndpointFanoutSeverity,
                CrossReuseSeverity = baseline.CrossReuseSeverity,
                FlagUnknownAuthority = resolvedOverride?.FlagUnknownAuthority ?? baseline.FlagUnknownAuthority,
                FlagUnknownRootAuthority = resolvedOverride?.FlagUnknownRootAuthority ?? baseline.FlagUnknownRootAuthority,
                RequireCtForKnownAuthority = resolvedOverride?.RequireCtForKnownAuthority ?? baseline.RequireCtForKnownAuthority,
                FlagClientAuthUsage = resolvedOverride?.FlagClientAuthUsage ?? baseline.FlagClientAuthUsage,
                FlagSecureEmailUsage = resolvedOverride?.FlagSecureEmailUsage ?? baseline.FlagSecureEmailUsage,
                FlagCrossServiceReuse = resolvedOverride?.FlagCrossServiceReuse ?? baseline.FlagCrossServiceReuse,
                FlagCrossPortReuse = resolvedOverride?.FlagCrossPortReuse ?? baseline.FlagCrossPortReuse
            };
        }

        private static CertificateInventoryEndpointPolicy EvaluateEndpoint(
            CertificateInventoryEndpointRisk endpoint,
            BaselineProfileDefinition profile,
            string effectiveBaselineProfile,
            HashSet<string>? suppressedViolationCodes,
            List<string> appliedPolicyOverrideRules) {
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
                ReusePolicyScope = ResolveReusePolicyScope(endpoint),
                EffectiveMaxReuseEndpointCount = ResolveMaxReuseEndpointCount(endpoint, profile),
                EffectiveBaselineProfile = effectiveBaselineProfile,
                SuppressedViolationCodes = suppressedViolationCodes == null
                    ? new List<string>()
                    : suppressedViolationCodes.OrderBy(code => code, StringComparer.OrdinalIgnoreCase).ToList(),
                AppliedPolicyOverrideRules = (appliedPolicyOverrideRules ?? new List<string>()).ToList(),
                RiskReasons = endpoint.Reasons.ToList()
            };

            if (!row.IsReachable) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.EndpointUnreachable,
                    "Critical",
                    "Endpoint is unreachable during certificate collection.",
                    suppressedViolationCodes);
            }

            if (row.NotYetValid) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.CertificateNotYetValid,
                    "Critical",
                    "Certificate validity window starts in the future.",
                    suppressedViolationCodes);
            }

            if (row.Expired) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.CertificateExpired,
                    "Critical",
                    "Certificate is expired.",
                    suppressedViolationCodes);
            } else if (row.DaysToExpire.HasValue && row.DaysToExpire.Value >= 0 && row.DaysToExpire.Value <= profile.RenewalWindowDays) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.CertificateExpiringSoon,
                    profile.ExpiringSoonSeverity,
                    $"Certificate expires within {profile.RenewalWindowDays} days.",
                    suppressedViolationCodes);
            }

            if (!row.Valid && row.IsReachable) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.CertificateValidationFailed,
                    "High",
                    "Certificate validation failed for reachable endpoint.",
                    suppressedViolationCodes);
            }

            if (!row.ChainComplete && row.IsReachable && !row.IsSelfSigned) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.ChainIncomplete,
                    "High",
                    "Certificate chain appears incomplete.",
                    suppressedViolationCodes);
            }

            if (!row.HostnameMatch && row.IsReachable) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.HostnameMismatch,
                    "High",
                    "Certificate subject/SAN does not match requested hostname.",
                    suppressedViolationCodes);
            }

            if (!row.AllowsServerAuthentication && row.IsReachable) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.MissingServerAuthEku,
                    "High",
                    "Certificate is missing Server Authentication EKU usage.",
                    suppressedViolationCodes);
            }

            if (row.IsSelfSigned) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.SelfSignedCertificate,
                    "High",
                    "Endpoint uses a self-signed certificate.",
                    suppressedViolationCodes);
            }

            if (row.WeakKey) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.WeakKey,
                    "High",
                    "Certificate key strength is below policy expectations.",
                    suppressedViolationCodes);
            }

            if (row.Sha1Signature) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.Sha1Signature,
                    "High",
                    "Certificate uses SHA-1 signature algorithm.",
                    suppressedViolationCodes);
            }

            if (profile.FlagUnknownAuthority && row.IsReachable && !row.IsSelfSigned && !row.IsKnownCertificateAuthority) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.UnknownAuthority,
                    "Medium",
                    "Certificate issuer is not recognized as a known public CA.",
                    suppressedViolationCodes);
            }

            if (profile.FlagUnknownRootAuthority && row.IsReachable && !row.IsSelfSigned && !row.IsKnownRootCertificateAuthority) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.UnknownRootAuthority,
                    "Medium",
                    "Certificate root issuer is not recognized as a known public root CA.",
                    suppressedViolationCodes);
            }

            if (profile.RequireCtForKnownAuthority && row.IsReachable && row.IsKnownCertificateAuthority && !row.PresentInCtLogs) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.CtNotObserved,
                    "Medium",
                    "Certificate was not observed in certificate transparency sources.",
                    suppressedViolationCodes);
            }

            if (profile.FlagClientAuthUsage && row.AllowsClientAuthentication) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.ClientAuthEkuPresent,
                    "Medium",
                    "Certificate allows Client Authentication EKU under strict baseline.",
                    suppressedViolationCodes);
            }

            if (profile.FlagSecureEmailUsage && row.AllowsSecureEmail) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.SecureEmailEkuPresent,
                    "Low",
                    "Certificate allows Secure Email EKU under strict baseline.",
                    suppressedViolationCodes);
            }

            if (row.CertificateReuseEndpointCount > row.EffectiveMaxReuseEndpointCount) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.ReuseEndpointFanout,
                    profile.ReuseEndpointFanoutSeverity,
                    $"Certificate is reused by {row.CertificateReuseEndpointCount} endpoints ({row.ReusePolicyScope} policy max {row.EffectiveMaxReuseEndpointCount}).",
                    suppressedViolationCodes);
            }

            if (profile.FlagCrossServiceReuse && row.CertificateReuseDistinctServiceCount > 1) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.ReuseCrossService,
                    profile.CrossReuseSeverity,
                    "Certificate is reused across multiple services.",
                    suppressedViolationCodes);
            }

            if (profile.FlagCrossPortReuse && row.CertificateReuseDistinctPortCount > 1) {
                AddViolation(
                    row.Violations,
                    CertificateInventoryPolicyViolationCodes.ReuseCrossPort,
                    profile.CrossReuseSeverity,
                    "Certificate is reused across multiple ports.",
                    suppressedViolationCodes);
            }

            row.ViolationCount = row.Violations.Count;
            row.MaxViolationSeverity = PickMaxSeverity(row.Violations);
            row.Compliant = row.ViolationCount == 0;
            return row;
        }

        private static string ResolveReusePolicyScope(CertificateInventoryEndpointRisk endpoint) {
            if (endpoint.IsKnownCertificateAuthority && !endpoint.IsSelfSigned) {
                return "PublicAuthority";
            }

            return "PrivateOrInternal";
        }

        private static int ResolveMaxReuseEndpointCount(
            CertificateInventoryEndpointRisk endpoint,
            BaselineProfileDefinition profile) {
            return string.Equals(ResolveReusePolicyScope(endpoint), "PublicAuthority", StringComparison.OrdinalIgnoreCase)
                ? profile.MaxKnownAuthorityReuseEndpointCount
                : profile.MaxPrivateAuthorityReuseEndpointCount;
        }

        private static void AddViolation(
            List<CertificateInventoryPolicyViolation> violations,
            string code,
            string severity,
            string message,
            HashSet<string>? suppressedViolationCodes = null) {
            if (suppressedViolationCodes != null &&
                suppressedViolationCodes.Contains(code)) {
                return;
            }

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
