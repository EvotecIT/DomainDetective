using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Tests {
    public class TestCertificateInventoryPolicyAnalyzer {
        [Fact]
        public void TryResolveBaselineProfileSupportsCaseInsensitiveValues() {
            Assert.True(CertificateInventoryPolicyAnalyzer.TryResolveBaselineProfile("strict", out var strict));
            Assert.Equal("Strict", strict);

            Assert.True(CertificateInventoryPolicyAnalyzer.TryResolveBaselineProfile("BALANCED", out var balanced));
            Assert.Equal("Balanced", balanced);

            Assert.True(CertificateInventoryPolicyAnalyzer.TryResolveBaselineProfile("Legacy", out var legacy));
            Assert.Equal("Legacy", legacy);

            Assert.False(CertificateInventoryPolicyAnalyzer.TryResolveBaselineProfile("", out _));
            Assert.False(CertificateInventoryPolicyAnalyzer.TryResolveBaselineProfile("Unknown", out _));
        }

        [Fact]
        public void BuildPolicyThrowsForInvalidBaselineProfile() {
            var ex = Assert.Throws<ArgumentException>(() => CertificateInventoryPolicyAnalyzer.BuildPolicy(
                snapshots: Array.Empty<CertificateInventorySnapshot>(),
                baselineProfile: "InvalidProfile"));
            Assert.Equal("baselineProfile", ex.ParamName);
        }

        [Fact]
        public void BuildPolicyAppliesStrictnessDifferencesAcrossProfiles() {
            var now = DateTimeOffset.UtcNow;
            const string reusedThumbprint = "ABCDEF00112233445566778899AABBCCDDEEFF00";
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        BuildReusableEntry(now, "api1.example.com", 443, "HTTPS", reusedThumbprint),
                        BuildReusableEntry(now, "api2.example.com", 8443, "HTTPS-Alt", reusedThumbprint),
                        BuildReusableEntry(now, "smtp1.example.com", 465, "SMTPS", reusedThumbprint)
                    }
                }
            };

            var strict = CertificateInventoryPolicyAnalyzer.BuildPolicy(
                snapshots,
                baselineProfile: "Strict",
                includeCompliant: true,
                maxEndpoints: 100);
            var balanced = CertificateInventoryPolicyAnalyzer.BuildPolicy(
                snapshots,
                baselineProfile: "Balanced",
                includeCompliant: true,
                maxEndpoints: 100);
            var legacy = CertificateInventoryPolicyAnalyzer.BuildPolicy(
                snapshots,
                baselineProfile: "Legacy",
                includeCompliant: true,
                maxEndpoints: 100);

            Assert.Equal(3, strict.EndpointCount);
            Assert.Equal(3, balanced.EndpointCount);
            Assert.Equal(3, legacy.EndpointCount);

            Assert.Equal(3, strict.ViolationEndpointCount);
            Assert.Equal(3, balanced.ViolationEndpointCount);
            Assert.Equal(0, legacy.ViolationEndpointCount);

            var strictEndpoint = strict.Endpoints.Single(endpoint => endpoint.Host == "api1.example.com");
            Assert.Contains(strictEndpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.CtNotObserved);
            Assert.Contains(strictEndpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.ClientAuthEkuPresent);
            Assert.Contains(strictEndpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.SecureEmailEkuPresent);
            Assert.Contains(strictEndpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.ReuseCrossService);
            Assert.Contains(strictEndpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.ReuseCrossPort);

            var balancedEndpoint = balanced.Endpoints.Single(endpoint => endpoint.Host == "api1.example.com");
            Assert.Contains(balancedEndpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.CtNotObserved);
            Assert.Contains(balancedEndpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.ReuseCrossService);
            Assert.DoesNotContain(balancedEndpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.ClientAuthEkuPresent);
            Assert.DoesNotContain(balancedEndpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.SecureEmailEkuPresent);
            Assert.DoesNotContain(balancedEndpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.ReuseCrossPort);

            var legacyEndpoint = legacy.Endpoints.Single(endpoint => endpoint.Host == "api1.example.com");
            Assert.True(legacyEndpoint.Compliant);
            Assert.Equal(0, legacyEndpoint.ViolationCount);
        }

        [Fact]
        public void BuildPolicyExcludesCompliantEndpointsByDefault() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "healthy.example.com",
                            ResolvedHost = "healthy.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(-30),
                            NotAfterUtc = now.AddDays(180),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            IsSelfSigned = false,
                            IsKnownCertificateAuthority = true,
                            IsKnownRootCertificateAuthority = true,
                            PresentInCtLogs = true,
                            AllowsServerAuthentication = true,
                            AllowsClientAuthentication = false,
                            AllowsSecureEmail = false,
                            CertificateIssuerNormalized = "Issuer Healthy",
                            CertificateRootIssuerNormalized = "Root Healthy",
                            CertificateThumbprint = "00112233445566778899AABBCCDDEEFF00112233"
                        }
                    }
                }
            };

            var policy = CertificateInventoryPolicyAnalyzer.BuildPolicy(
                snapshots,
                baselineProfile: "Balanced",
                includeCompliant: false,
                maxEndpoints: 100);

            Assert.Equal(1, policy.EndpointCount);
            Assert.Equal(0, policy.ViolationEndpointCount);
            Assert.Equal(1, policy.CompliantEndpointCount);
            Assert.Equal(0, policy.MatchedEndpointCount);
            Assert.Empty(policy.Endpoints);
        }

        [Fact]
        public void BuildPolicySummarizesViolationCodeAndSeverityCounts() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "expired.example.com",
                            ResolvedHost = "expired.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(-90),
                            NotAfterUtc = now.AddDays(-2),
                            Valid = false,
                            Expired = true,
                            ChainComplete = false,
                            IsReachable = true,
                            HostnameMatch = false,
                            IsSelfSigned = false,
                            IsKnownCertificateAuthority = true,
                            IsKnownRootCertificateAuthority = true,
                            PresentInCtLogs = true,
                            AllowsServerAuthentication = false,
                            WeakKey = true,
                            CertificateIssuerNormalized = "Issuer Expired",
                            CertificateRootIssuerNormalized = "Root Expired",
                            CertificateThumbprint = "AA11223344556677889900AABBCCDDEEFF001122"
                        }
                    }
                }
            };

            var policy = CertificateInventoryPolicyAnalyzer.BuildPolicy(
                snapshots,
                baselineProfile: "Balanced",
                includeCompliant: false,
                maxEndpoints: 100);

            Assert.Equal(1, policy.EndpointCount);
            Assert.Equal(1, policy.ViolationEndpointCount);
            Assert.Equal(0, policy.CompliantEndpointCount);
            Assert.Equal(6, policy.TotalViolationCount);
            Assert.Equal(1, policy.CriticalViolationCount);
            Assert.Equal(5, policy.HighViolationCount);
            Assert.Equal(0, policy.MediumViolationCount);
            Assert.Equal(0, policy.LowViolationCount);
            Assert.True(policy.ViolationCodeCounts.TryGetValue(CertificateInventoryPolicyViolationCodes.CertificateExpired, out var expiredCount) && expiredCount == 1);
            Assert.True(policy.ViolationCodeCounts.ContainsKey(CertificateInventoryPolicyViolationCodes.WeakKey));
            Assert.True(policy.ViolationCodeCounts.ContainsKey(CertificateInventoryPolicyViolationCodes.HostnameMismatch));
        }

        [Fact]
        public void BuildPolicyHandlesNullSnapshotsAsEmptySummary() {
            var policy = CertificateInventoryPolicyAnalyzer.BuildPolicy(
                snapshots: null,
                baselineProfile: "Balanced",
                includeCompliant: true,
                maxEndpoints: 100);

            Assert.Equal("Balanced", policy.BaselineProfile);
            Assert.Equal(0, policy.SnapshotCount);
            Assert.Equal(0, policy.EndpointCount);
            Assert.Equal(0, policy.ViolationEndpointCount);
            Assert.Equal(0, policy.TotalViolationCount);
            Assert.Equal(0, policy.MatchedEndpointCount);
            Assert.False(policy.Truncated);
            Assert.Empty(policy.Endpoints);
        }

        [Fact]
        public void BuildPolicySupportsMaxEndpointsZero() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        BuildReusableEntry(now, "zero-1.example.com", 443, "HTTPS", "00AA223344556677889900AABBCCDDEEFF001122"),
                        BuildReusableEntry(now, "zero-2.example.com", 443, "HTTPS", "11AA223344556677889900AABBCCDDEEFF001122")
                    }
                }
            };

            var policy = CertificateInventoryPolicyAnalyzer.BuildPolicy(
                snapshots,
                baselineProfile: "Balanced",
                includeCompliant: false,
                maxEndpoints: 0);

            Assert.Equal(2, policy.EndpointCount);
            Assert.Equal(2, policy.ViolationEndpointCount);
            Assert.Equal(2, policy.MatchedEndpointCount);
            Assert.True(policy.Truncated);
            Assert.Equal(2, policy.EndpointsTruncatedByMaxEndpoints);
            Assert.Empty(policy.Endpoints);
        }

        [Fact]
        public void BuildPolicyTracksTruncationCounters() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        BuildReusableEntry(now, "truncate-1.example.com", 443, "HTTPS", "AAAB223344556677889900AABBCCDDEEFF001122"),
                        BuildReusableEntry(now, "truncate-2.example.com", 443, "HTTPS", "BBAB223344556677889900AABBCCDDEEFF001122"),
                        BuildReusableEntry(now, "truncate-3.example.com", 443, "HTTPS", "CCAB223344556677889900AABBCCDDEEFF001122")
                    }
                }
            };

            var policy = CertificateInventoryPolicyAnalyzer.BuildPolicy(
                snapshots,
                baselineProfile: "Balanced",
                includeCompliant: false,
                maxEndpoints: 1);

            Assert.Equal(3, policy.MatchedEndpointCount);
            Assert.True(policy.Truncated);
            Assert.Equal(2, policy.EndpointsTruncatedByMaxEndpoints);
            Assert.Single(policy.Endpoints);
        }

        [Fact]
        public void BuildPolicyAppliesHostSuffixOverrideAndSuppression() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "api.example.com",
                            ResolvedHost = "api.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(-30),
                            NotAfterUtc = now.AddDays(120),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            IsSelfSigned = false,
                            IsKnownCertificateAuthority = true,
                            IsKnownRootCertificateAuthority = true,
                            PresentInCtLogs = false,
                            AllowsServerAuthentication = true,
                            AllowsClientAuthentication = true,
                            AllowsSecureEmail = true,
                            CertificateIssuerNormalized = "Issuer Override",
                            CertificateRootIssuerNormalized = "Root Override",
                            CertificateThumbprint = "11AA223344556677889900AABBCCDDEEFF001122"
                        }
                    }
                }
            };
            var overrides = new CertificateInventoryPolicyOverrides {
                Rules = new List<CertificateInventoryPolicyOverrideRule> {
                    new() {
                        Name = "strict-example",
                        Match = new CertificateInventoryPolicyOverrideMatch {
                            HostSuffixes = new[] { "example.com" }
                        },
                        Action = new CertificateInventoryPolicyOverrideAction {
                            BaselineProfile = "Strict",
                            SuppressViolationCodes = new[] { CertificateInventoryPolicyViolationCodes.CtNotObserved }
                        }
                    }
                }
            };

            var policy = CertificateInventoryPolicyAnalyzer.BuildPolicy(
                snapshots,
                baselineProfile: "Balanced",
                includeCompliant: true,
                maxEndpoints: 100,
                policyOverrides: overrides);

            var endpoint = policy.Endpoints.Single();
            Assert.Equal("Strict", endpoint.EffectiveBaselineProfile);
            Assert.Contains("strict-example", endpoint.AppliedPolicyOverrideRules);
            Assert.Contains(CertificateInventoryPolicyViolationCodes.CtNotObserved, endpoint.SuppressedViolationCodes);
            Assert.DoesNotContain(endpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.CtNotObserved);
            Assert.Contains(endpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.ClientAuthEkuPresent);
            Assert.Contains(endpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.SecureEmailEkuPresent);
        }

        [Fact]
        public void BuildPolicySupportsInternalEndpointFlagOverrides() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "internal-known.example.com",
                            ResolvedHost = "internal-known.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(-5),
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            IsSelfSigned = false,
                            IsKnownCertificateAuthority = true,
                            IsKnownRootCertificateAuthority = true,
                            PresentInCtLogs = false,
                            AllowsServerAuthentication = true,
                            AllowsClientAuthentication = true,
                            AllowsSecureEmail = true,
                            CertificateIssuerNormalized = "Corp Internal Issuer",
                            CertificateRootIssuerNormalized = "Corp Internal Root",
                            CertificateThumbprint = "32AA223344556677889900AABBCCDDEEFF001122"
                        },
                        new() {
                            Host = "internal-unknown.example.com",
                            ResolvedHost = "internal-unknown.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(-5),
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            IsSelfSigned = false,
                            IsKnownCertificateAuthority = false,
                            IsKnownRootCertificateAuthority = false,
                            PresentInCtLogs = false,
                            AllowsServerAuthentication = true,
                            AllowsClientAuthentication = true,
                            AllowsSecureEmail = true,
                            CertificateIssuerNormalized = "Corp Unknown Issuer",
                            CertificateRootIssuerNormalized = "Corp Unknown Root",
                            CertificateThumbprint = "33AA223344556677889900AABBCCDDEEFF001122"
                        }
                    }
                }
            };

            var strictWithoutOverrides = CertificateInventoryPolicyAnalyzer.BuildPolicy(
                snapshots,
                baselineProfile: "Strict",
                includeCompliant: true,
                maxEndpoints: 100);
            var baselineKnown = strictWithoutOverrides.Endpoints.Single(endpoint => endpoint.Host == "internal-known.example.com");
            Assert.Contains(baselineKnown.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.CtNotObserved);
            Assert.Contains(baselineKnown.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.ClientAuthEkuPresent);
            Assert.Contains(baselineKnown.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.SecureEmailEkuPresent);

            var baselineUnknown = strictWithoutOverrides.Endpoints.Single(endpoint => endpoint.Host == "internal-unknown.example.com");
            Assert.Contains(baselineUnknown.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.UnknownAuthority);
            Assert.Contains(baselineUnknown.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.UnknownRootAuthority);
            Assert.Contains(baselineUnknown.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.ClientAuthEkuPresent);
            Assert.Contains(baselineUnknown.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.SecureEmailEkuPresent);

            var overrides = new CertificateInventoryPolicyOverrides {
                Rules = new List<CertificateInventoryPolicyOverrideRule> {
                    new() {
                        Name = "internal-pki-relaxed",
                        Match = new CertificateInventoryPolicyOverrideMatch {
                            HostSuffixes = new[] { "example.com" }
                        },
                        Action = new CertificateInventoryPolicyOverrideAction {
                            RequireCtForKnownAuthority = false,
                            FlagUnknownAuthority = false,
                            FlagUnknownRootAuthority = false,
                            FlagClientAuthUsage = false,
                            FlagSecureEmailUsage = false
                        }
                    }
                }
            };

            var strictWithOverrides = CertificateInventoryPolicyAnalyzer.BuildPolicy(
                snapshots,
                baselineProfile: "Strict",
                includeCompliant: true,
                maxEndpoints: 100,
                policyOverrides: overrides);
            var overriddenKnown = strictWithOverrides.Endpoints.Single(endpoint => endpoint.Host == "internal-known.example.com");
            Assert.Contains("internal-pki-relaxed", overriddenKnown.AppliedPolicyOverrideRules);
            Assert.DoesNotContain(overriddenKnown.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.CtNotObserved);
            Assert.DoesNotContain(overriddenKnown.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.ClientAuthEkuPresent);
            Assert.DoesNotContain(overriddenKnown.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.SecureEmailEkuPresent);

            var overriddenUnknown = strictWithOverrides.Endpoints.Single(endpoint => endpoint.Host == "internal-unknown.example.com");
            Assert.Contains("internal-pki-relaxed", overriddenUnknown.AppliedPolicyOverrideRules);
            Assert.DoesNotContain(overriddenUnknown.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.UnknownAuthority);
            Assert.DoesNotContain(overriddenUnknown.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.UnknownRootAuthority);
            Assert.DoesNotContain(overriddenUnknown.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.ClientAuthEkuPresent);
            Assert.DoesNotContain(overriddenUnknown.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.SecureEmailEkuPresent);
        }

        [Fact]
        public void BuildPolicySupportsRenewalWindowAndReuseThresholdOverrides() {
            var now = DateTimeOffset.UtcNow;
            const string sharedThumbprint = "44AA223344556677889900AABBCCDDEEFF001122";
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "reuse1.example.com",
                            ResolvedHost = "reuse1.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(-30),
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            IsSelfSigned = false,
                            IsKnownCertificateAuthority = true,
                            IsKnownRootCertificateAuthority = true,
                            PresentInCtLogs = true,
                            AllowsServerAuthentication = true,
                            AllowsClientAuthentication = false,
                            AllowsSecureEmail = false,
                            CertificateIssuerNormalized = "Issuer Reuse",
                            CertificateRootIssuerNormalized = "Root Reuse",
                            CertificateThumbprint = sharedThumbprint
                        },
                        new() {
                            Host = "reuse2.example.com",
                            ResolvedHost = "reuse2.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(-30),
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            IsSelfSigned = false,
                            IsKnownCertificateAuthority = true,
                            IsKnownRootCertificateAuthority = true,
                            PresentInCtLogs = true,
                            AllowsServerAuthentication = true,
                            AllowsClientAuthentication = false,
                            AllowsSecureEmail = false,
                            CertificateIssuerNormalized = "Issuer Reuse",
                            CertificateRootIssuerNormalized = "Root Reuse",
                            CertificateThumbprint = sharedThumbprint
                        }
                    }
                }
            };

            var baseline = CertificateInventoryPolicyAnalyzer.BuildPolicy(
                snapshots,
                baselineProfile: "Balanced",
                includeCompliant: true,
                maxEndpoints: 100);
            var baselineEndpoint = baseline.Endpoints.Single(endpoint => endpoint.Host == "reuse1.example.com");
            Assert.DoesNotContain(baselineEndpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.CertificateExpiringSoon);
            Assert.DoesNotContain(baselineEndpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.ReuseEndpointFanout);

            var overrides = new CertificateInventoryPolicyOverrides {
                Rules = new List<CertificateInventoryPolicyOverrideRule> {
                    new() {
                        Name = "tight-reuse-window",
                        Match = new CertificateInventoryPolicyOverrideMatch {
                            HostSuffixes = new[] { "example.com" }
                        },
                        Action = new CertificateInventoryPolicyOverrideAction {
                            RenewalWindowDays = 120,
                            MaxReuseEndpointCount = 1
                        }
                    }
                }
            };

            var withOverrides = CertificateInventoryPolicyAnalyzer.BuildPolicy(
                snapshots,
                baselineProfile: "Balanced",
                includeCompliant: true,
                maxEndpoints: 100,
                policyOverrides: overrides);
            var overriddenEndpoint = withOverrides.Endpoints.Single(endpoint => endpoint.Host == "reuse1.example.com");
            Assert.Contains("tight-reuse-window", overriddenEndpoint.AppliedPolicyOverrideRules);
            Assert.Contains(overriddenEndpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.CertificateExpiringSoon);
            Assert.Contains(overriddenEndpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.ReuseEndpointFanout);
        }

        [Fact]
        public void BuildPolicySupportsIssuerContainsOverrideMatching() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "issuer-match.example.com",
                            ResolvedHost = "issuer-match.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(-30),
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            IsSelfSigned = false,
                            IsKnownCertificateAuthority = false,
                            IsKnownRootCertificateAuthority = false,
                            PresentInCtLogs = false,
                            AllowsServerAuthentication = true,
                            AllowsClientAuthentication = false,
                            AllowsSecureEmail = false,
                            CertificateIssuerNormalized = "Corp Internal Issuing CA",
                            CertificateRootIssuerNormalized = "Corp Internal Root CA",
                            CertificateThumbprint = "66AA223344556677889900AABBCCDDEEFF001122"
                        }
                    }
                }
            };

            var strict = CertificateInventoryPolicyAnalyzer.BuildPolicy(
                snapshots,
                baselineProfile: "Strict",
                includeCompliant: true,
                maxEndpoints: 100);
            var baselineEndpoint = strict.Endpoints.Single();
            Assert.Contains(baselineEndpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.UnknownAuthority);
            Assert.Contains(baselineEndpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.UnknownRootAuthority);

            var overrides = new CertificateInventoryPolicyOverrides {
                Rules = new List<CertificateInventoryPolicyOverrideRule> {
                    new() {
                        Name = "issuer-based-internal-pki",
                        Match = new CertificateInventoryPolicyOverrideMatch {
                            IssuerContainsAnyOf = new[] { "corp internal" }
                        },
                        Action = new CertificateInventoryPolicyOverrideAction {
                            FlagUnknownAuthority = false,
                            FlagUnknownRootAuthority = false
                        }
                    }
                }
            };

            var strictWithOverride = CertificateInventoryPolicyAnalyzer.BuildPolicy(
                snapshots,
                baselineProfile: "Strict",
                includeCompliant: true,
                maxEndpoints: 100,
                policyOverrides: overrides);
            var endpoint = strictWithOverride.Endpoints.Single();
            Assert.Contains("issuer-based-internal-pki", endpoint.AppliedPolicyOverrideRules);
            Assert.DoesNotContain(endpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.UnknownAuthority);
            Assert.DoesNotContain(endpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.UnknownRootAuthority);
            Assert.True(endpoint.Compliant);
        }

        [Fact]
        public void BuildPolicySupportsAuthenticationProfileOverrideMatching() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "auth-profile.example.com",
                            ResolvedHost = "auth-profile.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(-30),
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            IsSelfSigned = false,
                            IsKnownCertificateAuthority = true,
                            IsKnownRootCertificateAuthority = true,
                            PresentInCtLogs = true,
                            AllowsServerAuthentication = true,
                            AllowsClientAuthentication = true,
                            AllowsSecureEmail = false,
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAndClientAuth,
                            CertificateIssuerNormalized = "Issuer Auth Profile",
                            CertificateRootIssuerNormalized = "Root Auth Profile",
                            CertificateThumbprint = "67AA223344556677889900AABBCCDDEEFF001122"
                        }
                    }
                }
            };

            var strict = CertificateInventoryPolicyAnalyzer.BuildPolicy(
                snapshots,
                baselineProfile: "Strict",
                includeCompliant: true,
                maxEndpoints: 100);
            var baselineEndpoint = strict.Endpoints.Single();
            Assert.Contains(baselineEndpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.ClientAuthEkuPresent);

            var overrides = new CertificateInventoryPolicyOverrides {
                Rules = new List<CertificateInventoryPolicyOverrideRule> {
                    new() {
                        Name = "disable-client-auth-flag-for-server-and-client-profile",
                        Match = new CertificateInventoryPolicyOverrideMatch {
                            AuthenticationProfiles = new[] { CertificateAuthenticationProfileClassifier.ServerAndClientAuth }
                        },
                        Action = new CertificateInventoryPolicyOverrideAction {
                            FlagClientAuthUsage = false
                        }
                    }
                }
            };

            var strictWithOverride = CertificateInventoryPolicyAnalyzer.BuildPolicy(
                snapshots,
                baselineProfile: "Strict",
                includeCompliant: true,
                maxEndpoints: 100,
                policyOverrides: overrides);
            var endpoint = strictWithOverride.Endpoints.Single();
            Assert.Contains("disable-client-auth-flag-for-server-and-client-profile", endpoint.AppliedPolicyOverrideRules);
            Assert.DoesNotContain(endpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.ClientAuthEkuPresent);
            Assert.True(endpoint.Compliant);
        }

        [Fact]
        public void BuildPolicySupportsKnownAuthorityOverrideMatching() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "known-ca.example.com",
                            ResolvedHost = "known-ca.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(-30),
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            IsSelfSigned = false,
                            IsKnownCertificateAuthority = true,
                            IsKnownRootCertificateAuthority = true,
                            PresentInCtLogs = false,
                            AllowsServerAuthentication = true,
                            AllowsClientAuthentication = false,
                            AllowsSecureEmail = false,
                            CertificateIssuerNormalized = "Known Issuer",
                            CertificateRootIssuerNormalized = "Known Root",
                            CertificateThumbprint = "68AA223344556677889900AABBCCDDEEFF001122"
                        },
                        new() {
                            Host = "unknown-ca.example.com",
                            ResolvedHost = "unknown-ca.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(-30),
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            IsSelfSigned = false,
                            IsKnownCertificateAuthority = false,
                            IsKnownRootCertificateAuthority = false,
                            PresentInCtLogs = false,
                            AllowsServerAuthentication = true,
                            AllowsClientAuthentication = false,
                            AllowsSecureEmail = false,
                            CertificateIssuerNormalized = "Unknown Issuer",
                            CertificateRootIssuerNormalized = "Unknown Root",
                            CertificateThumbprint = "69AA223344556677889900AABBCCDDEEFF001122"
                        }
                    }
                }
            };

            var overrides = new CertificateInventoryPolicyOverrides {
                Rules = new List<CertificateInventoryPolicyOverrideRule> {
                    new() {
                        Name = "disable-ct-only-for-known-ca",
                        Match = new CertificateInventoryPolicyOverrideMatch {
                            KnownCertificateAuthority = true
                        },
                        Action = new CertificateInventoryPolicyOverrideAction {
                            RequireCtForKnownAuthority = false
                        }
                    }
                }
            };

            var policy = CertificateInventoryPolicyAnalyzer.BuildPolicy(
                snapshots,
                baselineProfile: "Strict",
                includeCompliant: true,
                maxEndpoints: 100,
                policyOverrides: overrides);

            var knownEndpoint = policy.Endpoints.Single(endpoint => endpoint.Host == "known-ca.example.com");
            Assert.Contains("disable-ct-only-for-known-ca", knownEndpoint.AppliedPolicyOverrideRules);
            Assert.DoesNotContain(knownEndpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.CtNotObserved);

            var unknownEndpoint = policy.Endpoints.Single(endpoint => endpoint.Host == "unknown-ca.example.com");
            Assert.DoesNotContain("disable-ct-only-for-known-ca", unknownEndpoint.AppliedPolicyOverrideRules);
            Assert.Contains(unknownEndpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.UnknownAuthority);
        }

        [Fact]
        public void BuildPolicySupportsCtObservedOverrideMatching() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "ct-observed.example.com",
                            ResolvedHost = "ct-observed.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(-30),
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            IsSelfSigned = false,
                            IsKnownCertificateAuthority = true,
                            IsKnownRootCertificateAuthority = true,
                            PresentInCtLogs = true,
                            AllowsServerAuthentication = true,
                            AllowsClientAuthentication = true,
                            AllowsSecureEmail = false,
                            CertificateIssuerNormalized = "Observed Issuer",
                            CertificateRootIssuerNormalized = "Observed Root",
                            CertificateThumbprint = "70AA223344556677889900AABBCCDDEEFF001122"
                        },
                        new() {
                            Host = "ct-missing.example.com",
                            ResolvedHost = "ct-missing.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(-30),
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            IsSelfSigned = false,
                            IsKnownCertificateAuthority = true,
                            IsKnownRootCertificateAuthority = true,
                            PresentInCtLogs = false,
                            AllowsServerAuthentication = true,
                            AllowsClientAuthentication = true,
                            AllowsSecureEmail = false,
                            CertificateIssuerNormalized = "Missing Issuer",
                            CertificateRootIssuerNormalized = "Missing Root",
                            CertificateThumbprint = "71AA223344556677889900AABBCCDDEEFF001122"
                        }
                    }
                }
            };

            var overrides = new CertificateInventoryPolicyOverrides {
                Rules = new List<CertificateInventoryPolicyOverrideRule> {
                    new() {
                        Name = "disable-client-auth-when-ct-observed",
                        Match = new CertificateInventoryPolicyOverrideMatch {
                            CtObserved = true
                        },
                        Action = new CertificateInventoryPolicyOverrideAction {
                            FlagClientAuthUsage = false
                        }
                    }
                }
            };

            var policy = CertificateInventoryPolicyAnalyzer.BuildPolicy(
                snapshots,
                baselineProfile: "Strict",
                includeCompliant: true,
                maxEndpoints: 100,
                policyOverrides: overrides);

            var observedEndpoint = policy.Endpoints.Single(endpoint => endpoint.Host == "ct-observed.example.com");
            Assert.Contains("disable-client-auth-when-ct-observed", observedEndpoint.AppliedPolicyOverrideRules);
            Assert.DoesNotContain(observedEndpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.ClientAuthEkuPresent);

            var missingEndpoint = policy.Endpoints.Single(endpoint => endpoint.Host == "ct-missing.example.com");
            Assert.DoesNotContain("disable-client-auth-when-ct-observed", missingEndpoint.AppliedPolicyOverrideRules);
            Assert.Contains(missingEndpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.ClientAuthEkuPresent);
        }

        [Fact]
        public void BuildPolicySuppressesDefaultViolationCodes() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "suppressed.example.com",
                            ResolvedHost = "suppressed.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(-30),
                            NotAfterUtc = now.AddDays(120),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            IsSelfSigned = false,
                            IsKnownCertificateAuthority = true,
                            IsKnownRootCertificateAuthority = true,
                            PresentInCtLogs = true,
                            AllowsServerAuthentication = true,
                            AllowsClientAuthentication = false,
                            AllowsSecureEmail = false,
                            WeakKey = true,
                            CertificateIssuerNormalized = "Issuer Suppressed",
                            CertificateRootIssuerNormalized = "Root Suppressed",
                            CertificateThumbprint = "22AA223344556677889900AABBCCDDEEFF001122"
                        }
                    }
                }
            };
            var overrides = new CertificateInventoryPolicyOverrides {
                Defaults = new CertificateInventoryPolicyOverrideAction {
                    SuppressViolationCodes = new[] { CertificateInventoryPolicyViolationCodes.WeakKey }
                }
            };

            var policy = CertificateInventoryPolicyAnalyzer.BuildPolicy(
                snapshots,
                baselineProfile: "Balanced",
                includeCompliant: true,
                maxEndpoints: 100,
                policyOverrides: overrides);

            var endpoint = policy.Endpoints.Single();
            Assert.True(endpoint.Compliant);
            Assert.Equal(0, endpoint.ViolationCount);
            Assert.Contains(CertificateInventoryPolicyViolationCodes.WeakKey, endpoint.SuppressedViolationCodes);
            Assert.DoesNotContain(endpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.WeakKey);
        }

        private static CertificateInventoryEntry BuildReusableEntry(
            DateTimeOffset now,
            string host,
            int port,
            string service,
            string thumbprint) {
            return new CertificateInventoryEntry {
                Host = host,
                ResolvedHost = host,
                Port = port,
                Service = service,
                NotBeforeUtc = now.AddDays(-30),
                NotAfterUtc = now.AddDays(120),
                Valid = true,
                Expired = false,
                ChainComplete = true,
                IsReachable = true,
                HostnameMatch = true,
                IsSelfSigned = false,
                IsKnownCertificateAuthority = true,
                IsKnownRootCertificateAuthority = true,
                PresentInCtLogs = false,
                AllowsServerAuthentication = true,
                AllowsClientAuthentication = true,
                AllowsSecureEmail = true,
                CertificateIssuerNormalized = "Issuer Reused",
                CertificateRootIssuerNormalized = "Root Reused",
                CertificateThumbprint = thumbprint
            };
        }
    }
}
