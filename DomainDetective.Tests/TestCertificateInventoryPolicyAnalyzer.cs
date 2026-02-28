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
            Assert.True(policy.TotalViolationCount >= 4);
            Assert.True(policy.CriticalViolationCount >= 1);
            Assert.True(policy.ViolationCodeCounts.TryGetValue(CertificateInventoryPolicyViolationCodes.CertificateExpired, out var expiredCount) && expiredCount == 1);
            Assert.True(policy.ViolationCodeCounts.ContainsKey(CertificateInventoryPolicyViolationCodes.WeakKey));
            Assert.True(policy.ViolationCodeCounts.ContainsKey(CertificateInventoryPolicyViolationCodes.HostnameMismatch));
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
