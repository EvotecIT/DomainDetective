using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Tests {
    public partial class TestCertificateInventoryPolicyAnalyzer {
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

    }
}
