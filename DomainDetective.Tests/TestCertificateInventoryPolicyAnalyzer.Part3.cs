using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Tests {
    public partial class TestCertificateInventoryPolicyAnalyzer {
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
