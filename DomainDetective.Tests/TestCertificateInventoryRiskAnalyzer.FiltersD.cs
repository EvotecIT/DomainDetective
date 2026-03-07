using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Tests {
    public partial class TestCertificateInventoryRiskAnalyzer {
        [Fact]
        public void BuildRiskFiltersReturnedEndpointsBySelfSignedAndCryptoState() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "selfsigned-weak-sha1.example.com",
                            ResolvedHost = "selfsigned-weak-sha1.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(45),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsSelfSigned = true,
                            IsKnownCertificateAuthority = false,
                            PresentInCtLogs = false,
                            WeakKey = true,
                            Sha1Signature = true
                        },
                        new() {
                            Host = "casigned-strong-modern.example.com",
                            ResolvedHost = "casigned-strong-modern.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(-1),
                            Valid = false,
                            Expired = true,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsSelfSigned = false,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = false,
                            Sha1Signature = false
                        },
                        new() {
                            Host = "casigned-weak-modern.example.com",
                            ResolvedHost = "casigned-weak-modern.example.com",
                            Port = 8443,
                            Service = "HTTPS-Alt",
                            NotAfterUtc = now.AddDays(45),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsSelfSigned = false,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true,
                            Sha1Signature = false
                        }
                    }
                }
            };

            var selfSigned = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                selfSignedOnly: true);
            Assert.Single(selfSigned.Endpoints);
            Assert.Equal("selfsigned-weak-sha1.example.com", selfSigned.Endpoints[0].Host);

            var caSigned = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                selfSignedOnly: false);
            Assert.Equal(2, caSigned.Endpoints.Count);
            Assert.Contains(caSigned.Endpoints, endpoint => endpoint.Host.Equals("casigned-strong-modern.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(caSigned.Endpoints, endpoint => endpoint.Host.Equals("casigned-weak-modern.example.com", StringComparison.OrdinalIgnoreCase));

            var weakKey = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                weakKeyOnly: true);
            Assert.Equal(2, weakKey.Endpoints.Count);
            Assert.Contains(weakKey.Endpoints, endpoint => endpoint.Host.Equals("selfsigned-weak-sha1.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(weakKey.Endpoints, endpoint => endpoint.Host.Equals("casigned-weak-modern.example.com", StringComparison.OrdinalIgnoreCase));

            var strongKey = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                weakKeyOnly: false);
            Assert.Single(strongKey.Endpoints);
            Assert.Equal("casigned-strong-modern.example.com", strongKey.Endpoints[0].Host);

            var sha1 = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                sha1SignatureOnly: true);
            Assert.Single(sha1.Endpoints);
            Assert.Equal("selfsigned-weak-sha1.example.com", sha1.Endpoints[0].Host);

            var nonSha1 = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                sha1SignatureOnly: false);
            Assert.Equal(2, nonSha1.Endpoints.Count);
            Assert.Contains(nonSha1.Endpoints, endpoint => endpoint.Host.Equals("casigned-strong-modern.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(nonSha1.Endpoints, endpoint => endpoint.Host.Equals("casigned-weak-modern.example.com", StringComparison.OrdinalIgnoreCase));

            var selfSignedWeakAndSha1 = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                selfSignedOnly: true,
                weakKeyOnly: true,
                sha1SignatureOnly: true);
            Assert.Single(selfSignedWeakAndSha1.Endpoints);
            Assert.Equal("selfsigned-weak-sha1.example.com", selfSignedWeakAndSha1.Endpoints[0].Host);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByValidityState() {
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
                            NotBeforeUtc = now.AddDays(-120),
                            NotAfterUtc = now.AddDays(-1),
                            Valid = false,
                            Expired = true,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true
                        },
                        new() {
                            Host = "notyetvalid.example.com",
                            ResolvedHost = "notyetvalid.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(5),
                            NotAfterUtc = now.AddDays(120),
                            Valid = false,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true
                        },
                        new() {
                            Host = "currentlyvalid.example.com",
                            ResolvedHost = "currentlyvalid.example.com",
                            Port = 8443,
                            Service = "HTTPS-Alt",
                            NotBeforeUtc = now.AddDays(-10),
                            NotAfterUtc = now.AddDays(120),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true
                        }
                    }
                }
            };

            var expiredOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiredOnly: true);
            Assert.Single(expiredOnly.Endpoints);
            Assert.Equal("expired.example.com", expiredOnly.Endpoints[0].Host);

            var notExpiredOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiredOnly: false);
            Assert.Equal(2, notExpiredOnly.Endpoints.Count);
            Assert.Contains(notExpiredOnly.Endpoints, endpoint => endpoint.Host.Equals("notyetvalid.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(notExpiredOnly.Endpoints, endpoint => endpoint.Host.Equals("currentlyvalid.example.com", StringComparison.OrdinalIgnoreCase));

            var notYetValidOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                notYetValidOnly: true);
            Assert.Single(notYetValidOnly.Endpoints);
            Assert.Equal("notyetvalid.example.com", notYetValidOnly.Endpoints[0].Host);

            var alreadyValidOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                notYetValidOnly: false);
            Assert.Equal(2, alreadyValidOnly.Endpoints.Count);
            Assert.Contains(alreadyValidOnly.Endpoints, endpoint => endpoint.Host.Equals("expired.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(alreadyValidOnly.Endpoints, endpoint => endpoint.Host.Equals("currentlyvalid.example.com", StringComparison.OrdinalIgnoreCase));

            var currentlyValidOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                currentlyValidOnly: true);
            Assert.Single(currentlyValidOnly.Endpoints);
            Assert.Equal("currentlyvalid.example.com", currentlyValidOnly.Endpoints[0].Host);

            var currentlyInvalidOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                currentlyValidOnly: false);
            Assert.Equal(2, currentlyInvalidOnly.Endpoints.Count);
            Assert.Contains(currentlyInvalidOnly.Endpoints, endpoint => endpoint.Host.Equals("expired.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(currentlyInvalidOnly.Endpoints, endpoint => endpoint.Host.Equals("notyetvalid.example.com", StringComparison.OrdinalIgnoreCase));

            var currentlyInvalidAndNotExpired = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                currentlyValidOnly: false,
                expiredOnly: false);
            Assert.Single(currentlyInvalidAndNotExpired.Endpoints);
            Assert.Equal("notyetvalid.example.com", currentlyInvalidAndNotExpired.Endpoints[0].Host);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByValidityDayWindows() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "expired-window.example.com",
                            ResolvedHost = "expired-window.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(-60),
                            NotAfterUtc = now.AddDays(-2),
                            Valid = false,
                            Expired = true,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true
                        },
                        new() {
                            Host = "expiring-window.example.com",
                            ResolvedHost = "expiring-window.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(-30),
                            NotAfterUtc = now.AddDays(8),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true
                        },
                        new() {
                            Host = "long-valid-window.example.com",
                            ResolvedHost = "long-valid-window.example.com",
                            Port = 8443,
                            Service = "HTTPS-Alt",
                            NotBeforeUtc = now.AddDays(-30),
                            NotAfterUtc = now.AddDays(45),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true
                        },
                        new() {
                            Host = "future-window.example.com",
                            ResolvedHost = "future-window.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(5),
                            NotAfterUtc = now.AddDays(120),
                            Valid = false,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true
                        }
                    }
                }
            };

            var expiringSoon = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                daysToExpireMin: 0,
                daysToExpireMax: 14);
            Assert.Single(expiringSoon.Endpoints);
            Assert.Equal("expiring-window.example.com", expiringSoon.Endpoints[0].Host);

            var alreadyExpired = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                daysToExpireMax: -1);
            Assert.Single(alreadyExpired.Endpoints);
            Assert.Equal("expired-window.example.com", alreadyExpired.Endpoints[0].Host);

            var longCurrentlyValid = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                daysToExpireMin: 30,
                currentlyValidOnly: true);
            Assert.Single(longCurrentlyValid.Endpoints);
            Assert.Equal("long-valid-window.example.com", longCurrentlyValid.Endpoints[0].Host);

            var futureByDaysUntilValid = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                daysUntilValidMin: 0,
                daysUntilValidMax: 10);
            Assert.Single(futureByDaysUntilValid.Endpoints);
            Assert.Equal("future-window.example.com", futureByDaysUntilValid.Endpoints[0].Host);

            var noFutureInShortWindow = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                daysUntilValidMin: 0,
                daysUntilValidMax: 2);
            Assert.Empty(noFutureInShortWindow.Endpoints);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByAuthUsageFlags() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "server-auth-only.example.com",
                            ResolvedHost = "server-auth-only.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(120),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            AllowsClientAuthentication = false,
                            AllowsSecureEmail = false,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            WeakKey = true
                        },
                        new() {
                            Host = "client-auth-only.example.com",
                            ResolvedHost = "client-auth-only.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(120),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = false,
                            AllowsClientAuthentication = true,
                            AllowsSecureEmail = false,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ClientAuthOnly,
                            WeakKey = true
                        },
                        new() {
                            Host = "secure-email-only.example.com",
                            ResolvedHost = "secure-email-only.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(120),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = false,
                            AllowsClientAuthentication = false,
                            AllowsSecureEmail = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.SecureEmailOnly,
                            WeakKey = true
                        },
                        new() {
                            Host = "full-auth.example.com",
                            ResolvedHost = "full-auth.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(120),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            AllowsClientAuthentication = true,
                            AllowsSecureEmail = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.MixedOrCustom,
                            WeakKey = true
                        }
                    }
                }
            };

            var serverOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                serverAuthOnly: true);
            Assert.Equal(2, serverOnly.Endpoints.Count);
            Assert.Contains(serverOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "server-auth-only.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(serverOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "full-auth.example.com", StringComparison.OrdinalIgnoreCase));

            var clientOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                clientAuthOnly: true);
            Assert.Equal(2, clientOnly.Endpoints.Count);
            Assert.Contains(clientOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "client-auth-only.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(clientOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "full-auth.example.com", StringComparison.OrdinalIgnoreCase));

            var secureEmailOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                secureEmailOnly: true);
            Assert.Equal(2, secureEmailOnly.Endpoints.Count);
            Assert.Contains(secureEmailOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "secure-email-only.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(secureEmailOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "full-auth.example.com", StringComparison.OrdinalIgnoreCase));

            var serverAndClient = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                serverAuthOnly: true,
                clientAuthOnly: true);
            Assert.Single(serverAndClient.Endpoints);
            Assert.Equal("full-auth.example.com", serverAndClient.Endpoints[0].Host);

            var filteredByAuthenticationProfile = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authenticationProfileEquals: "serverauthonly");
            Assert.Single(filteredByAuthenticationProfile.Endpoints);
            Assert.Equal("server-auth-only.example.com", filteredByAuthenticationProfile.Endpoints[0].Host);
            Assert.Equal(CertificateAuthenticationProfileClassifier.ServerAuthOnly, filteredByAuthenticationProfile.Endpoints[0].AuthenticationProfile);

            var filteredByMissingAuthenticationProfile = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authenticationProfileEquals: "not-present");
            Assert.Empty(filteredByMissingAuthenticationProfile.Endpoints);

            var filteredByWhitespaceAuthenticationProfile = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authenticationProfileEquals: "   ");
            Assert.Equal(4, filteredByWhitespaceAuthenticationProfile.Endpoints.Count);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByAuthorityFamilyFilters() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "letsencrypt-risk.example.com",
                            ResolvedHost = "letsencrypt-risk.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            CertificateAuthorityFamily = "LetsEncrypt",
                            CertificateRootAuthorityFamily = "LetsEncrypt",
                            WeakKey = true
                        },
                        new() {
                            Host = "digicert-risk.example.com",
                            ResolvedHost = "digicert-risk.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            CertificateAuthorityFamily = "DigiCert",
                            CertificateRootAuthorityFamily = "DigiCert",
                            WeakKey = true
                        },
                        new() {
                            Host = "gts-risk.example.com",
                            ResolvedHost = "gts-risk.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            CertificateAuthorityFamily = "GoogleTrustServices",
                            CertificateRootAuthorityFamily = "GoogleTrustServices",
                            WeakKey = true
                        },
                        new() {
                            Host = "letsencrypt-healthy.example.com",
                            ResolvedHost = "letsencrypt-healthy.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(120),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            CertificateAuthorityFamily = "LetsEncrypt",
                            CertificateRootAuthorityFamily = "LetsEncrypt"
                        },
                        new() {
                            Host = "unknown-family-risk.example.com",
                            ResolvedHost = "unknown-family-risk.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true
                        }
                    }
                }
            };

            var filteredByLeafFamily = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: "letsencrypt");
            Assert.Single(filteredByLeafFamily.Endpoints);
            Assert.Equal("letsencrypt-risk.example.com", filteredByLeafFamily.Endpoints[0].Host);
            Assert.DoesNotContain(filteredByLeafFamily.Endpoints, endpoint => string.Equals(endpoint.Host, "unknown-family-risk.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByLeafFamilyIncludingHealthy = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: "letsencrypt");
            Assert.Equal(2, filteredByLeafFamilyIncludingHealthy.Endpoints.Count);
            Assert.Contains(filteredByLeafFamilyIncludingHealthy.Endpoints, endpoint => string.Equals(endpoint.Host, "letsencrypt-risk.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByLeafFamilyIncludingHealthy.Endpoints, endpoint => string.Equals(endpoint.Host, "letsencrypt-healthy.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(filteredByLeafFamilyIncludingHealthy.Endpoints, endpoint => string.Equals(endpoint.Host, "unknown-family-risk.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByRootFamily = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: "digicert");
            Assert.Single(filteredByRootFamily.Endpoints);
            Assert.Equal("digicert-risk.example.com", filteredByRootFamily.Endpoints[0].Host);

            var filteredByBothFamilies = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: "LetsEncrypt",
                rootAuthorityFamilyEquals: "LetsEncrypt");
            Assert.Single(filteredByBothFamilies.Endpoints);
            Assert.Equal("letsencrypt-risk.example.com", filteredByBothFamilies.Endpoints[0].Host);

            var filteredByMissingFamily = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: "not-present");
            Assert.Empty(filteredByMissingFamily.Endpoints);

            var filteredByWhitespaceFamily = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: "   ",
                rootAuthorityFamilyEquals: "   ");
            Assert.Equal(5, filteredByWhitespaceFamily.Endpoints.Count);
        }

    }
}
