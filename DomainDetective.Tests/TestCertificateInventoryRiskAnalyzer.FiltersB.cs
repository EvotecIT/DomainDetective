using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Tests {
    public partial class TestCertificateInventoryRiskAnalyzer {
        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByReasonContains() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "expired-reason.example.com",
                            ResolvedHost = "expired-reason.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(-2),
                            Valid = false,
                            Expired = true,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true
                        },
                        new() {
                            Host = "weak-reason.example.com",
                            ResolvedHost = "weak-reason.example.com",
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
                            WeakKey = true
                        },
                        new() {
                            Host = "healthy-reason.example.com",
                            ResolvedHost = "healthy-reason.example.com",
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
                            PresentInCtLogs = true
                        }
                    }
                }
            };

            var filteredByWeakKey = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: "wEaK");
            Assert.Single(filteredByWeakKey.Endpoints);
            Assert.Equal("weak-reason.example.com", filteredByWeakKey.Endpoints[0].Host);
            Assert.Contains("WeakKey", filteredByWeakKey.Endpoints[0].Reasons);

            var filteredByExpiredWithoutNoRisk = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: "expired");
            Assert.Single(filteredByExpiredWithoutNoRisk.Endpoints);
            Assert.Equal("expired-reason.example.com", filteredByExpiredWithoutNoRisk.Endpoints[0].Host);
            Assert.Contains("CertificateExpired", filteredByExpiredWithoutNoRisk.Endpoints[0].Reasons);

            var filteredByNoneWithoutNoRisk = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: "none");
            Assert.Empty(filteredByNoneWithoutNoRisk.Endpoints);

            var filteredByMissingReason = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: "does-not-exist");
            Assert.Empty(filteredByMissingReason.Endpoints);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByReasonAnyOfAndReasonAllOf() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "expired-only-reason-list.example.com",
                            ResolvedHost = "expired-only-reason-list.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(-2),
                            Valid = false,
                            Expired = true,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true
                        },
                        new() {
                            Host = "weak-only-reason-list.example.com",
                            ResolvedHost = "weak-only-reason-list.example.com",
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
                            WeakKey = true
                        },
                        new() {
                            Host = "expired-weak-reason-list.example.com",
                            ResolvedHost = "expired-weak-reason-list.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(-3),
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
                            Host = "healthy-reason-list.example.com",
                            ResolvedHost = "healthy-reason-list.example.com",
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
                            PresentInCtLogs = true
                        }
                    }
                }
            };

            var filteredByAnyReason = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                reasonAnyOf: new[] { "WeakKey", "Sha1Signature" });
            Assert.Equal(2, filteredByAnyReason.Endpoints.Count);
            Assert.Contains(filteredByAnyReason.Endpoints, endpoint => string.Equals(endpoint.Host, "weak-only-reason-list.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByAnyReason.Endpoints, endpoint => string.Equals(endpoint.Host, "expired-weak-reason-list.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByAllReasons = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                reasonAllOf: new[] { "CertificateExpired", "WeakKey" });
            Assert.Single(filteredByAllReasons.Endpoints);
            Assert.Equal("expired-weak-reason-list.example.com", filteredByAllReasons.Endpoints[0].Host);
            Assert.Contains("CertificateExpired", filteredByAllReasons.Endpoints[0].Reasons);
            Assert.Contains("WeakKey", filteredByAllReasons.Endpoints[0].Reasons);

            var filteredByReasonContainsAndAnyReason = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: "validation",
                reasonAnyOf: new[] { "CertificateExpired" });
            Assert.Equal(2, filteredByReasonContainsAndAnyReason.Endpoints.Count);
            Assert.Contains(filteredByReasonContainsAndAnyReason.Endpoints, endpoint => string.Equals(endpoint.Host, "expired-only-reason-list.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByReasonContainsAndAnyReason.Endpoints, endpoint => string.Equals(endpoint.Host, "expired-weak-reason-list.example.com", StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public void BuildRiskTreatsWhitespaceReasonAnyOfAndReasonAllOfAsAbsent() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "expired-whitespace-reason-list.example.com",
                            ResolvedHost = "expired-whitespace-reason-list.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(-2),
                            Valid = false,
                            Expired = true,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true
                        },
                        new() {
                            Host = "weak-whitespace-reason-list.example.com",
                            ResolvedHost = "weak-whitespace-reason-list.example.com",
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
                            WeakKey = true
                        }
                    }
                }
            };

            var filteredByReasonAnyWithWhitespace = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                reasonAnyOf: new[] { "  ", "WeakKey", "weakkey" },
                reasonAllOf: new[] { "   " });
            Assert.Single(filteredByReasonAnyWithWhitespace.Endpoints);
            Assert.Equal("weak-whitespace-reason-list.example.com", filteredByReasonAnyWithWhitespace.Endpoints[0].Host);

            var filteredByOnlyWhitespaceReasonLists = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                reasonAnyOf: new[] { "   " },
                reasonAllOf: new[] { "   " });
            // Whitespace-only reason lists are treated as absent, so all risk-bearing entries are returned.
            Assert.Equal(2, filteredByOnlyWhitespaceReasonLists.Endpoints.Count);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByIssuerContains() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "digicert-issuer.example.com",
                            ResolvedHost = "digicert-issuer.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(5),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true,
                            CertificateIssuerNormalized = "DigiCert TLS RSA SHA256 2020 CA1",
                            CertificateRootIssuerNormalized = "DigiCert Global Root G2"
                        },
                        new() {
                            Host = "isrg-root.example.com",
                            ResolvedHost = "isrg-root.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(4),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            CertificateIssuerNormalized = "R3",
                            CertificateRootIssuerNormalized = "ISRG Root X1"
                        },
                        new() {
                            Host = "other-issuer.example.com",
                            ResolvedHost = "other-issuer.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(3),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            CertificateIssuerNormalized = "Contoso Trust Services",
                            CertificateRootIssuerNormalized = "Contoso Root CA"
                        },
                        new() {
                            Host = "healthy-contoso-issuer.example.com",
                            ResolvedHost = "healthy-contoso-issuer.example.com",
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
                            CertificateIssuerNormalized = "Contoso Trust Services",
                            CertificateRootIssuerNormalized = "Contoso Root CA"
                        }
                    }
                }
            };

            var filteredByLeafIssuer = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: "digicert");
            Assert.Single(filteredByLeafIssuer.Endpoints);
            Assert.Equal("digicert-issuer.example.com", filteredByLeafIssuer.Endpoints[0].Host);
            Assert.Contains("DigiCert", filteredByLeafIssuer.Endpoints[0].Issuer, StringComparison.OrdinalIgnoreCase);

            var filteredByRootIssuer = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: "isrg");
            Assert.Single(filteredByRootIssuer.Endpoints);
            Assert.Equal("isrg-root.example.com", filteredByRootIssuer.Endpoints[0].Host);
            Assert.Contains("ISRG", filteredByRootIssuer.Endpoints[0].RootIssuer, StringComparison.OrdinalIgnoreCase);

            var filteredByIssuerWithoutNoRisk = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: "contoso");
            Assert.Single(filteredByIssuerWithoutNoRisk.Endpoints);
            Assert.Equal("other-issuer.example.com", filteredByIssuerWithoutNoRisk.Endpoints[0].Host);
            Assert.DoesNotContain(filteredByIssuerWithoutNoRisk.Endpoints, endpoint => string.Equals(endpoint.Host, "healthy-contoso-issuer.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByIssuerAndReason = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: "WeakKey",
                issuerContains: "digicert");
            Assert.Single(filteredByIssuerAndReason.Endpoints);
            Assert.Equal("digicert-issuer.example.com", filteredByIssuerAndReason.Endpoints[0].Host);

            var filteredByWhitespaceIssuer = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: "   ");
            Assert.Equal(4, filteredByWhitespaceIssuer.Endpoints.Count);

            var filteredByMissingIssuer = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: "not-present");
            Assert.Empty(filteredByMissingIssuer.Endpoints);

            var filteredByIssuerAnyOf = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                issuerContainsAnyOf: new[] { "digicert", "isrg" });
            Assert.Equal(2, filteredByIssuerAnyOf.Endpoints.Count);
            Assert.Contains(filteredByIssuerAnyOf.Endpoints, endpoint => string.Equals(endpoint.Host, "digicert-issuer.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByIssuerAnyOf.Endpoints, endpoint => string.Equals(endpoint.Host, "isrg-root.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByIssuerAllOf = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                issuerContainsAllOf: new[] { "contoso", "root" });
            Assert.Equal(2, filteredByIssuerAllOf.Endpoints.Count);
            Assert.Contains(filteredByIssuerAllOf.Endpoints, endpoint => string.Equals(endpoint.Host, "other-issuer.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByIssuerAllOf.Endpoints, endpoint => string.Equals(endpoint.Host, "healthy-contoso-issuer.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByIssuerAnyAndAll = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                issuerContainsAnyOf: new[] { "contoso", "digicert" },
                issuerContainsAllOf: new[] { "root" });
            Assert.Equal(3, filteredByIssuerAnyAndAll.Endpoints.Count);
            Assert.Contains(filteredByIssuerAnyAndAll.Endpoints, endpoint => string.Equals(endpoint.Host, "digicert-issuer.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByIssuerAnyAndAll.Endpoints, endpoint => string.Equals(endpoint.Host, "other-issuer.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByIssuerAnyAndAll.Endpoints, endpoint => string.Equals(endpoint.Host, "healthy-contoso-issuer.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByWhitespaceIssuerLists = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                issuerContainsAnyOf: new[] { "  ", "DIGICERT", "digicert" },
                issuerContainsAllOf: new[] { "   " });
            Assert.Single(filteredByWhitespaceIssuerLists.Endpoints);
            Assert.Equal("digicert-issuer.example.com", filteredByWhitespaceIssuerLists.Endpoints[0].Host);

            var filteredByRootIssuerContains = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                rootIssuerContains: "isrg root");
            Assert.Single(filteredByRootIssuerContains.Endpoints);
            Assert.Equal("isrg-root.example.com", filteredByRootIssuerContains.Endpoints[0].Host);

            var filteredByRootIssuerAnyOf = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                rootIssuerContainsAnyOf: new[] { "global root", "root x1" });
            Assert.Equal(2, filteredByRootIssuerAnyOf.Endpoints.Count);
            Assert.Contains(filteredByRootIssuerAnyOf.Endpoints, endpoint => string.Equals(endpoint.Host, "digicert-issuer.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByRootIssuerAnyOf.Endpoints, endpoint => string.Equals(endpoint.Host, "isrg-root.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByRootIssuerAllOf = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                rootIssuerContainsAllOf: new[] { "contoso", "root" });
            Assert.Equal(2, filteredByRootIssuerAllOf.Endpoints.Count);
            Assert.Contains(filteredByRootIssuerAllOf.Endpoints, endpoint => string.Equals(endpoint.Host, "other-issuer.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByRootIssuerAllOf.Endpoints, endpoint => string.Equals(endpoint.Host, "healthy-contoso-issuer.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByWhitespaceRootIssuerLists = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                rootIssuerContainsAnyOf: new[] { "   ", "isrg root", "ISRG ROOT" },
                rootIssuerContainsAllOf: new[] { "   " });
            Assert.Single(filteredByWhitespaceRootIssuerLists.Endpoints);
            Assert.Equal("isrg-root.example.com", filteredByWhitespaceRootIssuerLists.Endpoints[0].Host);
        }

    }
}
