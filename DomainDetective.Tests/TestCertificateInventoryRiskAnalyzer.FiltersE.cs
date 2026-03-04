using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Tests {
    public partial class TestCertificateInventoryRiskAnalyzer {
        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByKnownAuthorityState() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "known-leaf-known-root.example.com",
                            ResolvedHost = "known-leaf-known-root.example.com",
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
                            IsKnownRootCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true
                        },
                        new() {
                            Host = "unknown-leaf-known-root.example.com",
                            ResolvedHost = "unknown-leaf-known-root.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = false,
                            IsKnownRootCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true
                        },
                        new() {
                            Host = "known-leaf-unknown-root.example.com",
                            ResolvedHost = "known-leaf-unknown-root.example.com",
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
                            IsKnownRootCertificateAuthority = false,
                            PresentInCtLogs = true,
                            WeakKey = true
                        },
                        new() {
                            Host = "unknown-leaf-unknown-root.example.com",
                            ResolvedHost = "unknown-leaf-unknown-root.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = false,
                            IsKnownRootCertificateAuthority = false,
                            PresentInCtLogs = true,
                            WeakKey = true
                        }
                    }
                }
            };

            var knownLeafOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                knownAuthorityOnly: true);
            Assert.Equal(2, knownLeafOnly.Endpoints.Count);
            Assert.Contains(knownLeafOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "known-leaf-known-root.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(knownLeafOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "known-leaf-unknown-root.example.com", StringComparison.OrdinalIgnoreCase));

            var unknownLeafOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                knownAuthorityOnly: false);
            Assert.Equal(2, unknownLeafOnly.Endpoints.Count);
            Assert.Contains(unknownLeafOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "unknown-leaf-known-root.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(unknownLeafOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "unknown-leaf-unknown-root.example.com", StringComparison.OrdinalIgnoreCase));

            var knownRootOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                knownRootAuthorityOnly: true);
            Assert.Equal(2, knownRootOnly.Endpoints.Count);
            Assert.Contains(knownRootOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "known-leaf-known-root.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(knownRootOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "unknown-leaf-known-root.example.com", StringComparison.OrdinalIgnoreCase));

            var unknownRootOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                knownRootAuthorityOnly: false);
            Assert.Equal(2, unknownRootOnly.Endpoints.Count);
            Assert.Contains(unknownRootOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "known-leaf-unknown-root.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(unknownRootOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "unknown-leaf-unknown-root.example.com", StringComparison.OrdinalIgnoreCase));

            var unknownLeafAndUnknownRoot = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                knownAuthorityOnly: false,
                knownRootAuthorityOnly: false);
            Assert.Single(unknownLeafAndUnknownRoot.Endpoints);
            Assert.Equal("unknown-leaf-unknown-root.example.com", unknownLeafAndUnknownRoot.Endpoints[0].Host);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsBySourceFilters() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "crtsh-source.example.com",
                            ResolvedHost = "crtsh-source.example.com",
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
                            WeakKey = true,
                            CtDiscoverySources = new[] { "crt.sh", "shodan" },
                            CtTemplateFormatErrors = new[] { "ShodanApiUrlTemplate" },
                            CertificateChainSource = "tls-handshake",
                            CertificateChainSources = new List<string> { "tls-handshake", "cert-spotter" }
                        },
                        new() {
                            Host = "censys-source.example.com",
                            ResolvedHost = "censys-source.example.com",
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
                            WeakKey = true,
                            CtDiscoverySources = new[] { "censys" },
                            CtTemplateFormatErrors = new[] { "CensysApiUrlTemplate" },
                            CertificateChainSource = "aia-download",
                            CertificateChainSources = new List<string> { "aia-download" }
                        },
                        new() {
                            Host = "historical-chain-source.example.com",
                            ResolvedHost = "historical-chain-source.example.com",
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
                            WeakKey = true,
                            CtDiscoverySources = new[] { "internal-scan" },
                            CertificateChainSource = string.Empty,
                            CertificateChainSources = new List<string> { "cached-chain-bundle" }
                        }
                    }
                }
            };

            var filteredByCtSource = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: "crt.sh");
            Assert.Single(filteredByCtSource.Endpoints);
            Assert.Equal("crtsh-source.example.com", filteredByCtSource.Endpoints[0].Host);
            Assert.Contains("crt.sh", filteredByCtSource.Endpoints[0].CtDiscoverySources, StringComparer.OrdinalIgnoreCase);

            var filteredByTemplateError = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: "censysapi");
            Assert.Single(filteredByTemplateError.Endpoints);
            Assert.Equal("censys-source.example.com", filteredByTemplateError.Endpoints[0].Host);

            var filteredByPrimaryChainSource = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: null,
                chainSourceContains: "aia-download");
            Assert.Single(filteredByPrimaryChainSource.Endpoints);
            Assert.Equal("censys-source.example.com", filteredByPrimaryChainSource.Endpoints[0].Host);

            var filteredByHistoricalChainSource = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: null,
                chainSourceContains: "cached-chain");
            Assert.Single(filteredByHistoricalChainSource.Endpoints);
            Assert.Equal("historical-chain-source.example.com", filteredByHistoricalChainSource.Endpoints[0].Host);
            Assert.Equal(string.Empty, filteredByHistoricalChainSource.Endpoints[0].ChainSource);
            Assert.Contains("cached-chain-bundle", filteredByHistoricalChainSource.Endpoints[0].ChainSources, StringComparer.OrdinalIgnoreCase);

            var filteredByCtAndChain = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: "shodan",
                ctTemplateErrorContains: null,
                chainSourceContains: "tls-handshake");
            Assert.Single(filteredByCtAndChain.Endpoints);
            Assert.Equal("crtsh-source.example.com", filteredByCtAndChain.Endpoints[0].Host);

            var filteredByWhitespaceSourceFilters = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: "   ",
                ctTemplateErrorContains: "   ",
                chainSourceContains: "   ");
            // Whitespace-only source filters are treated as absent, so all three risk-bearing entries are returned.
            Assert.Equal(3, filteredByWhitespaceSourceFilters.Endpoints.Count);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByThumbprintEquals() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "thumbprint-a.example.com",
                            ResolvedHost = "thumbprint-a.example.com",
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
                            CertificateThumbprint = "AA11BB22CC33DD44EE55FF6677889900AABBCCDD",
                            WeakKey = true
                        },
                        new() {
                            Host = "thumbprint-b.example.com",
                            ResolvedHost = "thumbprint-b.example.com",
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
                            CertificateThumbprint = "11223344556677889900AABBCCDDEEFF00112233",
                            WeakKey = true
                        },
                        new() {
                            Host = "thumbprint-missing.example.com",
                            ResolvedHost = "thumbprint-missing.example.com",
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

            var filteredByThumbprint = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: null,
                chainSourceContains: null,
                thumbprintEquals: "aa11bb22cc33dd44ee55ff6677889900aabbccdd");
            Assert.Single(filteredByThumbprint.Endpoints);
            Assert.Equal("thumbprint-a.example.com", filteredByThumbprint.Endpoints[0].Host);
            Assert.Equal("AA11BB22CC33DD44EE55FF6677889900AABBCCDD", filteredByThumbprint.Endpoints[0].CertificateThumbprint);
            Assert.DoesNotContain(filteredByThumbprint.Endpoints, endpoint => string.Equals(endpoint.Host, "thumbprint-missing.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByMissingThumbprint = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: null,
                chainSourceContains: null,
                thumbprintEquals: "not-present");
            Assert.Empty(filteredByMissingThumbprint.Endpoints);

            var filteredByWhitespaceThumbprint = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: null,
                chainSourceContains: null,
                thumbprintEquals: "   ");
            Assert.Equal(3, filteredByWhitespaceThumbprint.Endpoints.Count);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByRootThumbprintEquals() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "root-thumbprint-a.example.com",
                            ResolvedHost = "root-thumbprint-a.example.com",
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
                            CertificateRootThumbprint = "5A3F4D2C1B0099887766554433221100AABBCCDD",
                            WeakKey = true
                        },
                        new() {
                            Host = "root-thumbprint-b.example.com",
                            ResolvedHost = "root-thumbprint-b.example.com",
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
                            CertificateRootThumbprint = "00112233445566778899AABBCCDDEEFF00112233",
                            WeakKey = true
                        },
                        new() {
                            Host = "root-thumbprint-missing.example.com",
                            ResolvedHost = "root-thumbprint-missing.example.com",
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

            var filteredByRootThumbprint = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: null,
                chainSourceContains: null,
                thumbprintEquals: null,
                rootThumbprintEquals: "5a3f:4d2c1b00 99887766554433221100aabbccdd");
            Assert.Single(filteredByRootThumbprint.Endpoints);
            Assert.Equal("root-thumbprint-a.example.com", filteredByRootThumbprint.Endpoints[0].Host);
            Assert.Equal("5A3F4D2C1B0099887766554433221100AABBCCDD", filteredByRootThumbprint.Endpoints[0].CertificateRootThumbprint);
            Assert.DoesNotContain(filteredByRootThumbprint.Endpoints, endpoint => string.Equals(endpoint.Host, "root-thumbprint-missing.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByMissingRootThumbprint = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: null,
                chainSourceContains: null,
                thumbprintEquals: null,
                rootThumbprintEquals: "not-present");
            Assert.Empty(filteredByMissingRootThumbprint.Endpoints);

            var filteredByWhitespaceRootThumbprint = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: null,
                chainSourceContains: null,
                thumbprintEquals: null,
                rootThumbprintEquals: "   ");
            Assert.Equal(3, filteredByWhitespaceRootThumbprint.Endpoints.Count);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsBySerialNumberEquals() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "serial-a.example.com",
                            ResolvedHost = "serial-a.example.com",
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
                            CertificateSerialNumber = "00AA11BB22CC33DD44EE55FF66778899",
                            WeakKey = true
                        },
                        new() {
                            Host = "serial-b.example.com",
                            ResolvedHost = "serial-b.example.com",
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
                            CertificateSerialNumber = "11223344556677889900AABBCCDDEEFF",
                            WeakKey = true
                        },
                        new() {
                            Host = "serial-missing.example.com",
                            ResolvedHost = "serial-missing.example.com",
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

            var filteredBySerialNumber = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: null,
                chainSourceContains: null,
                thumbprintEquals: null,
                serialNumberEquals: "00aa:11bb 22cc33dd44ee55ff66778899");
            Assert.Single(filteredBySerialNumber.Endpoints);
            Assert.Equal("serial-a.example.com", filteredBySerialNumber.Endpoints[0].Host);
            Assert.Equal("00AA11BB22CC33DD44EE55FF66778899", filteredBySerialNumber.Endpoints[0].CertificateSerialNumber);
            Assert.DoesNotContain(filteredBySerialNumber.Endpoints, endpoint => string.Equals(endpoint.Host, "serial-missing.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByMissingSerialNumber = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: null,
                chainSourceContains: null,
                thumbprintEquals: null,
                serialNumberEquals: "not-present");
            Assert.Empty(filteredByMissingSerialNumber.Endpoints);

            var filteredByWhitespaceSerialNumber = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: null,
                chainSourceContains: null,
                thumbprintEquals: null,
                serialNumberEquals: "   ");
            Assert.Equal(3, filteredByWhitespaceSerialNumber.Endpoints.Count);
        }
    }
}
