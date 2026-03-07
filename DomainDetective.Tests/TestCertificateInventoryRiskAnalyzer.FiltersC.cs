using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Tests {
    public partial class TestCertificateInventoryRiskAnalyzer {
        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByHostServiceAndPort() {
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
                        },
                        new() {
                            Host = "api-alt.example.com",
                            ResolvedHost = "api-alt.example.com",
                            Port = 8443,
                            Service = "HTTPS-Alt",
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
                        },
                        new() {
                            Host = "mail.example.com",
                            ResolvedHost = "mail.example.com",
                            Port = 25,
                            Service = "SMTP TLS",
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

            var filteredByHost = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                hostContains: "api");
            Assert.Equal(2, filteredByHost.Endpoints.Count);
            Assert.Contains(filteredByHost.Endpoints, endpoint => string.Equals(endpoint.Host, "api.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByHost.Endpoints, endpoint => string.Equals(endpoint.Host, "api-alt.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByService = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                serviceEquals: "https-alt");
            Assert.Single(filteredByService.Endpoints);
            Assert.Equal("api-alt.example.com", filteredByService.Endpoints[0].Host);

            var filteredByPort = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                portEquals: 25);
            Assert.Single(filteredByPort.Endpoints);
            Assert.Equal("mail.example.com", filteredByPort.Endpoints[0].Host);

            var filteredByHostServiceAndPort = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                hostContains: "api",
                serviceEquals: "HTTPS-Alt",
                portEquals: 8443);
            Assert.Single(filteredByHostServiceAndPort.Endpoints);
            Assert.Equal("api-alt.example.com", filteredByHostServiceAndPort.Endpoints[0].Host);

            var filteredByMissingService = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                serviceEquals: "not-present");
            Assert.Empty(filteredByMissingService.Endpoints);

            var filteredByWhitespaceHostAndService = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                hostContains: "   ",
                serviceEquals: "   ");
            Assert.Equal(3, filteredByWhitespaceHostAndService.Endpoints.Count);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByChainLengthAndIntermediateCount() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "chain-length-1.example.com",
                            ResolvedHost = "chain-length-1.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateChainLength = 1,
                            CertificateIntermediateCount = 0,
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = false,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true
                        },
                        new() {
                            Host = "chain-length-2.example.com",
                            ResolvedHost = "chain-length-2.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateChainLength = 2,
                            CertificateIntermediateCount = 0,
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
                        },
                        new() {
                            Host = "chain-length-3.example.com",
                            ResolvedHost = "chain-length-3.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateChainLength = 3,
                            CertificateIntermediateCount = 1,
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

            var allRiskRows = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false);
            Assert.Equal(3, allRiskRows.Endpoints.Count);
            var chainLengthThree = allRiskRows.Endpoints.Single(endpoint => string.Equals(endpoint.Host, "chain-length-3.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Equal(3, chainLengthThree.ChainLength);
            Assert.Equal(1, chainLengthThree.IntermediateCount);

            var filteredByChainLengthMin = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                chainLengthMin: 2);
            Assert.Equal(2, filteredByChainLengthMin.Endpoints.Count);
            Assert.Contains(filteredByChainLengthMin.Endpoints, endpoint => string.Equals(endpoint.Host, "chain-length-2.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByChainLengthMin.Endpoints, endpoint => string.Equals(endpoint.Host, "chain-length-3.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByChainLengthMax = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                chainLengthMax: 2);
            Assert.Equal(2, filteredByChainLengthMax.Endpoints.Count);
            Assert.Contains(filteredByChainLengthMax.Endpoints, endpoint => string.Equals(endpoint.Host, "chain-length-1.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByChainLengthMax.Endpoints, endpoint => string.Equals(endpoint.Host, "chain-length-2.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByIntermediateCountMin = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                intermediateCountMin: 1);
            Assert.Single(filteredByIntermediateCountMin.Endpoints);
            Assert.Equal("chain-length-3.example.com", filteredByIntermediateCountMin.Endpoints[0].Host);

            var filteredByChainAndIntermediate = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                chainLengthMin: 2,
                intermediateCountMax: 0);
            Assert.Single(filteredByChainAndIntermediate.Endpoints);
            Assert.Equal("chain-length-2.example.com", filteredByChainAndIntermediate.Endpoints[0].Host);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByCtObservationAndChainCompleteness() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "public-complete.example.com",
                            ResolvedHost = "public-complete.example.com",
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
                        },
                        new() {
                            Host = "private-complete.example.com",
                            ResolvedHost = "private-complete.example.com",
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
                            PresentInCtLogs = false,
                            WeakKey = true
                        },
                        new() {
                            Host = "public-incomplete.example.com",
                            ResolvedHost = "public-incomplete.example.com",
                            Port = 8443,
                            Service = "HTTPS-Alt",
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = false,
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

            var ctObserved = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                ctObservedOnly: true);
            Assert.Equal(2, ctObserved.Endpoints.Count);
            Assert.Contains(ctObserved.Endpoints, endpoint => endpoint.Host.Equals("public-complete.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(ctObserved.Endpoints, endpoint => endpoint.Host.Equals("public-incomplete.example.com", StringComparison.OrdinalIgnoreCase));

            var ctMissing = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                ctObservedOnly: false);
            Assert.Single(ctMissing.Endpoints);
            Assert.Equal("private-complete.example.com", ctMissing.Endpoints[0].Host);

            var chainComplete = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                chainCompleteOnly: true);
            Assert.Equal(2, chainComplete.Endpoints.Count);
            Assert.Contains(chainComplete.Endpoints, endpoint => endpoint.Host.Equals("public-complete.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(chainComplete.Endpoints, endpoint => endpoint.Host.Equals("private-complete.example.com", StringComparison.OrdinalIgnoreCase));

            var chainIncomplete = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                chainCompleteOnly: false);
            Assert.Single(chainIncomplete.Endpoints);
            Assert.Equal("public-incomplete.example.com", chainIncomplete.Endpoints[0].Host);

            var ctObservedAndChainIncomplete = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                ctObservedOnly: true,
                chainCompleteOnly: false);
            Assert.Single(ctObservedAndChainIncomplete.Endpoints);
            Assert.Equal("public-incomplete.example.com", ctObservedAndChainIncomplete.Endpoints[0].Host);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByReachabilityAndHostnameValidation() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "reachable-match.example.com",
                            ResolvedHost = "reachable-match.example.com",
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
                        },
                        new() {
                            Host = "unreachable-match.example.com",
                            ResolvedHost = "unreachable-match.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = false,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true
                        },
                        new() {
                            Host = "reachable-mismatch.example.com",
                            ResolvedHost = "reachable-mismatch.example.com",
                            Port = 8443,
                            Service = "HTTPS-Alt",
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = false,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true
                        }
                    }
                }
            };

            var reachable = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                reachableOnly: true);
            Assert.Equal(2, reachable.Endpoints.Count);
            Assert.Contains(reachable.Endpoints, endpoint => endpoint.Host.Equals("reachable-match.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(reachable.Endpoints, endpoint => endpoint.Host.Equals("reachable-mismatch.example.com", StringComparison.OrdinalIgnoreCase));

            var unreachable = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                reachableOnly: false);
            Assert.Single(unreachable.Endpoints);
            Assert.Equal("unreachable-match.example.com", unreachable.Endpoints[0].Host);

            var hostnameMatch = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                hostnameMatchOnly: true);
            Assert.Equal(2, hostnameMatch.Endpoints.Count);
            Assert.Contains(hostnameMatch.Endpoints, endpoint => endpoint.Host.Equals("reachable-match.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(hostnameMatch.Endpoints, endpoint => endpoint.Host.Equals("unreachable-match.example.com", StringComparison.OrdinalIgnoreCase));

            var hostnameMismatch = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                hostnameMatchOnly: false);
            Assert.Single(hostnameMismatch.Endpoints);
            Assert.Equal("reachable-mismatch.example.com", hostnameMismatch.Endpoints[0].Host);

            var reachableAndHostnameMismatch = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                reachableOnly: true,
                hostnameMatchOnly: false);
            Assert.Single(reachableAndHostnameMismatch.Endpoints);
            Assert.Equal("reachable-mismatch.example.com", reachableAndHostnameMismatch.Endpoints[0].Host);
        }

    }
}
