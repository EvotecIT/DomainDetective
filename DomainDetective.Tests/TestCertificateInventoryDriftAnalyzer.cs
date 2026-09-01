using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Tests {
    public partial class TestCertificateInventoryDriftAnalyzer {
        [Fact]
        public void BuildDriftDetectsCertificateIssuerAndExpiryChanges() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-6),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "api.example.com",
                            ResolvedHost = "api.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "AAA111",
                            CertificateIssuerNormalized = "Let's Encrypt",
                            NotAfterUtc = now.AddDays(30),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            CertificateChainSource = "tls-handshake"
                        },
                        new() {
                            Host = "portal.example.com",
                            ResolvedHost = "portal.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "ZZZ999",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(90),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            CertificateChainSource = "tls-handshake"
                        }
                    }
                },
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-2),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "api.example.com",
                            ResolvedHost = "api.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "BBB222",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(365),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ClientAuthOnly,
                            CertificateChainSource = "local-build-no-check"
                        },
                        new() {
                            Host = "portal.example.com",
                            ResolvedHost = "portal.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "ZZZ999",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(90),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            CertificateChainSource = "tls-handshake"
                        }
                    }
                }
            };

            var drift = CertificateInventoryDriftAnalyzer.BuildDrift(snapshots, changedOnly: false, maxEndpoints: 100);

            Assert.Equal(2, drift.SnapshotCount);
            Assert.Equal(2, drift.EndpointCount);
            Assert.Equal(1, drift.EndpointsWithAnyChange);
            Assert.Equal(1, drift.EndpointsWithCertificateChange);
            Assert.Equal(1, drift.EndpointsWithIssuerChange);
            Assert.Equal(1, drift.EndpointsWithExpiryChange);
            Assert.Equal(0, drift.EndpointsWithServiceChange);
            Assert.Equal(1, drift.EndpointsWithAuthenticationProfileChange);
            Assert.Equal(1, drift.EndpointsWithChainSourceChange);
            Assert.Equal(1, drift.EndpointsWithHighSeverityDrift);
            Assert.Equal(0, drift.EndpointsWithMediumSeverityDrift);
            Assert.Equal(0, drift.EndpointsWithLowSeverityDrift);
            Assert.Equal(0, drift.EndpointsExcludedByChangedOnly);
            Assert.Equal(0, drift.EndpointsExcludedByMinimumSeverity);
            Assert.Equal(0, drift.EndpointsExcludedByChangeKindFilter);
            Assert.Equal(0, drift.EndpointsExcludedByFilters);
            Assert.Equal(0, drift.EndpointsTruncatedByMaxEndpoints);
            Assert.Equal(drift.EndpointCount, drift.EndpointsMatchingFilters + drift.EndpointsExcludedByFilters);
            Assert.Equal(drift.EndpointsMatchingFilters, drift.Endpoints.Count + drift.EndpointsTruncatedByMaxEndpoints);
            Assert.Equal(2, drift.Endpoints.Count);

            var api = drift.Endpoints.Single(x => x.Host == "api.example.com");
            Assert.True(api.CertificateChanged);
            Assert.True(api.IssuerChanged);
            Assert.True(api.ExpiryChanged);
            Assert.False(api.ServiceChanged);
            Assert.True(api.AuthenticationProfileChanged);
            Assert.True(api.ChainSourceChanged);
            Assert.Equal("High", api.DriftSeverity);
            Assert.Equal(new[] { "certificate", "issuer", "expiry", "auth-profile", "chain-source" }, api.ChangeKinds);
            Assert.Equal("AAA111", api.PreviousCertificateId);
            Assert.Equal("BBB222", api.CurrentCertificateId);
            Assert.Equal(CertificateAuthenticationProfileClassifier.ServerAuthOnly, api.PreviousAuthenticationProfile);
            Assert.Equal(CertificateAuthenticationProfileClassifier.ClientAuthOnly, api.CurrentAuthenticationProfile);
            Assert.Equal("tls-handshake", api.PreviousChainSource);
            Assert.Equal("local-build-no-check", api.CurrentChainSource);
            Assert.NotNull(api.LastChangedAtUtc);
            Assert.Equal(2, api.ObservationCount);
            Assert.Equal(2, api.DistinctCertificateCount);

            var portal = drift.Endpoints.Single(x => x.Host == "portal.example.com");
            Assert.False(portal.CertificateChanged);
            Assert.False(portal.IssuerChanged);
            Assert.False(portal.ExpiryChanged);
            Assert.False(portal.ServiceChanged);
            Assert.False(portal.AuthenticationProfileChanged);
            Assert.False(portal.ChainSourceChanged);
            Assert.Equal("None", portal.DriftSeverity);
            Assert.Empty(portal.ChangeKinds);
            Assert.Null(portal.LastChangedAtUtc);
        }

        [Fact]
        public void BuildDriftKeepsServicesOnSameHostAndPortSeparate() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-1),
                    Entries = new List<CertificateInventoryEntry> {
                        new() { Host = "multi.example.com", Port = 443, Service = "HTTPS", CertificateThumbprint = "HTTPS-1" },
                        new() { Host = "multi.example.com", Port = 443, Service = "LDAPS", CertificateThumbprint = "LDAPS-1" }
                    }
                },
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Entries = new List<CertificateInventoryEntry> {
                        new() { Host = "multi.example.com", Port = 443, Service = "HTTPS", CertificateThumbprint = "HTTPS-1" },
                        new() { Host = "multi.example.com", Port = 443, Service = "LDAPS", CertificateThumbprint = "LDAPS-1" }
                    }
                }
            };

            CertificateInventoryDriftSummary drift = CertificateInventoryDriftAnalyzer.BuildDrift(snapshots, changedOnly: false, maxEndpoints: 100);

            Assert.Equal(2, drift.EndpointCount);
            Assert.Contains(drift.Endpoints, endpoint => endpoint.Service == "HTTPS" && endpoint.ObservationCount == 2);
            Assert.Contains(drift.Endpoints, endpoint => endpoint.Service == "LDAPS" && endpoint.ObservationCount == 2);
        }

        [Fact]
        public void BuildDriftKeepsProbeVantageHistoriesSeparate() {
            var now = DateTimeOffset.UtcNow;
            CertificateInventoryEntry Entry(string vantage, string thumbprint) => new() {
                Host = "shared.example.com",
                ResolvedHost = "shared.example.com",
                Port = 443,
                Service = "HTTPS",
                ProbeVantage = vantage,
                CertificateThumbprint = thumbprint
            };
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-1),
                    Entries = new List<CertificateInventoryEntry> {
                        Entry("branch-office", "BRANCH-CERT"),
                        Entry("cloud", "CLOUD-CERT")
                    }
                },
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Entries = new List<CertificateInventoryEntry> {
                        Entry("branch-office", "BRANCH-CERT"),
                        Entry("cloud", "CLOUD-CERT")
                    }
                }
            };

            CertificateInventoryDriftSummary drift = CertificateInventoryDriftAnalyzer.BuildDrift(
                snapshots,
                changedOnly: false,
                maxEndpoints: 100);

            Assert.Equal(2, drift.EndpointCount);
            Assert.Equal(0, drift.EndpointsWithAnyChange);
            Assert.All(drift.Endpoints, endpoint => {
                Assert.Equal(2, endpoint.ObservationCount);
                Assert.Equal(1, endpoint.DistinctCertificateCount);
                Assert.Equal("None", endpoint.DriftSeverity);
            });
            Assert.Contains(drift.Endpoints, endpoint => endpoint.ProbeVantage == "branch-office");
            Assert.Contains(drift.Endpoints, endpoint => endpoint.ProbeVantage == "cloud");
        }

        [Fact]
        public void BuildDriftChangedOnlyFiltersUnchangedEndpoints() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-4),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "app.example.com",
                            ResolvedHost = "app.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateSubject = "CN=app.example.com",
                            CertificateIssuerNormalized = "Contoso PKI",
                            NotBeforeUtc = now.AddDays(-10),
                            NotAfterUtc = now.AddDays(20)
                        }
                    }
                },
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-1),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "app.example.com",
                            ResolvedHost = "app.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateSubject = "CN=app.example.com",
                            CertificateIssuerNormalized = "Contoso PKI",
                            NotBeforeUtc = now.AddDays(-10),
                            NotAfterUtc = now.AddDays(20)
                        }
                    }
                }
            };

            var changedOnly = CertificateInventoryDriftAnalyzer.BuildDrift(snapshots, changedOnly: true, maxEndpoints: 100);
            Assert.Equal(1, changedOnly.EndpointCount);
            Assert.Empty(changedOnly.Endpoints);
        }

        [Fact]
        public void BuildDriftChangedOnlyIncludesAuthProfileAndChainSourceChanges() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-4),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "authchain.example.com",
                            ResolvedHost = "authchain.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "CONST-THUMBPRINT",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(90),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            CertificateChainSource = "tls-handshake"
                        }
                    }
                },
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-1),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "authchain.example.com",
                            ResolvedHost = "authchain.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "CONST-THUMBPRINT",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(90),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ClientAuthOnly,
                            CertificateChainSource = "local-build-no-check"
                        }
                    }
                }
            };

            var changedOnly = CertificateInventoryDriftAnalyzer.BuildDrift(snapshots, changedOnly: true, maxEndpoints: 100);

            Assert.Equal(1, changedOnly.EndpointCount);
            Assert.Equal(1, changedOnly.EndpointsWithAnyChange);
            Assert.Equal(0, changedOnly.EndpointsWithCertificateChange);
            Assert.Equal(0, changedOnly.EndpointsWithIssuerChange);
            Assert.Equal(0, changedOnly.EndpointsWithExpiryChange);
            Assert.Equal(0, changedOnly.EndpointsWithServiceChange);
            Assert.Equal(1, changedOnly.EndpointsWithAuthenticationProfileChange);
            Assert.Equal(1, changedOnly.EndpointsWithChainSourceChange);
            Assert.Equal(1, changedOnly.EndpointsWithHighSeverityDrift);
            Assert.Equal(0, changedOnly.EndpointsWithMediumSeverityDrift);
            Assert.Equal(0, changedOnly.EndpointsWithLowSeverityDrift);
            var endpoint = Assert.Single(changedOnly.Endpoints);
            Assert.False(endpoint.CertificateChanged);
            Assert.False(endpoint.IssuerChanged);
            Assert.False(endpoint.ExpiryChanged);
            Assert.False(endpoint.ServiceChanged);
            Assert.True(endpoint.AuthenticationProfileChanged);
            Assert.True(endpoint.ChainSourceChanged);
            Assert.Equal("High", endpoint.DriftSeverity);
            Assert.Equal(new[] { "auth-profile", "chain-source" }, endpoint.ChangeKinds);
            Assert.NotNull(endpoint.LastChangedAtUtc);
        }

        [Fact]
        public void BuildDriftClassifiesExpiryOnlyChangeAsLowSeverity() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-6),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "expiry-only.example.com",
                            ResolvedHost = "expiry-only.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "SAME-THUMBPRINT",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(30),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            CertificateChainSource = "tls-handshake"
                        }
                    }
                },
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-1),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "expiry-only.example.com",
                            ResolvedHost = "expiry-only.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "SAME-THUMBPRINT",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(60),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            CertificateChainSource = "tls-handshake"
                        }
                    }
                }
            };

            var drift = CertificateInventoryDriftAnalyzer.BuildDrift(snapshots, changedOnly: false, maxEndpoints: 100);
            Assert.Equal(1, drift.EndpointsWithAnyChange);
            Assert.Equal(0, drift.EndpointsWithHighSeverityDrift);
            Assert.Equal(0, drift.EndpointsWithMediumSeverityDrift);
            Assert.Equal(1, drift.EndpointsWithLowSeverityDrift);
            var endpoint = Assert.Single(drift.Endpoints);
            Assert.Equal("Low", endpoint.DriftSeverity);
            Assert.Equal(new[] { "expiry" }, endpoint.ChangeKinds);
        }

        [Fact]
        public void BuildDriftClassifiesCertificateAndChainSourceAsMediumSeverity() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-6),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "medium.example.com",
                            ResolvedHost = "medium.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "OLD-THUMB",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(45),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            CertificateChainSource = "tls-handshake"
                        }
                    }
                },
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-1),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "medium.example.com",
                            ResolvedHost = "medium.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "NEW-THUMB",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(45),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            CertificateChainSource = "local-build-online"
                        }
                    }
                }
            };

            var drift = CertificateInventoryDriftAnalyzer.BuildDrift(snapshots, changedOnly: false, maxEndpoints: 100);
            Assert.Equal(1, drift.EndpointsWithAnyChange);
            Assert.Equal(0, drift.EndpointsWithHighSeverityDrift);
            Assert.Equal(1, drift.EndpointsWithMediumSeverityDrift);
            Assert.Equal(0, drift.EndpointsWithLowSeverityDrift);
            var endpoint = Assert.Single(drift.Endpoints);
            Assert.Equal("Medium", endpoint.DriftSeverity);
            Assert.Equal(new[] { "certificate", "chain-source" }, endpoint.ChangeKinds);
        }

        [Fact]
        public void BuildDriftMinimumSeverityFiltersRowsByThreshold() {
            var snapshots = CreateThresholdFilterSnapshots(DateTimeOffset.UtcNow);

            var mediumAndHigh = CertificateInventoryDriftAnalyzer.BuildDrift(
                snapshots,
                changedOnly: false,
                maxEndpoints: 100,
                minimumSeverity: "medium");

            Assert.Equal(4, mediumAndHigh.EndpointCount);
            Assert.Equal(2, mediumAndHigh.EndpointsMatchingFilters);
            Assert.Equal(2, mediumAndHigh.Endpoints.Count);
            Assert.Equal(2, mediumAndHigh.EndpointsWithAnyChange);
            Assert.Equal(1, mediumAndHigh.EndpointsWithHighSeverityDrift);
            Assert.Equal(1, mediumAndHigh.EndpointsWithMediumSeverityDrift);
            Assert.Equal(0, mediumAndHigh.EndpointsWithLowSeverityDrift);
            Assert.Contains(mediumAndHigh.Endpoints, endpoint => endpoint.Host == "medium.example.com");
            Assert.Contains(mediumAndHigh.Endpoints, endpoint => endpoint.Host == "high.example.com");
            Assert.DoesNotContain(mediumAndHigh.Endpoints, endpoint => endpoint.Host == "low.example.com");
            Assert.DoesNotContain(mediumAndHigh.Endpoints, endpoint => endpoint.Host == "none.example.com");

            var highOnly = CertificateInventoryDriftAnalyzer.BuildDrift(
                snapshots,
                changedOnly: false,
                maxEndpoints: 100,
                minimumSeverity: "HIGH");

            var endpointHigh = Assert.Single(highOnly.Endpoints);
            Assert.Equal("high.example.com", endpointHigh.Host);
            Assert.Equal(1, highOnly.EndpointsMatchingFilters);
            Assert.Equal(1, highOnly.EndpointsWithAnyChange);
            Assert.Equal(1, highOnly.EndpointsWithHighSeverityDrift);
            Assert.Equal(0, highOnly.EndpointsWithMediumSeverityDrift);
            Assert.Equal(0, highOnly.EndpointsWithLowSeverityDrift);
        }

        [Fact]
        public void BuildDriftChangedOnlyAndMinimumSeverityCanExcludeLowChanges() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-3),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "low-change.example.com",
                            ResolvedHost = "low-change.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "LOW-SAME",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(30),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            CertificateChainSource = "tls-handshake"
                        }
                    }
                },
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-1),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "low-change.example.com",
                            ResolvedHost = "low-change.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "LOW-SAME",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(60),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            CertificateChainSource = "tls-handshake"
                        }
                    }
                }
            };

            var summary = CertificateInventoryDriftAnalyzer.BuildDrift(
                snapshots,
                changedOnly: true,
                maxEndpoints: 100,
                minimumSeverity: "medium");

            Assert.Equal(1, summary.EndpointCount);
            Assert.Equal(0, summary.EndpointsMatchingFilters);
            Assert.Empty(summary.Endpoints);
            Assert.Equal(0, summary.EndpointsWithAnyChange);
            Assert.Equal(0, summary.EndpointsWithHighSeverityDrift);
            Assert.Equal(0, summary.EndpointsWithMediumSeverityDrift);
            Assert.Equal(0, summary.EndpointsWithLowSeverityDrift);
        }

        [Fact]
        public void BuildDriftMinimumSeverityNoneMatchesDefaultBehavior() {
            var snapshots = CreateThresholdFilterSnapshots(DateTimeOffset.UtcNow);

            var implicitNone = CertificateInventoryDriftAnalyzer.BuildDrift(
                snapshots,
                changedOnly: false,
                maxEndpoints: 100);
            var explicitNone = CertificateInventoryDriftAnalyzer.BuildDrift(
                snapshots,
                changedOnly: false,
                maxEndpoints: 100,
                minimumSeverity: "none");

            Assert.Equal(implicitNone.EndpointCount, explicitNone.EndpointCount);
            Assert.Equal(implicitNone.EndpointsMatchingFilters, explicitNone.EndpointsMatchingFilters);
            Assert.Equal(implicitNone.EndpointsWithAnyChange, explicitNone.EndpointsWithAnyChange);
            Assert.Equal(implicitNone.EndpointsWithHighSeverityDrift, explicitNone.EndpointsWithHighSeverityDrift);
            Assert.Equal(implicitNone.EndpointsWithMediumSeverityDrift, explicitNone.EndpointsWithMediumSeverityDrift);
            Assert.Equal(implicitNone.EndpointsWithLowSeverityDrift, explicitNone.EndpointsWithLowSeverityDrift);
            Assert.Equal(
                implicitNone.Endpoints.Select(endpoint => endpoint.Host).OrderBy(host => host),
                explicitNone.Endpoints.Select(endpoint => endpoint.Host).OrderBy(host => host));
        }

        [Fact]
        public void BuildDriftMinimumSeverityLowExcludesOnlyNoneSeverityRows() {
            var snapshots = CreateThresholdFilterSnapshots(DateTimeOffset.UtcNow);

            var lowOrHigher = CertificateInventoryDriftAnalyzer.BuildDrift(
                snapshots,
                changedOnly: false,
                maxEndpoints: 100,
                minimumSeverity: "low");

            Assert.Equal(4, lowOrHigher.EndpointCount);
            Assert.Equal(3, lowOrHigher.EndpointsMatchingFilters);
            Assert.Equal(3, lowOrHigher.EndpointsWithAnyChange);
            Assert.Equal(1, lowOrHigher.EndpointsWithHighSeverityDrift);
            Assert.Equal(1, lowOrHigher.EndpointsWithMediumSeverityDrift);
            Assert.Equal(1, lowOrHigher.EndpointsWithLowSeverityDrift);
            Assert.DoesNotContain(lowOrHigher.Endpoints, endpoint => endpoint.Host == "none.example.com");
            Assert.Contains(lowOrHigher.Endpoints, endpoint => endpoint.Host == "low.example.com");
            Assert.Contains(lowOrHigher.Endpoints, endpoint => endpoint.Host == "medium.example.com");
            Assert.Contains(lowOrHigher.Endpoints, endpoint => endpoint.Host == "high.example.com");
        }

        [Fact]
        public void BuildDriftMaxEndpointsCanBeLowerThanMatchingFilterCount() {
            var snapshots = CreateThresholdFilterSnapshots(DateTimeOffset.UtcNow);

            var capped = CertificateInventoryDriftAnalyzer.BuildDrift(
                snapshots,
                changedOnly: false,
                maxEndpoints: 1,
                minimumSeverity: "low");

            Assert.Equal(4, capped.EndpointCount);
            Assert.Equal(3, capped.EndpointsMatchingFilters);
            Assert.Equal(2, capped.EndpointsTruncatedByMaxEndpoints);
            Assert.Equal(capped.EndpointsMatchingFilters, capped.Endpoints.Count + capped.EndpointsTruncatedByMaxEndpoints);
            Assert.Single(capped.Endpoints);
        }

        [Fact]
        public void BuildDriftNegativeMaxEndpointsReturnsNoRowsAndTracksTruncation() {
            var snapshots = CreateThresholdFilterSnapshots(DateTimeOffset.UtcNow);

            var capped = CertificateInventoryDriftAnalyzer.BuildDrift(
                snapshots,
                changedOnly: false,
                maxEndpoints: -5,
                minimumSeverity: "low");

            Assert.Equal(4, capped.EndpointCount);
            Assert.Equal(3, capped.EndpointsMatchingFilters);
            Assert.Equal(3, capped.EndpointsTruncatedByMaxEndpoints);
            Assert.Empty(capped.Endpoints);
            Assert.Equal(capped.EndpointsMatchingFilters, capped.Endpoints.Count + capped.EndpointsTruncatedByMaxEndpoints);
        }

        [Fact]
        public void BuildDriftZeroMaxEndpointsReturnsNoRowsAndTracksTruncation() {
            var snapshots = CreateThresholdFilterSnapshots(DateTimeOffset.UtcNow);

            var capped = CertificateInventoryDriftAnalyzer.BuildDrift(
                snapshots,
                changedOnly: false,
                maxEndpoints: 0,
                minimumSeverity: "low");

            Assert.Equal(4, capped.EndpointCount);
            Assert.Equal(3, capped.EndpointsMatchingFilters);
            Assert.Equal(3, capped.EndpointsTruncatedByMaxEndpoints);
            Assert.Empty(capped.Endpoints);
            Assert.Equal(capped.EndpointsMatchingFilters, capped.Endpoints.Count + capped.EndpointsTruncatedByMaxEndpoints);
        }

        [Fact]
        public void BuildDriftChangeKindFilterIncludesOnlyMatchingRows() {
            var snapshots = CreateThresholdFilterSnapshots(DateTimeOffset.UtcNow);

            var filtered = CertificateInventoryDriftAnalyzer.BuildDrift(
                snapshots,
                changedOnly: false,
                maxEndpoints: 100,
                requiredChangeKinds: new[] { "expiry" });

            Assert.Equal(4, filtered.EndpointCount);
            Assert.Equal(1, filtered.EndpointsMatchingFilters);
            Assert.Equal(new[] { "expiry" }, filtered.AppliedChangeKinds);
            var endpoint = Assert.Single(filtered.Endpoints);
            Assert.Equal("low.example.com", endpoint.Host);
            Assert.Equal("Low", endpoint.DriftSeverity);
            Assert.Equal(new[] { "expiry" }, endpoint.ChangeKinds);
        }

    }
}
