using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Tests {
    public class TestCertificateInventoryDriftAnalyzer {
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
                            Service = "HTTPS-Alt",
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
            Assert.Equal(1, drift.EndpointsWithServiceChange);
            Assert.Equal(1, drift.EndpointsWithAuthenticationProfileChange);
            Assert.Equal(1, drift.EndpointsWithChainSourceChange);
            Assert.Equal(1, drift.EndpointsWithHighSeverityDrift);
            Assert.Equal(0, drift.EndpointsWithMediumSeverityDrift);
            Assert.Equal(0, drift.EndpointsWithLowSeverityDrift);
            Assert.Equal(2, drift.Endpoints.Count);

            var api = drift.Endpoints.Single(x => x.Host == "api.example.com");
            Assert.True(api.CertificateChanged);
            Assert.True(api.IssuerChanged);
            Assert.True(api.ExpiryChanged);
            Assert.True(api.ServiceChanged);
            Assert.True(api.AuthenticationProfileChanged);
            Assert.True(api.ChainSourceChanged);
            Assert.Equal("High", api.DriftSeverity);
            Assert.Equal(new[] { "certificate", "issuer", "expiry", "service", "auth-profile", "chain-source" }, api.ChangeKinds);
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
    }
}
