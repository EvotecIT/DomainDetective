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
                            NotAfterUtc = now.AddDays(30)
                        },
                        new() {
                            Host = "portal.example.com",
                            ResolvedHost = "portal.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "ZZZ999",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(90)
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
                            NotAfterUtc = now.AddDays(365)
                        },
                        new() {
                            Host = "portal.example.com",
                            ResolvedHost = "portal.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "ZZZ999",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(90)
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
            Assert.Equal(2, drift.Endpoints.Count);

            var api = drift.Endpoints.Single(x => x.Host == "api.example.com");
            Assert.True(api.CertificateChanged);
            Assert.True(api.IssuerChanged);
            Assert.True(api.ExpiryChanged);
            Assert.True(api.ServiceChanged);
            Assert.Equal("AAA111", api.PreviousCertificateId);
            Assert.Equal("BBB222", api.CurrentCertificateId);
            Assert.NotNull(api.LastChangedAtUtc);
            Assert.Equal(2, api.ObservationCount);
            Assert.Equal(2, api.DistinctCertificateCount);

            var portal = drift.Endpoints.Single(x => x.Host == "portal.example.com");
            Assert.False(portal.CertificateChanged);
            Assert.False(portal.IssuerChanged);
            Assert.False(portal.ExpiryChanged);
            Assert.False(portal.ServiceChanged);
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
    }
}
