using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Tests {
    public class TestCertificateInventoryReuseAnalyzer {
        [Fact]
        public void BuildReuseFindsSharedCertificatesAcrossEndpointsAndServices() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-2),
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "api.example.com",
                            ResolvedHost = "api.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "AAA111",
                            CertificateSubject = "CN=*.example.com",
                            CertificateIssuerNormalized = "DigiCert",
                            CertificateRootIssuerNormalized = "DigiCert Global Root G2",
                            NotAfterUtc = now.AddDays(50),
                            IsKnownCertificateAuthority = true,
                            AllowsServerAuthentication = true,
                            SubjectAlternativeNames = new List<string> { "*.example.com", "api.example.com" }
                        }
                    }
                },
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "api.example.com",
                            ResolvedHost = "api.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "AAA111",
                            CertificateSubject = "CN=*.example.com",
                            CertificateIssuerNormalized = "DigiCert",
                            CertificateRootIssuerNormalized = "DigiCert Global Root G2",
                            NotAfterUtc = now.AddDays(60),
                            IsKnownCertificateAuthority = true,
                            AllowsServerAuthentication = true,
                            SubjectAlternativeNames = new List<string> { "*.example.com", "api.example.com" }
                        },
                        new() {
                            Host = "portal.example.com",
                            ResolvedHost = "portal.example.com",
                            Port = 8443,
                            Service = "HTTPS-Alt",
                            CertificateThumbprint = "AAA111",
                            CertificateSubject = "CN=*.example.com",
                            CertificateIssuerNormalized = "DigiCert",
                            CertificateRootIssuerNormalized = "DigiCert Global Root G2",
                            NotAfterUtc = now.AddDays(60),
                            IsKnownCertificateAuthority = true,
                            AllowsServerAuthentication = true,
                            SubjectAlternativeNames = new List<string> { "*.example.com", "portal.example.com" }
                        },
                        new() {
                            Host = "mail.example.com",
                            ResolvedHost = "mail.example.com",
                            Port = 25,
                            Service = "SMTP STARTTLS",
                            CertificateThumbprint = "AAA111",
                            CertificateSubject = "CN=*.example.com",
                            CertificateIssuerNormalized = "DigiCert",
                            CertificateRootIssuerNormalized = "DigiCert Global Root G2",
                            NotAfterUtc = now.AddDays(60),
                            IsKnownCertificateAuthority = true,
                            AllowsServerAuthentication = true,
                            SubjectAlternativeNames = new List<string> { "*.example.com", "mail.example.com" }
                        },
                        new() {
                            Host = "isolated.example.com",
                            ResolvedHost = "isolated.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "BBB222",
                            CertificateSubject = "CN=isolated.example.com",
                            CertificateIssuerNormalized = "Let's Encrypt",
                            NotAfterUtc = now.AddDays(30),
                            IsKnownCertificateAuthority = true,
                            AllowsServerAuthentication = true
                        }
                    }
                }
            };

            var reuse = CertificateInventoryReuseAnalyzer.BuildReuse(
                snapshots,
                includeSingleEndpointCertificates: false,
                minEndpointCount: 2,
                maxCertificates: 100,
                maxEndpointsPerCertificate: 20);

            Assert.Equal(2, reuse.SnapshotCount);
            Assert.Equal(4, reuse.EndpointCount);
            Assert.Equal(2, reuse.CertificateCount);
            Assert.Equal(1, reuse.MultiEndpointCertificateCount);
            Assert.Equal(1, reuse.CrossServiceCertificateCount);
            Assert.Equal(1, reuse.WildcardCertificateCount);
            Assert.Single(reuse.Certificates);

            var shared = reuse.Certificates[0];
            Assert.Equal(3, shared.EndpointCount);
            Assert.Equal(3, shared.DistinctServiceCount);
            Assert.Equal(3, shared.DistinctPortCount);
            Assert.True(shared.HasWildcardSan);
            Assert.Equal("DigiCert", shared.Issuer);
            Assert.Contains(shared.Endpoints, x => x.Host == "api.example.com");
            Assert.Contains(shared.Endpoints, x => x.Host == "portal.example.com");
            Assert.Contains(shared.Endpoints, x => x.Host == "mail.example.com");
        }

        [Fact]
        public void BuildReuseCanIncludeSingletonCertificates() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "single.example.com",
                            ResolvedHost = "single.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "CCC333",
                            CertificateSubject = "CN=single.example.com",
                            CertificateIssuerNormalized = "Contoso PKI",
                            NotAfterUtc = now.AddDays(20),
                            AllowsServerAuthentication = true
                        }
                    }
                }
            };

            var withoutSingletons = CertificateInventoryReuseAnalyzer.BuildReuse(snapshots);
            Assert.Empty(withoutSingletons.Certificates);

            var withSingletons = CertificateInventoryReuseAnalyzer.BuildReuse(
                snapshots,
                includeSingleEndpointCertificates: true,
                minEndpointCount: 1,
                maxCertificates: 100,
                maxEndpointsPerCertificate: 20);

            Assert.Single(withSingletons.Certificates);
            Assert.Equal(1, withSingletons.Certificates[0].EndpointCount);
        }
    }
}
