using System;
using System.Collections.Generic;

namespace DomainDetective.Tests {
    public class TestCertificateInventoryAnalyzer {
        [Fact]
        public void BuildSummaryUsesLatestEndpointObservation() {
            var now = DateTimeOffset.UtcNow;
            var older = new CertificateInventorySnapshot {
                CapturedAtUtc = now.AddHours(-4),
                Port = 443,
                Entries = new List<CertificateInventoryEntry> {
                    new() {
                        Host = "api.example.com",
                        ResolvedHost = "api.example.com",
                        Port = 443,
                        Service = "HTTPS",
                        NotAfterUtc = now.AddDays(5),
                        ChainComplete = true,
                        IsReachable = true,
                        AllowsServerAuthentication = true,
                        AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                        CertificateChainSource = "tls-handshake",
                        CtDiscoverySources = new List<string> { "crt.sh" },
                        CertificateIssuer = "CN=R3, O=Let's Encrypt, C=US",
                        CertificateRootIssuerNormalized = "ISRG Root X1"
                    }
                }
            };
            var latest = new CertificateInventorySnapshot {
                CapturedAtUtc = now.AddHours(-1),
                Port = 443,
                Entries = new List<CertificateInventoryEntry> {
                    new() {
                        Host = "api.example.com",
                        ResolvedHost = "api.example.com",
                        Port = 443,
                        Service = "HTTPS",
                        NotAfterUtc = now.AddDays(120),
                        ChainComplete = true,
                        IsReachable = true,
                        AllowsServerAuthentication = true,
                        AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                        CertificateChainSource = "tls-handshake",
                        CtDiscoverySources = new List<string> { "crt.sh", "shodan" },
                        CertificateIssuerNormalized = "Let's Encrypt",
                        CertificateRootIssuerNormalized = "ISRG Root X1"
                    },
                    new() {
                        Host = "portal.example.com",
                        ResolvedHost = "portal.example.com",
                        Port = 8443,
                        Service = "HTTPS-Alt",
                        NotAfterUtc = now.AddDays(-2),
                        ChainComplete = false,
                        IsReachable = true,
                        AllowsServerAuthentication = false,
                        AllowsClientAuthentication = true,
                        AuthenticationProfile = CertificateAuthenticationProfileClassifier.ClientAuthOnly,
                        CtTemplateFormatErrors = new List<string> { "CensysApiUrlTemplate: source enabled but template is empty." },
                        CertificateChainSource = "local-build-no-check",
                        CertificateIssuer = "CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US",
                        CertificateRootIssuerNormalized = "DigiCert Global Root G2"
                    },
                    new() {
                        Host = "mail.example.com",
                        ResolvedHost = "mail.example.com",
                        Port = 443,
                        Service = "HTTPS",
                        NotAfterUtc = now.AddDays(20),
                        ChainComplete = true,
                        IsReachable = true,
                        IsSelfSigned = true,
                        AllowsServerAuthentication = true,
                        AllowsSecureEmail = true,
                        AuthenticationProfile = CertificateAuthenticationProfileClassifier.MixedOrCustom,
                        CertificateChainSource = "local-build-online",
                        CertificateIssuerOrganization = "Contoso Security",
                        CertificateRootIssuerNormalized = "Contoso Root CA"
                    }
                }
            };

            var summary = CertificateInventoryAnalyzer.BuildSummary(new[] { older, latest }, expiringWithinDays: 30, maxExpiringEndpoints: 100);

            Assert.Equal(2, summary.SnapshotCount);
            Assert.Equal(4, summary.SampleCount);
            Assert.Equal(3, summary.UniqueEndpointCount);
            Assert.Equal(1, summary.ExpiredEndpointCount);
            Assert.Equal(1, summary.ExpiringSoonEndpointCount);
            Assert.Equal(1, summary.MissingServerAuthEndpointCount);
            Assert.Equal(1, summary.ClientAuthEndpointCount);
            Assert.Equal(1, summary.SecureEmailEndpointCount);
            Assert.Equal(1, summary.SelfSignedEndpointCount);
            Assert.Equal(1, summary.IncompleteChainEndpointCount);
            Assert.Equal(1, summary.CtTemplateErrorEndpointCount);
            Assert.Equal(2, summary.ServiceCounts["HTTPS"]);
            Assert.Equal(1, summary.ServiceCounts["HTTPS-Alt"]);
            Assert.Equal(1, summary.IssuerCounts["Let's Encrypt"]);
            Assert.Equal(1, summary.IssuerCounts["DigiCert"]);
            Assert.Equal(1, summary.IssuerCounts["Contoso Security"]);
            Assert.Equal(1, summary.RootIssuerCounts["ISRG Root X1"]);
            Assert.Equal(1, summary.RootIssuerCounts["DigiCert Global Root G2"]);
            Assert.Equal(1, summary.RootIssuerCounts["Contoso Root CA"]);
            Assert.Equal(1, summary.AuthenticationProfileCounts[CertificateAuthenticationProfileClassifier.ServerAuthOnly]);
            Assert.Equal(1, summary.AuthenticationProfileCounts[CertificateAuthenticationProfileClassifier.ClientAuthOnly]);
            Assert.Equal(1, summary.AuthenticationProfileCounts[CertificateAuthenticationProfileClassifier.MixedOrCustom]);
            Assert.Equal(1, summary.ChainSourceCounts["tls-handshake"]);
            Assert.Equal(1, summary.ChainSourceCounts["local-build-no-check"]);
            Assert.Equal(1, summary.CtSourceCounts["crt.sh"]);
            Assert.Equal(1, summary.CtSourceCounts["shodan"]);
            Assert.Equal(2, summary.CtSourceCounts["none"]);
            Assert.Equal(1, summary.CtTemplateErrorCounts["CensysApiUrlTemplate"]);
            Assert.Single(summary.ExpiringSoon);
            Assert.Equal("mail.example.com", summary.ExpiringSoon[0].Host);
        }
    }
}
