using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Tests {
    public partial class TestCertificateInventoryDriftAnalyzer {
        [Fact]
        public void BuildDriftThrowsForInvalidMinimumSeverity() {
            var snapshots = CreateThresholdFilterSnapshots(DateTimeOffset.UtcNow);

            Assert.Throws<ArgumentException>(() =>
                CertificateInventoryDriftAnalyzer.BuildDrift(
                    snapshots,
                    minimumSeverity: "critical"));
        }

        [Fact]
        public void BuildDriftThrowsForInvalidChangeKindMatchMode() {
            var snapshots = CreateThresholdFilterSnapshots(DateTimeOffset.UtcNow);

            Assert.Throws<ArgumentException>(() =>
                CertificateInventoryDriftAnalyzer.BuildDrift(
                    snapshots,
                    requiredChangeKinds: new[] { "certificate" },
                    changeKindMatchMode: "strict"));
        }

        [Fact]
        public void BuildDriftChangeKindMatchAllWithNoRequiredKindsBehavesLikeNoChangeKindFilter() {
            var snapshots = CreateThresholdFilterSnapshots(DateTimeOffset.UtcNow);

            var baseline = CertificateInventoryDriftAnalyzer.BuildDrift(
                snapshots,
                changedOnly: false,
                maxEndpoints: 100);
            var withAllMode = CertificateInventoryDriftAnalyzer.BuildDrift(
                snapshots,
                changedOnly: false,
                maxEndpoints: 100,
                requiredChangeKinds: Array.Empty<string>(),
                changeKindMatchMode: "all");

            Assert.Equal(baseline.EndpointCount, withAllMode.EndpointCount);
            Assert.Equal(baseline.EndpointsMatchingFilters, withAllMode.EndpointsMatchingFilters);
            Assert.Equal(baseline.EndpointsWithAnyChange, withAllMode.EndpointsWithAnyChange);
            Assert.Equal(baseline.Endpoints.Select(endpoint => endpoint.Host), withAllMode.Endpoints.Select(endpoint => endpoint.Host));
            Assert.Empty(withAllMode.AppliedChangeKinds);
            Assert.Equal("All", withAllMode.AppliedChangeKindMatchMode);
        }

        [Fact]
        public void TryNormalizeChangeKindMatchModeHandlesExpectedValues() {
            Assert.True(CertificateInventoryDriftAnalyzer.TryNormalizeChangeKindMatchMode(null, out var nullMode));
            Assert.Equal("Any", nullMode);

            Assert.True(CertificateInventoryDriftAnalyzer.TryNormalizeChangeKindMatchMode("  ", out var whitespaceMode));
            Assert.Equal("Any", whitespaceMode);

            Assert.True(CertificateInventoryDriftAnalyzer.TryNormalizeChangeKindMatchMode("ANY", out var anyMode));
            Assert.Equal("Any", anyMode);

            Assert.True(CertificateInventoryDriftAnalyzer.TryNormalizeChangeKindMatchMode("aLl", out var allMode));
            Assert.Equal("All", allMode);

            Assert.False(CertificateInventoryDriftAnalyzer.TryNormalizeChangeKindMatchMode("strict", out _));
        }

        [Fact]
        public void BuildDriftThrowsForInvalidRequiredChangeKind() {
            var snapshots = CreateThresholdFilterSnapshots(DateTimeOffset.UtcNow);

            Assert.Throws<ArgumentException>(() =>
                CertificateInventoryDriftAnalyzer.BuildDrift(
                    snapshots,
                    requiredChangeKinds: new[] { "certificate", "broken-kind" }));
        }

        private static CertificateInventorySnapshot[] CreateThresholdFilterSnapshots(DateTimeOffset now) {
            return new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-5),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "none.example.com",
                            ResolvedHost = "none.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "NONE-THUMB",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(30),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            CertificateChainSource = "tls-handshake"
                        },
                        new() {
                            Host = "low.example.com",
                            ResolvedHost = "low.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "LOW-THUMB",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(30),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            CertificateChainSource = "tls-handshake"
                        },
                        new() {
                            Host = "medium.example.com",
                            ResolvedHost = "medium.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "MEDIUM-OLD",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(45),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            CertificateChainSource = "tls-handshake"
                        },
                        new() {
                            Host = "high.example.com",
                            ResolvedHost = "high.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "HIGH-THUMB",
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
                            Host = "none.example.com",
                            ResolvedHost = "none.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "NONE-THUMB",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(30),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            CertificateChainSource = "tls-handshake"
                        },
                        new() {
                            Host = "low.example.com",
                            ResolvedHost = "low.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "LOW-THUMB",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(60),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            CertificateChainSource = "tls-handshake"
                        },
                        new() {
                            Host = "medium.example.com",
                            ResolvedHost = "medium.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "MEDIUM-NEW",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(45),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            CertificateChainSource = "tls-handshake"
                        },
                        new() {
                            Host = "high.example.com",
                            ResolvedHost = "high.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "HIGH-THUMB",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(90),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ClientAuthOnly,
                            CertificateChainSource = "tls-handshake"
                        }
                    }
                }
            };
        }
    }
}
