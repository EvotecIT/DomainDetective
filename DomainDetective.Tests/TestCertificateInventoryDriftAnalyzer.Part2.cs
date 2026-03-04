using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Tests {
    public partial class TestCertificateInventoryDriftAnalyzer {
        [Fact]
        public void BuildDriftChangeKindFilterSupportsAliasesAndWorksWithSeverityThreshold() {
            var snapshots = CreateThresholdFilterSnapshots(DateTimeOffset.UtcNow);

            var filtered = CertificateInventoryDriftAnalyzer.BuildDrift(
                snapshots,
                changedOnly: false,
                maxEndpoints: 100,
                minimumSeverity: "medium",
                requiredChangeKinds: new[] { "AuthProfile", "service" });

            Assert.Equal(4, filtered.EndpointCount);
            Assert.Equal(1, filtered.EndpointsMatchingFilters);
            Assert.Equal(
                new[] { "auth-profile", "service" },
                filtered.AppliedChangeKinds.OrderBy(kind => kind, StringComparer.OrdinalIgnoreCase));
            var endpoint = Assert.Single(filtered.Endpoints);
            Assert.Equal("high.example.com", endpoint.Host);
            Assert.Equal("High", endpoint.DriftSeverity);
        }

        [Fact]
        public void BuildDriftRequiredChangeKindsEmptyArrayMatchesDefaultBehavior() {
            var snapshots = CreateThresholdFilterSnapshots(DateTimeOffset.UtcNow);

            var implicitAny = CertificateInventoryDriftAnalyzer.BuildDrift(
                snapshots,
                changedOnly: false,
                maxEndpoints: 100);
            var explicitAny = CertificateInventoryDriftAnalyzer.BuildDrift(
                snapshots,
                changedOnly: false,
                maxEndpoints: 100,
                requiredChangeKinds: Array.Empty<string>());

            Assert.Equal(implicitAny.EndpointCount, explicitAny.EndpointCount);
            Assert.Equal(implicitAny.EndpointsMatchingFilters, explicitAny.EndpointsMatchingFilters);
            Assert.Equal(implicitAny.EndpointsWithAnyChange, explicitAny.EndpointsWithAnyChange);
            Assert.Equal(implicitAny.EndpointsWithHighSeverityDrift, explicitAny.EndpointsWithHighSeverityDrift);
            Assert.Equal(implicitAny.EndpointsWithMediumSeverityDrift, explicitAny.EndpointsWithMediumSeverityDrift);
            Assert.Equal(implicitAny.EndpointsWithLowSeverityDrift, explicitAny.EndpointsWithLowSeverityDrift);
            Assert.Equal(
                implicitAny.Endpoints.Select(endpoint => endpoint.Host).OrderBy(host => host),
                explicitAny.Endpoints.Select(endpoint => endpoint.Host).OrderBy(host => host));
            Assert.Empty(explicitAny.AppliedChangeKinds);
        }

        [Fact]
        public void BuildDriftRequiredChangeKindsDeduplicateMixedCaseValues() {
            var snapshots = CreateThresholdFilterSnapshots(DateTimeOffset.UtcNow);

            var filtered = CertificateInventoryDriftAnalyzer.BuildDrift(
                snapshots,
                changedOnly: false,
                maxEndpoints: 100,
                requiredChangeKinds: new[] { "SERVICE", "service", "AuthProfile", "auth-profile" });

            Assert.Equal(4, filtered.EndpointCount);
            Assert.Equal(1, filtered.EndpointsMatchingFilters);
            Assert.Equal(
                new[] { "auth-profile", "service" },
                filtered.AppliedChangeKinds.OrderBy(kind => kind, StringComparer.OrdinalIgnoreCase));
            var endpoint = Assert.Single(filtered.Endpoints);
            Assert.Equal("high.example.com", endpoint.Host);
        }

        [Fact]
        public void BuildDriftChangedOnlyAndChangeKindFilterCanBeUsedTogether() {
            var snapshots = CreateThresholdFilterSnapshots(DateTimeOffset.UtcNow);

            var filtered = CertificateInventoryDriftAnalyzer.BuildDrift(
                snapshots,
                changedOnly: true,
                maxEndpoints: 100,
                requiredChangeKinds: new[] { "certificate" });

            Assert.Equal(4, filtered.EndpointCount);
            Assert.Equal(1, filtered.EndpointsMatchingFilters);
            var endpoint = Assert.Single(filtered.Endpoints);
            Assert.Equal("medium.example.com", endpoint.Host);
            Assert.Equal("Medium", endpoint.DriftSeverity);
        }

        [Fact]
        public void BuildDriftChangeKindMatchAllRequiresAllKinds() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-4),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "both.example.com",
                            ResolvedHost = "both.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "BOTH-OLD",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(30),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            CertificateChainSource = "tls-handshake"
                        },
                        new() {
                            Host = "certificate-only.example.com",
                            ResolvedHost = "certificate-only.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "CERT-OLD",
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
                            Host = "both.example.com",
                            ResolvedHost = "both.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "BOTH-NEW",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(30),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            CertificateChainSource = "local-build-online"
                        },
                        new() {
                            Host = "certificate-only.example.com",
                            ResolvedHost = "certificate-only.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "CERT-NEW",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(30),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            CertificateChainSource = "tls-handshake"
                        }
                    }
                }
            };

            var any = CertificateInventoryDriftAnalyzer.BuildDrift(
                snapshots,
                changedOnly: false,
                maxEndpoints: 100,
                requiredChangeKinds: new[] { "certificate", "chain-source" },
                changeKindMatchMode: "any");
            Assert.Equal(2, any.EndpointsMatchingFilters);

            var all = CertificateInventoryDriftAnalyzer.BuildDrift(
                snapshots,
                changedOnly: false,
                maxEndpoints: 100,
                requiredChangeKinds: new[] { "certificate", "chain-source" },
                changeKindMatchMode: "all");
            Assert.Equal(1, all.EndpointsMatchingFilters);
            Assert.Equal("All", all.AppliedChangeKindMatchMode);
            var endpoint = Assert.Single(all.Endpoints);
            Assert.Equal("both.example.com", endpoint.Host);
            Assert.Equal(new[] { "certificate", "chain-source" }, endpoint.ChangeKinds);
        }

        [Fact]
        public void BuildDriftTracksFilterExclusionCounters() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-4),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "unchanged.example.com",
                            ResolvedHost = "unchanged.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "UNCHANGED-THUMB",
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
                            NotAfterUtc = now.AddDays(20),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            CertificateChainSource = "tls-handshake"
                        },
                        new() {
                            Host = "medium-nomatch.example.com",
                            ResolvedHost = "medium-nomatch.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "MEDIUM-OLD",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(40),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            CertificateChainSource = "tls-handshake"
                        },
                        new() {
                            Host = "included.example.com",
                            ResolvedHost = "included.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "INCLUDED-THUMB",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(40),
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
                            Host = "unchanged.example.com",
                            ResolvedHost = "unchanged.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "UNCHANGED-THUMB",
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
                            Host = "medium-nomatch.example.com",
                            ResolvedHost = "medium-nomatch.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "MEDIUM-NEW",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(40),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            CertificateChainSource = "tls-handshake"
                        },
                        new() {
                            Host = "included.example.com",
                            ResolvedHost = "included.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateThumbprint = "INCLUDED-THUMB",
                            CertificateIssuerNormalized = "DigiCert",
                            NotAfterUtc = now.AddDays(40),
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ClientAuthOnly,
                            CertificateChainSource = "tls-handshake"
                        }
                    }
                }
            };

            var summary = CertificateInventoryDriftAnalyzer.BuildDrift(
                snapshots,
                changedOnly: true,
                maxEndpoints: 100,
                minimumSeverity: "medium",
                requiredChangeKinds: new[] { "auth-profile" },
                changeKindMatchMode: "any");

            Assert.Equal(4, summary.EndpointCount);
            Assert.Equal(1, summary.EndpointsMatchingFilters);
            Assert.Equal(1, summary.EndpointsExcludedByChangedOnly);
            Assert.Equal(1, summary.EndpointsExcludedByMinimumSeverity);
            Assert.Equal(1, summary.EndpointsExcludedByChangeKindFilter);
            Assert.Equal(3, summary.EndpointsExcludedByFilters);
            Assert.Equal(0, summary.EndpointsTruncatedByMaxEndpoints);
            Assert.Equal(summary.EndpointCount, summary.EndpointsMatchingFilters + summary.EndpointsExcludedByFilters);
            Assert.Equal(summary.EndpointsMatchingFilters, summary.Endpoints.Count + summary.EndpointsTruncatedByMaxEndpoints);
            var endpoint = Assert.Single(summary.Endpoints);
            Assert.Equal("included.example.com", endpoint.Host);
        }

    }
}
