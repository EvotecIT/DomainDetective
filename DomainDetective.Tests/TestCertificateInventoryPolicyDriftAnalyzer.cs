using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Tests {
    public class TestCertificateInventoryPolicyDriftAnalyzer {
        [Fact]
        public void BuildDriftDetectsAddedAndResolvedViolations() {
            var now = DateTimeOffset.UtcNow;
            var previousSnapshot = new CertificateInventorySnapshot {
                CapturedAtUtc = now.AddHours(-6),
                Port = 443,
                Entries = new List<CertificateInventoryEntry> {
                    new() {
                        Host = "api.example.com",
                        ResolvedHost = "api.example.com",
                        Port = 443,
                        Service = "HTTPS",
                        NotBeforeUtc = now.AddDays(-90),
                        NotAfterUtc = now.AddDays(-1),
                        Valid = false,
                        Expired = true,
                        ChainComplete = true,
                        IsReachable = true,
                        HostnameMatch = true,
                        IsSelfSigned = false,
                        IsKnownCertificateAuthority = true,
                        IsKnownRootCertificateAuthority = true,
                        PresentInCtLogs = true,
                        AllowsServerAuthentication = true,
                        CertificateIssuerNormalized = "Issuer A",
                        CertificateRootIssuerNormalized = "Root A",
                        CertificateThumbprint = "AABBCCDDEE00112233445566778899AABBCCDDEE"
                    }
                }
            };

            var currentSnapshot = new CertificateInventorySnapshot {
                CapturedAtUtc = now.AddHours(-1),
                Port = 443,
                Entries = new List<CertificateInventoryEntry> {
                    new() {
                        Host = "api.example.com",
                        ResolvedHost = "api.example.com",
                        Port = 443,
                        Service = "HTTPS",
                        NotBeforeUtc = now.AddDays(-20),
                        NotAfterUtc = now.AddDays(120),
                        Valid = true,
                        Expired = false,
                        ChainComplete = true,
                        IsReachable = true,
                        HostnameMatch = true,
                        IsSelfSigned = false,
                        IsKnownCertificateAuthority = true,
                        IsKnownRootCertificateAuthority = true,
                        PresentInCtLogs = true,
                        AllowsServerAuthentication = true,
                        CertificateIssuerNormalized = "Issuer A",
                        CertificateRootIssuerNormalized = "Root A",
                        CertificateThumbprint = "AABBCCDDEE00112233445566778899AABBCCDDEE"
                    },
                    new() {
                        Host = "portal.example.com",
                        ResolvedHost = "portal.example.com",
                        Port = 443,
                        Service = "HTTPS",
                        NotBeforeUtc = now.AddDays(-20),
                        NotAfterUtc = now.AddDays(180),
                        Valid = true,
                        Expired = false,
                        ChainComplete = true,
                        IsReachable = true,
                        HostnameMatch = true,
                        IsSelfSigned = false,
                        IsKnownCertificateAuthority = true,
                        IsKnownRootCertificateAuthority = true,
                        PresentInCtLogs = true,
                        AllowsServerAuthentication = true,
                        WeakKey = true,
                        CertificateIssuerNormalized = "Issuer B",
                        CertificateRootIssuerNormalized = "Root B",
                        CertificateThumbprint = "11223344556677889900AABBCCDDEEFF00112233"
                    }
                }
            };

            var drift = CertificateInventoryPolicyDriftAnalyzer.BuildDrift(
                new[] { previousSnapshot, currentSnapshot },
                baselineProfile: "Balanced",
                changedOnly: false,
                maxEndpoints: 100);

            Assert.Equal("Balanced", drift.BaselineProfile);
            Assert.Equal(2, drift.SnapshotCount);
            Assert.Equal(1, drift.PreviousEndpointCount);
            Assert.Equal(2, drift.CurrentEndpointCount);
            Assert.Equal(2, drift.EndpointCount);
            Assert.Equal(1, drift.PreviousViolationEndpointCount);
            Assert.Equal(1, drift.CurrentViolationEndpointCount);
            Assert.Equal(1, drift.AddedViolationEndpointCount);
            Assert.Equal(1, drift.ResolvedViolationEndpointCount);
            Assert.Equal(1, drift.DecreasedViolationEndpointCount);
            Assert.Equal(0, drift.IncreasedViolationEndpointCount);
            Assert.Equal(2, drift.EndpointsWithAnyPolicyChange);
            Assert.Equal(2, drift.EndpointsMatchingFilters);
            Assert.Equal(2, drift.Endpoints.Count);

            var api = drift.Endpoints.Single(endpoint => endpoint.Host == "api.example.com");
            Assert.Equal("Changed", api.Status);
            Assert.True(api.PreviousViolationCount > api.CurrentViolationCount);
            Assert.Contains(CertificateInventoryPolicyViolationCodes.CertificateExpired, api.ResolvedViolationCodes);
            Assert.DoesNotContain(CertificateInventoryPolicyViolationCodes.CertificateExpired, api.NewViolationCodes);

            var portal = drift.Endpoints.Single(endpoint => endpoint.Host == "portal.example.com");
            Assert.Equal("Added", portal.Status);
            Assert.Contains(CertificateInventoryPolicyViolationCodes.WeakKey, portal.NewViolationCodes);
            Assert.Empty(portal.ResolvedViolationCodes);

            Assert.True(drift.NewViolationCodeCounts.ContainsKey(CertificateInventoryPolicyViolationCodes.WeakKey));
            Assert.True(drift.ResolvedViolationCodeCounts.ContainsKey(CertificateInventoryPolicyViolationCodes.CertificateExpired));
        }

        [Fact]
        public void BuildDriftChangedOnlyCanExcludeUnchangedRows() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-4),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        BuildHealthyEntry(now, "steady.example.com", "00112233445566778899AABBCCDDEEFF00112233")
                    }
                },
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-1),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        BuildHealthyEntry(now, "steady.example.com", "00112233445566778899AABBCCDDEEFF00112233")
                    }
                }
            };

            var drift = CertificateInventoryPolicyDriftAnalyzer.BuildDrift(
                snapshots,
                baselineProfile: "Balanced",
                changedOnly: true,
                maxEndpoints: 100);

            Assert.Equal(1, drift.EndpointCount);
            Assert.Equal(0, drift.EndpointsWithAnyPolicyChange);
            Assert.Equal(1, drift.EndpointsExcludedByChangedOnly);
            Assert.Equal(0, drift.EndpointsMatchingFilters);
            Assert.Empty(drift.Endpoints);
        }

        [Fact]
        public void BuildDriftThrowsForInvalidProfile() {
            var ex = Assert.Throws<ArgumentException>(() => CertificateInventoryPolicyDriftAnalyzer.BuildDrift(
                snapshots: Array.Empty<CertificateInventorySnapshot>(),
                baselineProfile: "Nope"));
            Assert.Equal("baselineProfile", ex.ParamName);
        }

        [Fact]
        public void BuildDriftResolvesExplicitSnapshotPair() {
            var now = DateTimeOffset.UtcNow;
            var snapshot1 = new CertificateInventorySnapshot {
                CapturedAtUtc = now.AddDays(-3),
                Port = 443,
                Entries = new List<CertificateInventoryEntry> {
                    new() {
                        Host = "pair.example.com",
                        ResolvedHost = "pair.example.com",
                        Port = 443,
                        Service = "HTTPS",
                        NotBeforeUtc = now.AddDays(-40),
                        NotAfterUtc = now.AddDays(-1),
                        Valid = false,
                        Expired = true,
                        ChainComplete = true,
                        IsReachable = true,
                        HostnameMatch = true,
                        IsKnownCertificateAuthority = true,
                        IsKnownRootCertificateAuthority = true,
                        PresentInCtLogs = true,
                        AllowsServerAuthentication = true,
                        CertificateIssuerNormalized = "Issuer Pair",
                        CertificateRootIssuerNormalized = "Root Pair",
                        CertificateThumbprint = "ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD"
                    }
                }
            };

            var snapshot2 = new CertificateInventorySnapshot {
                CapturedAtUtc = now.AddDays(-2),
                Port = 443,
                Entries = new List<CertificateInventoryEntry> {
                    BuildHealthyEntry(now, "pair.example.com", "ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD")
                }
            };

            var snapshot3 = new CertificateInventorySnapshot {
                CapturedAtUtc = now.AddDays(-1),
                Port = 443,
                Entries = new List<CertificateInventoryEntry> {
                    new() {
                        Host = "pair.example.com",
                        ResolvedHost = "pair.example.com",
                        Port = 443,
                        Service = "HTTPS",
                        NotBeforeUtc = now.AddDays(-20),
                        NotAfterUtc = now.AddDays(120),
                        Valid = true,
                        Expired = false,
                        ChainComplete = true,
                        IsReachable = true,
                        HostnameMatch = true,
                        IsKnownCertificateAuthority = true,
                        IsKnownRootCertificateAuthority = true,
                        PresentInCtLogs = true,
                        AllowsServerAuthentication = true,
                        WeakKey = true,
                        CertificateIssuerNormalized = "Issuer Pair",
                        CertificateRootIssuerNormalized = "Root Pair",
                        CertificateThumbprint = "ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD"
                    }
                }
            };

            var drift = CertificateInventoryPolicyDriftAnalyzer.BuildDrift(
                new[] { snapshot1, snapshot2, snapshot3 },
                baselineProfile: "Balanced",
                previousCapturedAtUtc: snapshot1.CapturedAtUtc,
                currentCapturedAtUtc: snapshot2.CapturedAtUtc,
                changedOnly: false,
                maxEndpoints: 100);

            Assert.Equal(snapshot1.CapturedAtUtc, drift.PreviousCapturedAtUtc);
            Assert.Equal(snapshot2.CapturedAtUtc, drift.CurrentCapturedAtUtc);
            Assert.Equal(1, drift.PreviousViolationEndpointCount);
            Assert.Equal(0, drift.CurrentViolationEndpointCount);
            Assert.Equal(1, drift.ResolvedViolationEndpointCount);
            Assert.Equal(0, drift.AddedViolationEndpointCount);
            Assert.Empty(drift.NewViolationCodeCounts);
            Assert.True(drift.ResolvedViolationCodeCounts.ContainsKey(CertificateInventoryPolicyViolationCodes.CertificateExpired));
        }

        [Fact]
        public void BuildDriftAppliesSuppressionOverridesToViolationDeltas() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-4),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        BuildHealthyEntry(now, "override-drift.example.com", "00112233445566778899AABBCCDDEEFF00112244")
                    }
                },
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-1),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "override-drift.example.com",
                            ResolvedHost = "override-drift.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(-20),
                            NotAfterUtc = now.AddDays(120),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            IsSelfSigned = false,
                            IsKnownCertificateAuthority = true,
                            IsKnownRootCertificateAuthority = true,
                            PresentInCtLogs = true,
                            AllowsServerAuthentication = true,
                            WeakKey = true,
                            CertificateIssuerNormalized = "Issuer Healthy",
                            CertificateRootIssuerNormalized = "Root Healthy",
                            CertificateThumbprint = "00112233445566778899AABBCCDDEEFF00112244"
                        }
                    }
                }
            };
            var overrides = new CertificateInventoryPolicyOverrides {
                Defaults = new CertificateInventoryPolicyOverrideAction {
                    SuppressViolationCodes = new[] { CertificateInventoryPolicyViolationCodes.WeakKey }
                }
            };

            var drift = CertificateInventoryPolicyDriftAnalyzer.BuildDrift(
                snapshots,
                baselineProfile: "Balanced",
                changedOnly: false,
                maxEndpoints: 100,
                policyOverrides: overrides);

            var endpoint = drift.Endpoints.Single(row => row.Host == "override-drift.example.com");
            Assert.Equal("Changed", endpoint.Status);
            Assert.Empty(endpoint.NewViolationCodes);
            Assert.False(drift.NewViolationCodeCounts.ContainsKey(CertificateInventoryPolicyViolationCodes.WeakKey));
            Assert.Equal(0, drift.AddedViolationEndpointCount);
        }

        private static CertificateInventoryEntry BuildHealthyEntry(DateTimeOffset now, string host, string thumbprint) {
            return new CertificateInventoryEntry {
                Host = host,
                ResolvedHost = host,
                Port = 443,
                Service = "HTTPS",
                NotBeforeUtc = now.AddDays(-20),
                NotAfterUtc = now.AddDays(120),
                Valid = true,
                Expired = false,
                ChainComplete = true,
                IsReachable = true,
                HostnameMatch = true,
                IsSelfSigned = false,
                IsKnownCertificateAuthority = true,
                IsKnownRootCertificateAuthority = true,
                PresentInCtLogs = true,
                AllowsServerAuthentication = true,
                CertificateIssuerNormalized = "Issuer Healthy",
                CertificateRootIssuerNormalized = "Root Healthy",
                CertificateThumbprint = thumbprint
            };
        }
    }
}
