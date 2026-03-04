using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Tests {
    public partial class TestCertificateInventoryRiskAnalyzer {
        [Fact]
        public void BuildRiskThrowsForInvalidScoreRange() {
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = DateTimeOffset.UtcNow,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry>()
                }
            };

            var scoreMin = Assert.Throws<ArgumentOutOfRangeException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                scoreMin: -1));
            Assert.Equal("scoreMin", scoreMin.ParamName);

            var scoreMax = Assert.Throws<ArgumentOutOfRangeException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                scoreMax: 101));
            Assert.Equal("scoreMax", scoreMax.ParamName);

            var scoreRange = Assert.Throws<ArgumentException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                scoreMin: 80,
                scoreMax: 20));
            Assert.Equal("scoreMin", scoreRange.ParamName);
        }

        [Fact]
        public void BuildRiskThrowsForInvalidReasonCountRange() {
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = DateTimeOffset.UtcNow,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry>()
                }
            };

            var reasonCountMin = Assert.Throws<ArgumentOutOfRangeException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                reasonCountMin: -1));
            Assert.Equal("reasonCountMin", reasonCountMin.ParamName);

            var reasonCountMax = Assert.Throws<ArgumentOutOfRangeException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                reasonCountMax: -1));
            Assert.Equal("reasonCountMax", reasonCountMax.ParamName);

            var reasonCountRange = Assert.Throws<ArgumentException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                reasonCountMin: 3,
                reasonCountMax: 1));
            Assert.Equal("reasonCountMin", reasonCountRange.ParamName);
        }

        [Fact]
        public void BuildRiskThrowsForInvalidCertificateReuseRange() {
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = DateTimeOffset.UtcNow,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry>()
                }
            };

            var reuseMin = Assert.Throws<ArgumentOutOfRangeException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                certificateReuseEndpointCountMin: 0));
            Assert.Equal("certificateReuseEndpointCountMin", reuseMin.ParamName);

            var reuseMax = Assert.Throws<ArgumentOutOfRangeException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                certificateReuseEndpointCountMax: 0));
            Assert.Equal("certificateReuseEndpointCountMax", reuseMax.ParamName);

            var reuseRange = Assert.Throws<ArgumentException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                certificateReuseEndpointCountMin: 5,
                certificateReuseEndpointCountMax: 2));
            Assert.Equal("certificateReuseEndpointCountMin", reuseRange.ParamName);

            var reuseDistinctServiceMin = Assert.Throws<ArgumentOutOfRangeException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                certificateReuseDistinctServiceCountMin: 0));
            Assert.Equal("certificateReuseDistinctServiceCountMin", reuseDistinctServiceMin.ParamName);

            var reuseDistinctServiceMax = Assert.Throws<ArgumentOutOfRangeException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                certificateReuseDistinctServiceCountMax: 0));
            Assert.Equal("certificateReuseDistinctServiceCountMax", reuseDistinctServiceMax.ParamName);

            var reuseDistinctServiceRange = Assert.Throws<ArgumentException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                certificateReuseDistinctServiceCountMin: 3,
                certificateReuseDistinctServiceCountMax: 1));
            Assert.Equal("certificateReuseDistinctServiceCountMin", reuseDistinctServiceRange.ParamName);

            var reuseDistinctPortMin = Assert.Throws<ArgumentOutOfRangeException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                certificateReuseDistinctPortCountMin: 0));
            Assert.Equal("certificateReuseDistinctPortCountMin", reuseDistinctPortMin.ParamName);

            var reuseDistinctPortMax = Assert.Throws<ArgumentOutOfRangeException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                certificateReuseDistinctPortCountMax: 0));
            Assert.Equal("certificateReuseDistinctPortCountMax", reuseDistinctPortMax.ParamName);

            var reuseDistinctPortRange = Assert.Throws<ArgumentException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                certificateReuseDistinctPortCountMin: 3,
                certificateReuseDistinctPortCountMax: 1));
            Assert.Equal("certificateReuseDistinctPortCountMin", reuseDistinctPortRange.ParamName);
        }

        [Fact]
        public void BuildRiskAppliesRiskProfilesAndSupportsExplicitOverrides() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "renewal-7.example.com",
                            ResolvedHost = "renewal-7.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(-20),
                            NotAfterUtc = now.AddDays(7),
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
                            Host = "renewal-25.example.com",
                            ResolvedHost = "renewal-25.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(-20),
                            NotAfterUtc = now.AddDays(25),
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
                            Host = "future-6.example.com",
                            ResolvedHost = "future-6.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(6),
                            NotAfterUtc = now.AddDays(100),
                            Valid = false,
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
                            Host = "expired-1.example.com",
                            ResolvedHost = "expired-1.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(-40),
                            NotAfterUtc = now.AddDays(-1),
                            Valid = false,
                            Expired = true,
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

            var renewal14 = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                riskProfile: "Renewal14d");
            Assert.Single(renewal14.Endpoints);
            Assert.Equal("renewal-7.example.com", renewal14.Endpoints[0].Host);

            var renewal30 = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                riskProfile: "renewal30D");
            Assert.Equal(2, renewal30.Endpoints.Count);
            Assert.Contains(renewal30.Endpoints, endpoint => endpoint.Host.Equals("renewal-7.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(renewal30.Endpoints, endpoint => endpoint.Host.Equals("renewal-25.example.com", StringComparison.OrdinalIgnoreCase));

            var futureNotYetValid = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                riskProfile: "FutureNotYetValid");
            Assert.Single(futureNotYetValid.Endpoints);
            Assert.Equal("future-6.example.com", futureNotYetValid.Endpoints[0].Host);

            var expired = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                riskProfile: "Expired");
            Assert.Single(expired.Endpoints);
            Assert.Equal("expired-1.example.com", expired.Endpoints[0].Host);

            var renewal14WithOverride = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                riskProfile: "Renewal14d",
                daysToExpireMax: 30);
            Assert.Equal(2, renewal14WithOverride.Endpoints.Count);
            Assert.Contains(renewal14WithOverride.Endpoints, endpoint => endpoint.Host.Equals("renewal-7.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(renewal14WithOverride.Endpoints, endpoint => endpoint.Host.Equals("renewal-25.example.com", StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public void BuildRiskTreatsNoneAsNoAdditionalFilterAndSupportsCaseInsensitiveSeverity() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "critical-case.example.com",
                            ResolvedHost = "critical-case.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(-1),
                            Valid = false,
                            Expired = true,
                            ChainComplete = false,
                            IsReachable = true,
                            HostnameMatch = false,
                            AllowsServerAuthentication = false,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true
                        },
                        new() {
                            Host = "medium-case.example.com",
                            ResolvedHost = "medium-case.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(120),
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
                            Host = "healthy-case.example.com",
                            ResolvedHost = "healthy-case.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(120),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true
                        }
                    }
                }
            };

            var withoutMinimumSeverity = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100);

            var withNoneSeverity = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: "None");

            Assert.Equal(withoutMinimumSeverity.Endpoints.Count, withNoneSeverity.Endpoints.Count);
            Assert.Equal(
                string.Join(",", withoutMinimumSeverity.Endpoints.Select(endpoint => endpoint.Host)),
                string.Join(",", withNoneSeverity.Endpoints.Select(endpoint => endpoint.Host)));

            var withMixedCaseHigh = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: "hIgH");
            Assert.Single(withMixedCaseHigh.Endpoints);
            Assert.Equal("critical-case.example.com", withMixedCaseHigh.Endpoints[0].Host);

            var withNoneSeverityDefaultInclude = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: "None");
            Assert.Equal(2, withNoneSeverityDefaultInclude.Endpoints.Count);
            Assert.DoesNotContain(withNoneSeverityDefaultInclude.Endpoints, endpoint => string.Equals(endpoint.Host, "healthy-case.example.com", StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByScoreRange() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "expired-score.example.com",
                            ResolvedHost = "expired-score.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(-2),
                            Valid = false,
                            Expired = true,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true
                        },
                        new() {
                            Host = "weak-score.example.com",
                            ResolvedHost = "weak-score.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(120),
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
                            Host = "healthy-score.example.com",
                            ResolvedHost = "healthy-score.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(120),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true
                        }
                    }
                }
            };

            var highScores = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                scoreMin: 60,
                scoreMax: 100);
            Assert.Single(highScores.Endpoints);
            Assert.Equal("expired-score.example.com", highScores.Endpoints[0].Host);
            Assert.Equal(100, highScores.Endpoints[0].Score);

            var midScores = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                scoreMin: 1,
                scoreMax: 40);
            Assert.Single(midScores.Endpoints);
            Assert.Equal("weak-score.example.com", midScores.Endpoints[0].Host);
            Assert.Equal(35, midScores.Endpoints[0].Score);

            var healthyScores = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                scoreMin: 0,
                scoreMax: 0);
            Assert.Single(healthyScores.Endpoints);
            Assert.Equal("healthy-score.example.com", healthyScores.Endpoints[0].Host);
            Assert.Equal(0, healthyScores.Endpoints[0].Score);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByReasonCountRange() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "expired-many-reasons.example.com",
                            ResolvedHost = "expired-many-reasons.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(-2),
                            Valid = false,
                            Expired = true,
                            ChainComplete = false,
                            IsReachable = true,
                            HostnameMatch = false,
                            AllowsServerAuthentication = false,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true
                        },
                        new() {
                            Host = "weak-single-reason.example.com",
                            ResolvedHost = "weak-single-reason.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(120),
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
                            Host = "healthy-zero-reasons.example.com",
                            ResolvedHost = "healthy-zero-reasons.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(120),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true
                        }
                    }
                }
            };

            var atLeastTwoReasons = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                reasonCountMin: 2);
            Assert.Single(atLeastTwoReasons.Endpoints);
            Assert.Equal("expired-many-reasons.example.com", atLeastTwoReasons.Endpoints[0].Host);
            Assert.True(atLeastTwoReasons.Endpoints[0].Reasons.Count >= 2);

            var oneReasonOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                reasonCountMin: 1,
                reasonCountMax: 1);
            Assert.Single(oneReasonOnly.Endpoints);
            Assert.Equal("weak-single-reason.example.com", oneReasonOnly.Endpoints[0].Host);
            Assert.Single(oneReasonOnly.Endpoints[0].Reasons);

            var zeroReasonOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                reasonCountMin: 0,
                reasonCountMax: 0);
            Assert.Single(zeroReasonOnly.Endpoints);
            Assert.Equal("healthy-zero-reasons.example.com", zeroReasonOnly.Endpoints[0].Host);
            Assert.Empty(zeroReasonOnly.Endpoints[0].Reasons);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByCertificateReuse() {
            var now = DateTimeOffset.UtcNow;
            const string reusedThumbprint = "AA11BB22CC33DD44EE55FF6677889900AABBCCDD";
            const string singletonThumbprint = "11AA22BB33CC44DD55EE66FF77889900AABBCCDD";
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "reuse-a.example.com",
                            ResolvedHost = "reuse-a.example.com",
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
                            CertificateThumbprint = reusedThumbprint
                        },
                        new() {
                            Host = "reuse-b.example.com",
                            ResolvedHost = "reuse-b.example.com",
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
                            CertificateThumbprint = reusedThumbprint
                        },
                        new() {
                            Host = "reuse-c.example.com",
                            ResolvedHost = "reuse-c.example.com",
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
                            CertificateThumbprint = reusedThumbprint
                        },
                        new() {
                            Host = "singleton.example.com",
                            ResolvedHost = "singleton.example.com",
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
                            CertificateThumbprint = singletonThumbprint
                        }
                    }
                }
            };

            var allEndpoints = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true);
            Assert.Equal(4, allEndpoints.Endpoints.Count);
            Assert.Equal(2, allEndpoints.UniqueCertificateIdentityCount);
            Assert.Equal(1, allEndpoints.ReusedCertificateIdentityCount);
            Assert.Equal(50d, allEndpoints.ReusedCertificateIdentityPercentage);
            Assert.Equal(3, allEndpoints.EndpointsWithReusedCertificateCount);
            Assert.Equal(75d, allEndpoints.EndpointsWithReusedCertificatePercentage);
            Assert.Equal(1, allEndpoints.CrossServiceReusedCertificateIdentityCount);
            Assert.Equal(1, allEndpoints.CrossPortReusedCertificateIdentityCount);
            Assert.Equal(50d, allEndpoints.CrossServiceReusedCertificateIdentityPercentage);
            Assert.Equal(50d, allEndpoints.CrossPortReusedCertificateIdentityPercentage);
            Assert.Equal(3, allEndpoints.EndpointsWithCrossServiceReuseCount);
            Assert.Equal(3, allEndpoints.EndpointsWithCrossPortReuseCount);
            Assert.Equal(75d, allEndpoints.EndpointsWithCrossServiceReusePercentage);
            Assert.Equal(75d, allEndpoints.EndpointsWithCrossPortReusePercentage);
            Assert.Equal(3, allEndpoints.MaxCertificateReuseEndpointCount);
            Assert.Equal(2, allEndpoints.MaxCertificateReuseDistinctServiceCount);
            Assert.Equal(2, allEndpoints.MaxCertificateReuseDistinctPortCount);

            var reused = allEndpoints.Endpoints.Single(endpoint => endpoint.Host == "reuse-a.example.com");
            Assert.Equal(3, reused.CertificateReuseEndpointCount);
            Assert.Equal(2, reused.CertificateReuseDistinctServiceCount);
            Assert.Equal(2, reused.CertificateReuseDistinctPortCount);

            var singleton = allEndpoints.Endpoints.Single(endpoint => endpoint.Host == "singleton.example.com");
            Assert.Equal(1, singleton.CertificateReuseEndpointCount);
            Assert.Equal(1, singleton.CertificateReuseDistinctServiceCount);
            Assert.Equal(1, singleton.CertificateReuseDistinctPortCount);

            var reusedOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                certificateReuseEndpointCountMin: 2);
            Assert.Equal(3, reusedOnly.Endpoints.Count);
            Assert.All(reusedOnly.Endpoints, endpoint => Assert.Equal(3, endpoint.CertificateReuseEndpointCount));

            var singletonOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                certificateReuseEndpointCountMax: 1);
            Assert.Single(singletonOnly.Endpoints);
            Assert.Equal("singleton.example.com", singletonOnly.Endpoints[0].Host);

            var crossServiceOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                certificateReuseCrossServiceOnly: true);
            Assert.Equal(3, crossServiceOnly.Endpoints.Count);
            Assert.All(crossServiceOnly.Endpoints, endpoint => Assert.True(endpoint.CertificateReuseDistinctServiceCount > 1));

            var singleServiceOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                certificateReuseCrossServiceOnly: false);
            Assert.Single(singleServiceOnly.Endpoints);
            Assert.Equal("singleton.example.com", singleServiceOnly.Endpoints[0].Host);

            var distinctServiceFiltered = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                certificateReuseDistinctServiceCountMin: 2,
                certificateReuseDistinctServiceCountMax: 2);
            Assert.Equal(3, distinctServiceFiltered.Endpoints.Count);
            Assert.All(distinctServiceFiltered.Endpoints, endpoint => Assert.Equal(2, endpoint.CertificateReuseDistinctServiceCount));

            var distinctServiceSingle = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                certificateReuseDistinctServiceCountMax: 1);
            Assert.Single(distinctServiceSingle.Endpoints);
            Assert.Equal("singleton.example.com", distinctServiceSingle.Endpoints[0].Host);

            var distinctPortFiltered = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                certificateReuseDistinctPortCountMin: 2,
                certificateReuseDistinctPortCountMax: 2);
            Assert.Equal(3, distinctPortFiltered.Endpoints.Count);
            Assert.All(distinctPortFiltered.Endpoints, endpoint => Assert.Equal(2, endpoint.CertificateReuseDistinctPortCount));

            var crossPortOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                certificateReuseCrossPortOnly: true);
            Assert.Equal(3, crossPortOnly.Endpoints.Count);
            Assert.All(crossPortOnly.Endpoints, endpoint => Assert.True(endpoint.CertificateReuseDistinctPortCount > 1));

            var singlePortOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                certificateReuseCrossPortOnly: false);
            Assert.Single(singlePortOnly.Endpoints);
            Assert.Equal("singleton.example.com", singlePortOnly.Endpoints[0].Host);
        }

    }
}
