using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Tests {
    public partial class TestCertificateInventoryRiskAnalyzer {
        [Fact]
        public void BuildRiskClassifiesSeverityAndTopReasons() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "expired.example.com",
                            ResolvedHost = "expired.example.com",
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
                            PresentInCtLogs = true,
                            CertificateIssuerNormalized = "Issuer A"
                        },
                        new() {
                            Host = "soon-weak.example.com",
                            ResolvedHost = "soon-weak.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(3),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true,
                            CertificateIssuerNormalized = "Issuer B"
                        },
                        new() {
                            Host = "healthy.example.com",
                            ResolvedHost = "healthy.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(180),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            CertificateIssuerNormalized = "Issuer C"
                        }
                    }
                }
            };

            var risk = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100);

            Assert.Equal(1, risk.SnapshotCount);
            Assert.Equal(3, risk.EndpointCount);
            Assert.Equal(2, risk.CriticalCount);
            Assert.Equal(0, risk.HighCount);
            Assert.Equal(0, risk.MediumCount);
            Assert.Equal(0, risk.LowCount);
            Assert.Equal(1, risk.NoRiskCount);
            Assert.Equal(2, risk.Endpoints.Count);

            var expired = risk.Endpoints.Single(x => x.Host == "expired.example.com");
            Assert.Equal("Critical", expired.Severity);
            Assert.Contains("CertificateExpired", expired.Reasons);
            Assert.Contains("CertificateValidationFailed", expired.Reasons);
            Assert.Contains("MissingServerAuthEku", expired.Reasons);

            var weak = risk.Endpoints.Single(x => x.Host == "soon-weak.example.com");
            Assert.Equal("Critical", weak.Severity);
            Assert.Contains("CertificateExpiringCritical", weak.Reasons);
            Assert.Contains("WeakKey", weak.Reasons);

            Assert.True(risk.ReasonCounts["CertificateExpired"] >= 1);
            Assert.True(risk.AverageScore > 0);
        }

        [Fact]
        public void BuildRiskExposesMatchedAndTruncatedEndpointCounts() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "expired-truncation.example.com",
                            ResolvedHost = "expired-truncation.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(-3),
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
                            Host = "weak-truncation.example.com",
                            ResolvedHost = "weak-truncation.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(60),
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
                            Host = "sha1-truncation.example.com",
                            ResolvedHost = "sha1-truncation.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(60),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            Sha1Signature = true
                        }
                    }
                }
            };

            var risk = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 2);

            Assert.Equal(3, risk.EndpointCount);
            Assert.Equal(3, risk.MatchedEndpointCount);
            Assert.Equal(1, risk.EndpointsTruncatedByMaxEndpoints);
            Assert.True(risk.Truncated);
            Assert.Equal(2, risk.Endpoints.Count);
        }

        [Fact]
        public void BuildRiskCanIncludeHealthyEndpoints() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "healthy.example.com",
                            ResolvedHost = "healthy.example.com",
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
                            CertificateIssuerNormalized = "Issuer Healthy"
                        }
                    }
                }
            };

            var risk = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100);

            Assert.Equal(1, risk.EndpointCount);
            Assert.Equal(1, risk.NoRiskCount);
            Assert.Single(risk.Endpoints);
            Assert.Equal("None", risk.Endpoints[0].Severity);
            Assert.Equal(0, risk.Endpoints[0].Score);
            Assert.Null(risk.Endpoints[0].DaysUntilValid);
            Assert.Empty(risk.Endpoints[0].Reasons);
        }

        [Fact]
        public void BuildRiskExposesZeroReuseSummaryMetricsWhenNoEndpointsExist() {
            var risk = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots: null,
                includeNoRisk: true);

            Assert.Equal(0, risk.EndpointCount);
            Assert.Equal(0, risk.UniqueCertificateIdentityCount);
            Assert.Equal(0, risk.ReusedCertificateIdentityCount);
            Assert.Equal(0d, risk.ReusedCertificateIdentityPercentage);
            Assert.Equal(0, risk.EndpointsWithReusedCertificateCount);
            Assert.Equal(0d, risk.EndpointsWithReusedCertificatePercentage);
            Assert.Equal(0, risk.CrossServiceReusedCertificateIdentityCount);
            Assert.Equal(0, risk.CrossPortReusedCertificateIdentityCount);
            Assert.Equal(0d, risk.CrossServiceReusedCertificateIdentityPercentage);
            Assert.Equal(0d, risk.CrossPortReusedCertificateIdentityPercentage);
            Assert.Equal(0, risk.EndpointsWithCrossServiceReuseCount);
            Assert.Equal(0, risk.EndpointsWithCrossPortReuseCount);
            Assert.Equal(0d, risk.EndpointsWithCrossServiceReusePercentage);
            Assert.Equal(0d, risk.EndpointsWithCrossPortReusePercentage);
            Assert.Equal(0, risk.MaxCertificateReuseEndpointCount);
            Assert.Equal(0, risk.MaxCertificateReuseDistinctServiceCount);
            Assert.Equal(0, risk.MaxCertificateReuseDistinctPortCount);
        }

        [Fact]
        public void BuildRiskFlagsNotYetValidCertificates() {
            var now = DateTimeOffset.UtcNow;
            var notBeforeUtc = now.AddDays(2);
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "future.example.com",
                            ResolvedHost = "future.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = notBeforeUtc,
                            NotAfterUtc = now.AddDays(180),
                            Valid = false,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            CertificateIssuerNormalized = "Issuer Future"
                        }
                    }
                }
            };

            var risk = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100);

            Assert.Equal(1, risk.EndpointCount);
            Assert.Equal(1, risk.CriticalCount);
            Assert.Equal(0, risk.HighCount);
            Assert.Equal(0, risk.MediumCount);
            Assert.Equal(0, risk.LowCount);
            Assert.Equal(0, risk.NoRiskCount);
            Assert.Single(risk.Endpoints);

            var future = risk.Endpoints[0];
            Assert.Equal("future.example.com", future.Host);
            Assert.Equal(notBeforeUtc, future.NotBeforeUtc);
            Assert.True(future.NotYetValid);
            Assert.Equal(2, future.DaysUntilValid);
            // 60 (not yet valid) + 45 (validation failed) is capped to 100 by design.
            Assert.Equal(100, future.Score);
            Assert.Equal("Critical", future.Severity);
            Assert.Contains("CertificateNotYetValid", future.Reasons);
            Assert.Contains("CertificateValidationFailed", future.Reasons);
            Assert.True(risk.ReasonCounts.TryGetValue("CertificateNotYetValid", out var count) && count == 1);
        }

        [Fact]
        public void BuildRiskDerivesNotYetValidFromNotBeforeEvenWhenValidFlagIsTrue() {
            var now = DateTimeOffset.UtcNow;
            var notBeforeUtc = now.AddHours(12);
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "future-valid-flag.example.com",
                            ResolvedHost = "future-valid-flag.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = notBeforeUtc,
                            NotAfterUtc = now.AddDays(120),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            CertificateIssuerNormalized = "Issuer Future Flag"
                        }
                    }
                }
            };

            var risk = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100);

            Assert.Equal(1, risk.EndpointCount);
            Assert.Equal(0, risk.CriticalCount);
            Assert.Equal(1, risk.HighCount);
            Assert.Equal(0, risk.MediumCount);
            Assert.Equal(0, risk.LowCount);
            Assert.Equal(0, risk.NoRiskCount);
            Assert.Single(risk.Endpoints);

            var future = risk.Endpoints[0];
            Assert.Equal("future-valid-flag.example.com", future.Host);
            Assert.Equal(notBeforeUtc, future.NotBeforeUtc);
            Assert.True(future.NotYetValid);
            Assert.Equal(1, future.DaysUntilValid);
            Assert.Equal(60, future.Score);
            Assert.Equal("High", future.Severity);
            Assert.Contains("CertificateNotYetValid", future.Reasons);
            Assert.DoesNotContain("CertificateValidationFailed", future.Reasons);
            Assert.True(risk.ReasonCounts.TryGetValue("CertificateNotYetValid", out var notYetValidCount) && notYetValidCount == 1);
            Assert.False(risk.ReasonCounts.ContainsKey("CertificateValidationFailed"));
        }

        [Fact]
        public void BuildRiskOrdersEqualScoresByDaysUntilValid() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "later-valid.example.com",
                            ResolvedHost = "later-valid.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(3),
                            NotAfterUtc = now.AddDays(120),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true
                        },
                        new() {
                            Host = "sooner-valid.example.com",
                            ResolvedHost = "sooner-valid.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(1),
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

            var risk = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100);

            Assert.Equal(2, risk.EndpointCount);
            Assert.Equal(2, risk.HighCount);
            Assert.Equal(2, risk.Endpoints.Count);

            Assert.Equal("sooner-valid.example.com", risk.Endpoints[0].Host);
            Assert.Equal(1, risk.Endpoints[0].DaysUntilValid);
            Assert.Equal("later-valid.example.com", risk.Endpoints[1].Host);
            Assert.Equal(3, risk.Endpoints[1].DaysUntilValid);
        }

        [Fact]
        public void BuildRiskIncludesAuthenticationProfileAndEkuFlags() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "mtls.example.com",
                            ResolvedHost = "mtls.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            AllowsServerAuthentication = true,
                            AllowsClientAuthentication = true,
                            AllowsSecureEmail = true,
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.MixedOrCustom
                        }
                    }
                }
            };

            var risk = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100);

            Assert.Equal(1, risk.EndpointCount);
            Assert.Single(risk.Endpoints);

            var endpoint = risk.Endpoints[0];
            Assert.Equal("mtls.example.com", endpoint.Host);
            Assert.True(endpoint.AllowsServerAuthentication);
            Assert.True(endpoint.AllowsClientAuthentication);
            Assert.True(endpoint.AllowsSecureEmail);
            Assert.Equal(CertificateAuthenticationProfileClassifier.MixedOrCustom, endpoint.AuthenticationProfile);
        }

        [Fact]
        public void BuildRiskDerivesAuthenticationProfileFromEkuFlagsWhenProfileMissing() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "derived-auth.example.com",
                            ResolvedHost = "derived-auth.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(120),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            HasEnhancedKeyUsageExtension = true,
                            HasAnyExtendedKeyUsageOid = false,
                            AllowsServerAuthentication = true,
                            AllowsClientAuthentication = true,
                            AllowsSecureEmail = false,
                            AuthenticationProfile = string.Empty
                        }
                    }
                }
            };

            var risk = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100);

            Assert.Equal(1, risk.EndpointCount);
            Assert.Single(risk.Endpoints);

            var endpoint = risk.Endpoints[0];
            Assert.Equal("derived-auth.example.com", endpoint.Host);
            Assert.True(endpoint.AllowsServerAuthentication);
            Assert.True(endpoint.AllowsClientAuthentication);
            Assert.False(endpoint.AllowsSecureEmail);
            Assert.Equal(CertificateAuthenticationProfileClassifier.ServerAndClientAuth, endpoint.AuthenticationProfile);
        }

        [Fact]
        public void BuildRiskAppliesMinimumSeverityFilterToReturnedEndpoints() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "critical.example.com",
                            ResolvedHost = "critical.example.com",
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
                            Host = "medium.example.com",
                            ResolvedHost = "medium.example.com",
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
                            Host = "healthy.example.com",
                            ResolvedHost = "healthy.example.com",
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

            var risk = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: "High");

            Assert.Equal(3, risk.EndpointCount);
            Assert.Equal(1, risk.CriticalCount);
            Assert.Equal(0, risk.HighCount);
            Assert.Equal(1, risk.MediumCount);
            Assert.Equal(0, risk.LowCount);
            Assert.Equal(1, risk.NoRiskCount);
            Assert.Single(risk.Endpoints);
            Assert.Equal("critical.example.com", risk.Endpoints[0].Host);
            Assert.Equal("Critical", risk.Endpoints[0].Severity);
        }

        [Fact]
        public void BuildRiskThrowsForInvalidMinimumSeverity() {
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = DateTimeOffset.UtcNow,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry>()
                }
            };

            var ex = Assert.Throws<ArgumentException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: "Sev1"));
            Assert.Equal("minimumSeverity", ex.ParamName);
        }

        [Fact]
        public void BuildRiskThrowsForInvalidRiskProfile() {
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = DateTimeOffset.UtcNow,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry>()
                }
            };

            var ex = Assert.Throws<ArgumentException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                riskProfile: "UnknownProfile"));
            Assert.Equal("riskProfile", ex.ParamName);
        }

        [Fact]
        public void BuildRiskThrowsForInvalidPortEquals() {
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = DateTimeOffset.UtcNow,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry>()
                }
            };

            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                portEquals: 70000));
            Assert.Equal("portEquals", ex.ParamName);
        }

        [Fact]
        public void BuildRiskThrowsForInvalidValidityDayWindows() {
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = DateTimeOffset.UtcNow,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry>()
                }
            };

            var daysToExpireRange = Assert.Throws<ArgumentException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                daysToExpireMin: 10,
                daysToExpireMax: 5));
            Assert.Equal("daysToExpireMin", daysToExpireRange.ParamName);

            var daysUntilValidMin = Assert.Throws<ArgumentOutOfRangeException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                daysUntilValidMin: -1));
            Assert.Equal("daysUntilValidMin", daysUntilValidMin.ParamName);
        }

        [Fact]
        public void BuildRiskThrowsForInvalidChainSizeRanges() {
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = DateTimeOffset.UtcNow,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry>()
                }
            };

            var chainLengthMin = Assert.Throws<ArgumentOutOfRangeException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                chainLengthMin: -1));
            Assert.Equal("chainLengthMin", chainLengthMin.ParamName);

            var chainLengthRange = Assert.Throws<ArgumentException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                chainLengthMin: 3,
                chainLengthMax: 2));
            Assert.Equal("chainLengthMin", chainLengthRange.ParamName);

            var intermediateCountMin = Assert.Throws<ArgumentOutOfRangeException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                intermediateCountMin: -1));
            Assert.Equal("intermediateCountMin", intermediateCountMin.ParamName);

            var intermediateCountRange = Assert.Throws<ArgumentException>(() => CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                intermediateCountMin: 2,
                intermediateCountMax: 1));
            Assert.Equal("intermediateCountMin", intermediateCountRange.ParamName);
        }

    }
}
