using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Tests {
    public class TestCertificateInventoryRiskAnalyzer {
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
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByReasonContains() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "expired-reason.example.com",
                            ResolvedHost = "expired-reason.example.com",
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
                            Host = "weak-reason.example.com",
                            ResolvedHost = "weak-reason.example.com",
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
                            Host = "healthy-reason.example.com",
                            ResolvedHost = "healthy-reason.example.com",
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

            var filteredByWeakKey = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: "wEaK");
            Assert.Single(filteredByWeakKey.Endpoints);
            Assert.Equal("weak-reason.example.com", filteredByWeakKey.Endpoints[0].Host);
            Assert.Contains("WeakKey", filteredByWeakKey.Endpoints[0].Reasons);

            var filteredByExpiredWithoutNoRisk = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: "expired");
            Assert.Single(filteredByExpiredWithoutNoRisk.Endpoints);
            Assert.Equal("expired-reason.example.com", filteredByExpiredWithoutNoRisk.Endpoints[0].Host);
            Assert.Contains("CertificateExpired", filteredByExpiredWithoutNoRisk.Endpoints[0].Reasons);

            var filteredByNoneWithoutNoRisk = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: "none");
            Assert.Empty(filteredByNoneWithoutNoRisk.Endpoints);

            var filteredByMissingReason = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: "does-not-exist");
            Assert.Empty(filteredByMissingReason.Endpoints);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByReasonAnyOfAndReasonAllOf() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "expired-only-reason-list.example.com",
                            ResolvedHost = "expired-only-reason-list.example.com",
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
                            Host = "weak-only-reason-list.example.com",
                            ResolvedHost = "weak-only-reason-list.example.com",
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
                            Host = "expired-weak-reason-list.example.com",
                            ResolvedHost = "expired-weak-reason-list.example.com",
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
                            PresentInCtLogs = true,
                            WeakKey = true
                        },
                        new() {
                            Host = "healthy-reason-list.example.com",
                            ResolvedHost = "healthy-reason-list.example.com",
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

            var filteredByAnyReason = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                reasonAnyOf: new[] { "WeakKey", "Sha1Signature" });
            Assert.Equal(2, filteredByAnyReason.Endpoints.Count);
            Assert.Contains(filteredByAnyReason.Endpoints, endpoint => string.Equals(endpoint.Host, "weak-only-reason-list.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByAnyReason.Endpoints, endpoint => string.Equals(endpoint.Host, "expired-weak-reason-list.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByAllReasons = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                reasonAllOf: new[] { "CertificateExpired", "WeakKey" });
            Assert.Single(filteredByAllReasons.Endpoints);
            Assert.Equal("expired-weak-reason-list.example.com", filteredByAllReasons.Endpoints[0].Host);
            Assert.Contains("CertificateExpired", filteredByAllReasons.Endpoints[0].Reasons);
            Assert.Contains("WeakKey", filteredByAllReasons.Endpoints[0].Reasons);

            var filteredByReasonContainsAndAnyReason = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: "validation",
                reasonAnyOf: new[] { "CertificateExpired" });
            Assert.Equal(2, filteredByReasonContainsAndAnyReason.Endpoints.Count);
            Assert.Contains(filteredByReasonContainsAndAnyReason.Endpoints, endpoint => string.Equals(endpoint.Host, "expired-only-reason-list.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByReasonContainsAndAnyReason.Endpoints, endpoint => string.Equals(endpoint.Host, "expired-weak-reason-list.example.com", StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public void BuildRiskTreatsWhitespaceReasonAnyOfAndReasonAllOfAsAbsent() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "expired-whitespace-reason-list.example.com",
                            ResolvedHost = "expired-whitespace-reason-list.example.com",
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
                            Host = "weak-whitespace-reason-list.example.com",
                            ResolvedHost = "weak-whitespace-reason-list.example.com",
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
                        }
                    }
                }
            };

            var filteredByReasonAnyWithWhitespace = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                reasonAnyOf: new[] { "  ", "WeakKey", "weakkey" },
                reasonAllOf: new[] { "   " });
            Assert.Single(filteredByReasonAnyWithWhitespace.Endpoints);
            Assert.Equal("weak-whitespace-reason-list.example.com", filteredByReasonAnyWithWhitespace.Endpoints[0].Host);

            var filteredByOnlyWhitespaceReasonLists = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                reasonAnyOf: new[] { "   " },
                reasonAllOf: new[] { "   " });
            // Whitespace-only reason lists are treated as absent, so all risk-bearing entries are returned.
            Assert.Equal(2, filteredByOnlyWhitespaceReasonLists.Endpoints.Count);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByIssuerContains() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "digicert-issuer.example.com",
                            ResolvedHost = "digicert-issuer.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(5),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true,
                            CertificateIssuerNormalized = "DigiCert TLS RSA SHA256 2020 CA1",
                            CertificateRootIssuerNormalized = "DigiCert Global Root G2"
                        },
                        new() {
                            Host = "isrg-root.example.com",
                            ResolvedHost = "isrg-root.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(4),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            CertificateIssuerNormalized = "R3",
                            CertificateRootIssuerNormalized = "ISRG Root X1"
                        },
                        new() {
                            Host = "other-issuer.example.com",
                            ResolvedHost = "other-issuer.example.com",
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
                            CertificateIssuerNormalized = "Contoso Trust Services",
                            CertificateRootIssuerNormalized = "Contoso Root CA"
                        },
                        new() {
                            Host = "healthy-contoso-issuer.example.com",
                            ResolvedHost = "healthy-contoso-issuer.example.com",
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
                            CertificateIssuerNormalized = "Contoso Trust Services",
                            CertificateRootIssuerNormalized = "Contoso Root CA"
                        }
                    }
                }
            };

            var filteredByLeafIssuer = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: "digicert");
            Assert.Single(filteredByLeafIssuer.Endpoints);
            Assert.Equal("digicert-issuer.example.com", filteredByLeafIssuer.Endpoints[0].Host);
            Assert.Contains("DigiCert", filteredByLeafIssuer.Endpoints[0].Issuer, StringComparison.OrdinalIgnoreCase);

            var filteredByRootIssuer = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: "isrg");
            Assert.Single(filteredByRootIssuer.Endpoints);
            Assert.Equal("isrg-root.example.com", filteredByRootIssuer.Endpoints[0].Host);
            Assert.Contains("ISRG", filteredByRootIssuer.Endpoints[0].RootIssuer, StringComparison.OrdinalIgnoreCase);

            var filteredByIssuerWithoutNoRisk = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: "contoso");
            Assert.Single(filteredByIssuerWithoutNoRisk.Endpoints);
            Assert.Equal("other-issuer.example.com", filteredByIssuerWithoutNoRisk.Endpoints[0].Host);
            Assert.DoesNotContain(filteredByIssuerWithoutNoRisk.Endpoints, endpoint => string.Equals(endpoint.Host, "healthy-contoso-issuer.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByIssuerAndReason = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: "WeakKey",
                issuerContains: "digicert");
            Assert.Single(filteredByIssuerAndReason.Endpoints);
            Assert.Equal("digicert-issuer.example.com", filteredByIssuerAndReason.Endpoints[0].Host);

            var filteredByWhitespaceIssuer = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: "   ");
            Assert.Equal(4, filteredByWhitespaceIssuer.Endpoints.Count);

            var filteredByMissingIssuer = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: "not-present");
            Assert.Empty(filteredByMissingIssuer.Endpoints);

            var filteredByIssuerAnyOf = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                issuerContainsAnyOf: new[] { "digicert", "isrg" });
            Assert.Equal(2, filteredByIssuerAnyOf.Endpoints.Count);
            Assert.Contains(filteredByIssuerAnyOf.Endpoints, endpoint => string.Equals(endpoint.Host, "digicert-issuer.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByIssuerAnyOf.Endpoints, endpoint => string.Equals(endpoint.Host, "isrg-root.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByIssuerAllOf = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                issuerContainsAllOf: new[] { "contoso", "root" });
            Assert.Equal(2, filteredByIssuerAllOf.Endpoints.Count);
            Assert.Contains(filteredByIssuerAllOf.Endpoints, endpoint => string.Equals(endpoint.Host, "other-issuer.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByIssuerAllOf.Endpoints, endpoint => string.Equals(endpoint.Host, "healthy-contoso-issuer.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByIssuerAnyAndAll = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                issuerContainsAnyOf: new[] { "contoso", "digicert" },
                issuerContainsAllOf: new[] { "root" });
            Assert.Equal(3, filteredByIssuerAnyAndAll.Endpoints.Count);
            Assert.Contains(filteredByIssuerAnyAndAll.Endpoints, endpoint => string.Equals(endpoint.Host, "digicert-issuer.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByIssuerAnyAndAll.Endpoints, endpoint => string.Equals(endpoint.Host, "other-issuer.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByIssuerAnyAndAll.Endpoints, endpoint => string.Equals(endpoint.Host, "healthy-contoso-issuer.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByWhitespaceIssuerLists = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                issuerContainsAnyOf: new[] { "  ", "DIGICERT", "digicert" },
                issuerContainsAllOf: new[] { "   " });
            Assert.Single(filteredByWhitespaceIssuerLists.Endpoints);
            Assert.Equal("digicert-issuer.example.com", filteredByWhitespaceIssuerLists.Endpoints[0].Host);

            var filteredByRootIssuerContains = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                rootIssuerContains: "isrg root");
            Assert.Single(filteredByRootIssuerContains.Endpoints);
            Assert.Equal("isrg-root.example.com", filteredByRootIssuerContains.Endpoints[0].Host);

            var filteredByRootIssuerAnyOf = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                rootIssuerContainsAnyOf: new[] { "global root", "root x1" });
            Assert.Equal(2, filteredByRootIssuerAnyOf.Endpoints.Count);
            Assert.Contains(filteredByRootIssuerAnyOf.Endpoints, endpoint => string.Equals(endpoint.Host, "digicert-issuer.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByRootIssuerAnyOf.Endpoints, endpoint => string.Equals(endpoint.Host, "isrg-root.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByRootIssuerAllOf = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                rootIssuerContainsAllOf: new[] { "contoso", "root" });
            Assert.Equal(2, filteredByRootIssuerAllOf.Endpoints.Count);
            Assert.Contains(filteredByRootIssuerAllOf.Endpoints, endpoint => string.Equals(endpoint.Host, "other-issuer.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByRootIssuerAllOf.Endpoints, endpoint => string.Equals(endpoint.Host, "healthy-contoso-issuer.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByWhitespaceRootIssuerLists = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                rootIssuerContainsAnyOf: new[] { "   ", "isrg root", "ISRG ROOT" },
                rootIssuerContainsAllOf: new[] { "   " });
            Assert.Single(filteredByWhitespaceRootIssuerLists.Endpoints);
            Assert.Equal("isrg-root.example.com", filteredByWhitespaceRootIssuerLists.Endpoints[0].Host);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByHostServiceAndPort() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "api.example.com",
                            ResolvedHost = "api.example.com",
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
                            WeakKey = true
                        },
                        new() {
                            Host = "api-alt.example.com",
                            ResolvedHost = "api-alt.example.com",
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
                            WeakKey = true
                        },
                        new() {
                            Host = "mail.example.com",
                            ResolvedHost = "mail.example.com",
                            Port = 25,
                            Service = "SMTP TLS",
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
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

            var filteredByHost = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                hostContains: "api");
            Assert.Equal(2, filteredByHost.Endpoints.Count);
            Assert.Contains(filteredByHost.Endpoints, endpoint => string.Equals(endpoint.Host, "api.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByHost.Endpoints, endpoint => string.Equals(endpoint.Host, "api-alt.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByService = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                serviceEquals: "https-alt");
            Assert.Single(filteredByService.Endpoints);
            Assert.Equal("api-alt.example.com", filteredByService.Endpoints[0].Host);

            var filteredByPort = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                portEquals: 25);
            Assert.Single(filteredByPort.Endpoints);
            Assert.Equal("mail.example.com", filteredByPort.Endpoints[0].Host);

            var filteredByHostServiceAndPort = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                hostContains: "api",
                serviceEquals: "HTTPS-Alt",
                portEquals: 8443);
            Assert.Single(filteredByHostServiceAndPort.Endpoints);
            Assert.Equal("api-alt.example.com", filteredByHostServiceAndPort.Endpoints[0].Host);

            var filteredByMissingService = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                serviceEquals: "not-present");
            Assert.Empty(filteredByMissingService.Endpoints);

            var filteredByWhitespaceHostAndService = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                hostContains: "   ",
                serviceEquals: "   ");
            Assert.Equal(3, filteredByWhitespaceHostAndService.Endpoints.Count);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByChainLengthAndIntermediateCount() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "chain-length-1.example.com",
                            ResolvedHost = "chain-length-1.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateChainLength = 1,
                            CertificateIntermediateCount = 0,
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = false,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true
                        },
                        new() {
                            Host = "chain-length-2.example.com",
                            ResolvedHost = "chain-length-2.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateChainLength = 2,
                            CertificateIntermediateCount = 0,
                            NotAfterUtc = now.AddDays(90),
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
                            Host = "chain-length-3.example.com",
                            ResolvedHost = "chain-length-3.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            CertificateChainLength = 3,
                            CertificateIntermediateCount = 1,
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
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

            var allRiskRows = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false);
            Assert.Equal(3, allRiskRows.Endpoints.Count);
            var chainLengthThree = allRiskRows.Endpoints.Single(endpoint => string.Equals(endpoint.Host, "chain-length-3.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Equal(3, chainLengthThree.ChainLength);
            Assert.Equal(1, chainLengthThree.IntermediateCount);

            var filteredByChainLengthMin = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                chainLengthMin: 2);
            Assert.Equal(2, filteredByChainLengthMin.Endpoints.Count);
            Assert.Contains(filteredByChainLengthMin.Endpoints, endpoint => string.Equals(endpoint.Host, "chain-length-2.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByChainLengthMin.Endpoints, endpoint => string.Equals(endpoint.Host, "chain-length-3.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByChainLengthMax = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                chainLengthMax: 2);
            Assert.Equal(2, filteredByChainLengthMax.Endpoints.Count);
            Assert.Contains(filteredByChainLengthMax.Endpoints, endpoint => string.Equals(endpoint.Host, "chain-length-1.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByChainLengthMax.Endpoints, endpoint => string.Equals(endpoint.Host, "chain-length-2.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByIntermediateCountMin = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                intermediateCountMin: 1);
            Assert.Single(filteredByIntermediateCountMin.Endpoints);
            Assert.Equal("chain-length-3.example.com", filteredByIntermediateCountMin.Endpoints[0].Host);

            var filteredByChainAndIntermediate = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                chainLengthMin: 2,
                intermediateCountMax: 0);
            Assert.Single(filteredByChainAndIntermediate.Endpoints);
            Assert.Equal("chain-length-2.example.com", filteredByChainAndIntermediate.Endpoints[0].Host);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByCtObservationAndChainCompleteness() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "public-complete.example.com",
                            ResolvedHost = "public-complete.example.com",
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
                            WeakKey = true
                        },
                        new() {
                            Host = "private-complete.example.com",
                            ResolvedHost = "private-complete.example.com",
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
                            PresentInCtLogs = false,
                            WeakKey = true
                        },
                        new() {
                            Host = "public-incomplete.example.com",
                            ResolvedHost = "public-incomplete.example.com",
                            Port = 8443,
                            Service = "HTTPS-Alt",
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = false,
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

            var ctObserved = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                ctObservedOnly: true);
            Assert.Equal(2, ctObserved.Endpoints.Count);
            Assert.Contains(ctObserved.Endpoints, endpoint => endpoint.Host.Equals("public-complete.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(ctObserved.Endpoints, endpoint => endpoint.Host.Equals("public-incomplete.example.com", StringComparison.OrdinalIgnoreCase));

            var ctMissing = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                ctObservedOnly: false);
            Assert.Single(ctMissing.Endpoints);
            Assert.Equal("private-complete.example.com", ctMissing.Endpoints[0].Host);

            var chainComplete = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                chainCompleteOnly: true);
            Assert.Equal(2, chainComplete.Endpoints.Count);
            Assert.Contains(chainComplete.Endpoints, endpoint => endpoint.Host.Equals("public-complete.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(chainComplete.Endpoints, endpoint => endpoint.Host.Equals("private-complete.example.com", StringComparison.OrdinalIgnoreCase));

            var chainIncomplete = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                chainCompleteOnly: false);
            Assert.Single(chainIncomplete.Endpoints);
            Assert.Equal("public-incomplete.example.com", chainIncomplete.Endpoints[0].Host);

            var ctObservedAndChainIncomplete = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                ctObservedOnly: true,
                chainCompleteOnly: false);
            Assert.Single(ctObservedAndChainIncomplete.Endpoints);
            Assert.Equal("public-incomplete.example.com", ctObservedAndChainIncomplete.Endpoints[0].Host);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByReachabilityAndHostnameValidation() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "reachable-match.example.com",
                            ResolvedHost = "reachable-match.example.com",
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
                            WeakKey = true
                        },
                        new() {
                            Host = "unreachable-match.example.com",
                            ResolvedHost = "unreachable-match.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = false,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true
                        },
                        new() {
                            Host = "reachable-mismatch.example.com",
                            ResolvedHost = "reachable-mismatch.example.com",
                            Port = 8443,
                            Service = "HTTPS-Alt",
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = false,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true
                        }
                    }
                }
            };

            var reachable = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                reachableOnly: true);
            Assert.Equal(2, reachable.Endpoints.Count);
            Assert.Contains(reachable.Endpoints, endpoint => endpoint.Host.Equals("reachable-match.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(reachable.Endpoints, endpoint => endpoint.Host.Equals("reachable-mismatch.example.com", StringComparison.OrdinalIgnoreCase));

            var unreachable = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                reachableOnly: false);
            Assert.Single(unreachable.Endpoints);
            Assert.Equal("unreachable-match.example.com", unreachable.Endpoints[0].Host);

            var hostnameMatch = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                hostnameMatchOnly: true);
            Assert.Equal(2, hostnameMatch.Endpoints.Count);
            Assert.Contains(hostnameMatch.Endpoints, endpoint => endpoint.Host.Equals("reachable-match.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(hostnameMatch.Endpoints, endpoint => endpoint.Host.Equals("unreachable-match.example.com", StringComparison.OrdinalIgnoreCase));

            var hostnameMismatch = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                hostnameMatchOnly: false);
            Assert.Single(hostnameMismatch.Endpoints);
            Assert.Equal("reachable-mismatch.example.com", hostnameMismatch.Endpoints[0].Host);

            var reachableAndHostnameMismatch = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                reachableOnly: true,
                hostnameMatchOnly: false);
            Assert.Single(reachableAndHostnameMismatch.Endpoints);
            Assert.Equal("reachable-mismatch.example.com", reachableAndHostnameMismatch.Endpoints[0].Host);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsBySelfSignedAndCryptoState() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "selfsigned-weak-sha1.example.com",
                            ResolvedHost = "selfsigned-weak-sha1.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(45),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsSelfSigned = true,
                            IsKnownCertificateAuthority = false,
                            PresentInCtLogs = false,
                            WeakKey = true,
                            Sha1Signature = true
                        },
                        new() {
                            Host = "casigned-strong-modern.example.com",
                            ResolvedHost = "casigned-strong-modern.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(-1),
                            Valid = false,
                            Expired = true,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsSelfSigned = false,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = false,
                            Sha1Signature = false
                        },
                        new() {
                            Host = "casigned-weak-modern.example.com",
                            ResolvedHost = "casigned-weak-modern.example.com",
                            Port = 8443,
                            Service = "HTTPS-Alt",
                            NotAfterUtc = now.AddDays(45),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsSelfSigned = false,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true,
                            Sha1Signature = false
                        }
                    }
                }
            };

            var selfSigned = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                selfSignedOnly: true);
            Assert.Single(selfSigned.Endpoints);
            Assert.Equal("selfsigned-weak-sha1.example.com", selfSigned.Endpoints[0].Host);

            var caSigned = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                selfSignedOnly: false);
            Assert.Equal(2, caSigned.Endpoints.Count);
            Assert.Contains(caSigned.Endpoints, endpoint => endpoint.Host.Equals("casigned-strong-modern.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(caSigned.Endpoints, endpoint => endpoint.Host.Equals("casigned-weak-modern.example.com", StringComparison.OrdinalIgnoreCase));

            var weakKey = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                weakKeyOnly: true);
            Assert.Equal(2, weakKey.Endpoints.Count);
            Assert.Contains(weakKey.Endpoints, endpoint => endpoint.Host.Equals("selfsigned-weak-sha1.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(weakKey.Endpoints, endpoint => endpoint.Host.Equals("casigned-weak-modern.example.com", StringComparison.OrdinalIgnoreCase));

            var strongKey = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                weakKeyOnly: false);
            Assert.Single(strongKey.Endpoints);
            Assert.Equal("casigned-strong-modern.example.com", strongKey.Endpoints[0].Host);

            var sha1 = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                sha1SignatureOnly: true);
            Assert.Single(sha1.Endpoints);
            Assert.Equal("selfsigned-weak-sha1.example.com", sha1.Endpoints[0].Host);

            var nonSha1 = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                sha1SignatureOnly: false);
            Assert.Equal(2, nonSha1.Endpoints.Count);
            Assert.Contains(nonSha1.Endpoints, endpoint => endpoint.Host.Equals("casigned-strong-modern.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(nonSha1.Endpoints, endpoint => endpoint.Host.Equals("casigned-weak-modern.example.com", StringComparison.OrdinalIgnoreCase));

            var selfSignedWeakAndSha1 = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                selfSignedOnly: true,
                weakKeyOnly: true,
                sha1SignatureOnly: true);
            Assert.Single(selfSignedWeakAndSha1.Endpoints);
            Assert.Equal("selfsigned-weak-sha1.example.com", selfSignedWeakAndSha1.Endpoints[0].Host);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByValidityState() {
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
                            NotBeforeUtc = now.AddDays(-120),
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
                        },
                        new() {
                            Host = "notyetvalid.example.com",
                            ResolvedHost = "notyetvalid.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(5),
                            NotAfterUtc = now.AddDays(120),
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
                            Host = "currentlyvalid.example.com",
                            ResolvedHost = "currentlyvalid.example.com",
                            Port = 8443,
                            Service = "HTTPS-Alt",
                            NotBeforeUtc = now.AddDays(-10),
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
                        }
                    }
                }
            };

            var expiredOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiredOnly: true);
            Assert.Single(expiredOnly.Endpoints);
            Assert.Equal("expired.example.com", expiredOnly.Endpoints[0].Host);

            var notExpiredOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiredOnly: false);
            Assert.Equal(2, notExpiredOnly.Endpoints.Count);
            Assert.Contains(notExpiredOnly.Endpoints, endpoint => endpoint.Host.Equals("notyetvalid.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(notExpiredOnly.Endpoints, endpoint => endpoint.Host.Equals("currentlyvalid.example.com", StringComparison.OrdinalIgnoreCase));

            var notYetValidOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                notYetValidOnly: true);
            Assert.Single(notYetValidOnly.Endpoints);
            Assert.Equal("notyetvalid.example.com", notYetValidOnly.Endpoints[0].Host);

            var alreadyValidOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                notYetValidOnly: false);
            Assert.Equal(2, alreadyValidOnly.Endpoints.Count);
            Assert.Contains(alreadyValidOnly.Endpoints, endpoint => endpoint.Host.Equals("expired.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(alreadyValidOnly.Endpoints, endpoint => endpoint.Host.Equals("currentlyvalid.example.com", StringComparison.OrdinalIgnoreCase));

            var currentlyValidOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                currentlyValidOnly: true);
            Assert.Single(currentlyValidOnly.Endpoints);
            Assert.Equal("currentlyvalid.example.com", currentlyValidOnly.Endpoints[0].Host);

            var currentlyInvalidOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                currentlyValidOnly: false);
            Assert.Equal(2, currentlyInvalidOnly.Endpoints.Count);
            Assert.Contains(currentlyInvalidOnly.Endpoints, endpoint => endpoint.Host.Equals("expired.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(currentlyInvalidOnly.Endpoints, endpoint => endpoint.Host.Equals("notyetvalid.example.com", StringComparison.OrdinalIgnoreCase));

            var currentlyInvalidAndNotExpired = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                currentlyValidOnly: false,
                expiredOnly: false);
            Assert.Single(currentlyInvalidAndNotExpired.Endpoints);
            Assert.Equal("notyetvalid.example.com", currentlyInvalidAndNotExpired.Endpoints[0].Host);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByValidityDayWindows() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "expired-window.example.com",
                            ResolvedHost = "expired-window.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(-60),
                            NotAfterUtc = now.AddDays(-2),
                            Valid = false,
                            Expired = true,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true
                        },
                        new() {
                            Host = "expiring-window.example.com",
                            ResolvedHost = "expiring-window.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(-30),
                            NotAfterUtc = now.AddDays(8),
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
                            Host = "long-valid-window.example.com",
                            ResolvedHost = "long-valid-window.example.com",
                            Port = 8443,
                            Service = "HTTPS-Alt",
                            NotBeforeUtc = now.AddDays(-30),
                            NotAfterUtc = now.AddDays(45),
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
                            Host = "future-window.example.com",
                            ResolvedHost = "future-window.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotBeforeUtc = now.AddDays(5),
                            NotAfterUtc = now.AddDays(120),
                            Valid = false,
                            Expired = false,
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

            var expiringSoon = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                daysToExpireMin: 0,
                daysToExpireMax: 14);
            Assert.Single(expiringSoon.Endpoints);
            Assert.Equal("expiring-window.example.com", expiringSoon.Endpoints[0].Host);

            var alreadyExpired = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                daysToExpireMax: -1);
            Assert.Single(alreadyExpired.Endpoints);
            Assert.Equal("expired-window.example.com", alreadyExpired.Endpoints[0].Host);

            var longCurrentlyValid = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                daysToExpireMin: 30,
                currentlyValidOnly: true);
            Assert.Single(longCurrentlyValid.Endpoints);
            Assert.Equal("long-valid-window.example.com", longCurrentlyValid.Endpoints[0].Host);

            var futureByDaysUntilValid = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                daysUntilValidMin: 0,
                daysUntilValidMax: 10);
            Assert.Single(futureByDaysUntilValid.Endpoints);
            Assert.Equal("future-window.example.com", futureByDaysUntilValid.Endpoints[0].Host);

            var noFutureInShortWindow = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                daysUntilValidMin: 0,
                daysUntilValidMax: 2);
            Assert.Empty(noFutureInShortWindow.Endpoints);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByAuthUsageFlags() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "server-auth-only.example.com",
                            ResolvedHost = "server-auth-only.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(120),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            AllowsClientAuthentication = false,
                            AllowsSecureEmail = false,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                            WeakKey = true
                        },
                        new() {
                            Host = "client-auth-only.example.com",
                            ResolvedHost = "client-auth-only.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(120),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = false,
                            AllowsClientAuthentication = true,
                            AllowsSecureEmail = false,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ClientAuthOnly,
                            WeakKey = true
                        },
                        new() {
                            Host = "secure-email-only.example.com",
                            ResolvedHost = "secure-email-only.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(120),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = false,
                            AllowsClientAuthentication = false,
                            AllowsSecureEmail = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.SecureEmailOnly,
                            WeakKey = true
                        },
                        new() {
                            Host = "full-auth.example.com",
                            ResolvedHost = "full-auth.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(120),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            AllowsClientAuthentication = true,
                            AllowsSecureEmail = true,
                            IsKnownCertificateAuthority = true,
                            PresentInCtLogs = true,
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.MixedOrCustom,
                            WeakKey = true
                        }
                    }
                }
            };

            var serverOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                serverAuthOnly: true);
            Assert.Equal(2, serverOnly.Endpoints.Count);
            Assert.Contains(serverOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "server-auth-only.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(serverOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "full-auth.example.com", StringComparison.OrdinalIgnoreCase));

            var clientOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                clientAuthOnly: true);
            Assert.Equal(2, clientOnly.Endpoints.Count);
            Assert.Contains(clientOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "client-auth-only.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(clientOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "full-auth.example.com", StringComparison.OrdinalIgnoreCase));

            var secureEmailOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                secureEmailOnly: true);
            Assert.Equal(2, secureEmailOnly.Endpoints.Count);
            Assert.Contains(secureEmailOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "secure-email-only.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(secureEmailOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "full-auth.example.com", StringComparison.OrdinalIgnoreCase));

            var serverAndClient = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                serverAuthOnly: true,
                clientAuthOnly: true);
            Assert.Single(serverAndClient.Endpoints);
            Assert.Equal("full-auth.example.com", serverAndClient.Endpoints[0].Host);

            var filteredByAuthenticationProfile = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authenticationProfileEquals: "serverauthonly");
            Assert.Single(filteredByAuthenticationProfile.Endpoints);
            Assert.Equal("server-auth-only.example.com", filteredByAuthenticationProfile.Endpoints[0].Host);
            Assert.Equal(CertificateAuthenticationProfileClassifier.ServerAuthOnly, filteredByAuthenticationProfile.Endpoints[0].AuthenticationProfile);

            var filteredByMissingAuthenticationProfile = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authenticationProfileEquals: "not-present");
            Assert.Empty(filteredByMissingAuthenticationProfile.Endpoints);

            var filteredByWhitespaceAuthenticationProfile = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authenticationProfileEquals: "   ");
            Assert.Equal(4, filteredByWhitespaceAuthenticationProfile.Endpoints.Count);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByAuthorityFamilyFilters() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "letsencrypt-risk.example.com",
                            ResolvedHost = "letsencrypt-risk.example.com",
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
                            CertificateAuthorityFamily = "LetsEncrypt",
                            CertificateRootAuthorityFamily = "LetsEncrypt",
                            WeakKey = true
                        },
                        new() {
                            Host = "digicert-risk.example.com",
                            ResolvedHost = "digicert-risk.example.com",
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
                            CertificateAuthorityFamily = "DigiCert",
                            CertificateRootAuthorityFamily = "DigiCert",
                            WeakKey = true
                        },
                        new() {
                            Host = "gts-risk.example.com",
                            ResolvedHost = "gts-risk.example.com",
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
                            CertificateAuthorityFamily = "GoogleTrustServices",
                            CertificateRootAuthorityFamily = "GoogleTrustServices",
                            WeakKey = true
                        },
                        new() {
                            Host = "letsencrypt-healthy.example.com",
                            ResolvedHost = "letsencrypt-healthy.example.com",
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
                            CertificateAuthorityFamily = "LetsEncrypt",
                            CertificateRootAuthorityFamily = "LetsEncrypt"
                        },
                        new() {
                            Host = "unknown-family-risk.example.com",
                            ResolvedHost = "unknown-family-risk.example.com",
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
                            WeakKey = true
                        }
                    }
                }
            };

            var filteredByLeafFamily = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: "letsencrypt");
            Assert.Single(filteredByLeafFamily.Endpoints);
            Assert.Equal("letsencrypt-risk.example.com", filteredByLeafFamily.Endpoints[0].Host);
            Assert.DoesNotContain(filteredByLeafFamily.Endpoints, endpoint => string.Equals(endpoint.Host, "unknown-family-risk.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByLeafFamilyIncludingHealthy = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: "letsencrypt");
            Assert.Equal(2, filteredByLeafFamilyIncludingHealthy.Endpoints.Count);
            Assert.Contains(filteredByLeafFamilyIncludingHealthy.Endpoints, endpoint => string.Equals(endpoint.Host, "letsencrypt-risk.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(filteredByLeafFamilyIncludingHealthy.Endpoints, endpoint => string.Equals(endpoint.Host, "letsencrypt-healthy.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(filteredByLeafFamilyIncludingHealthy.Endpoints, endpoint => string.Equals(endpoint.Host, "unknown-family-risk.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByRootFamily = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: "digicert");
            Assert.Single(filteredByRootFamily.Endpoints);
            Assert.Equal("digicert-risk.example.com", filteredByRootFamily.Endpoints[0].Host);

            var filteredByBothFamilies = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: "LetsEncrypt",
                rootAuthorityFamilyEquals: "LetsEncrypt");
            Assert.Single(filteredByBothFamilies.Endpoints);
            Assert.Equal("letsencrypt-risk.example.com", filteredByBothFamilies.Endpoints[0].Host);

            var filteredByMissingFamily = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: "not-present");
            Assert.Empty(filteredByMissingFamily.Endpoints);

            var filteredByWhitespaceFamily = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: true,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: "   ",
                rootAuthorityFamilyEquals: "   ");
            Assert.Equal(5, filteredByWhitespaceFamily.Endpoints.Count);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByKnownAuthorityState() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "known-leaf-known-root.example.com",
                            ResolvedHost = "known-leaf-known-root.example.com",
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
                            IsKnownRootCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true
                        },
                        new() {
                            Host = "unknown-leaf-known-root.example.com",
                            ResolvedHost = "unknown-leaf-known-root.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = false,
                            IsKnownRootCertificateAuthority = true,
                            PresentInCtLogs = true,
                            WeakKey = true
                        },
                        new() {
                            Host = "known-leaf-unknown-root.example.com",
                            ResolvedHost = "known-leaf-unknown-root.example.com",
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
                            IsKnownRootCertificateAuthority = false,
                            PresentInCtLogs = true,
                            WeakKey = true
                        },
                        new() {
                            Host = "unknown-leaf-unknown-root.example.com",
                            ResolvedHost = "unknown-leaf-unknown-root.example.com",
                            Port = 443,
                            Service = "HTTPS",
                            NotAfterUtc = now.AddDays(90),
                            Valid = true,
                            Expired = false,
                            ChainComplete = true,
                            IsReachable = true,
                            HostnameMatch = true,
                            AllowsServerAuthentication = true,
                            IsKnownCertificateAuthority = false,
                            IsKnownRootCertificateAuthority = false,
                            PresentInCtLogs = true,
                            WeakKey = true
                        }
                    }
                }
            };

            var knownLeafOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                knownAuthorityOnly: true);
            Assert.Equal(2, knownLeafOnly.Endpoints.Count);
            Assert.Contains(knownLeafOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "known-leaf-known-root.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(knownLeafOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "known-leaf-unknown-root.example.com", StringComparison.OrdinalIgnoreCase));

            var unknownLeafOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                knownAuthorityOnly: false);
            Assert.Equal(2, unknownLeafOnly.Endpoints.Count);
            Assert.Contains(unknownLeafOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "unknown-leaf-known-root.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(unknownLeafOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "unknown-leaf-unknown-root.example.com", StringComparison.OrdinalIgnoreCase));

            var knownRootOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                knownRootAuthorityOnly: true);
            Assert.Equal(2, knownRootOnly.Endpoints.Count);
            Assert.Contains(knownRootOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "known-leaf-known-root.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(knownRootOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "unknown-leaf-known-root.example.com", StringComparison.OrdinalIgnoreCase));

            var unknownRootOnly = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                knownRootAuthorityOnly: false);
            Assert.Equal(2, unknownRootOnly.Endpoints.Count);
            Assert.Contains(unknownRootOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "known-leaf-unknown-root.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(unknownRootOnly.Endpoints, endpoint => string.Equals(endpoint.Host, "unknown-leaf-unknown-root.example.com", StringComparison.OrdinalIgnoreCase));

            var unknownLeafAndUnknownRoot = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                knownAuthorityOnly: false,
                knownRootAuthorityOnly: false);
            Assert.Single(unknownLeafAndUnknownRoot.Endpoints);
            Assert.Equal("unknown-leaf-unknown-root.example.com", unknownLeafAndUnknownRoot.Endpoints[0].Host);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsBySourceFilters() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "crtsh-source.example.com",
                            ResolvedHost = "crtsh-source.example.com",
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
                            WeakKey = true,
                            CtDiscoverySources = new[] { "crt.sh", "shodan" },
                            CtTemplateFormatErrors = new[] { "ShodanApiUrlTemplate" },
                            CertificateChainSource = "tls-handshake",
                            CertificateChainSources = new List<string> { "tls-handshake", "cert-spotter" }
                        },
                        new() {
                            Host = "censys-source.example.com",
                            ResolvedHost = "censys-source.example.com",
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
                            WeakKey = true,
                            CtDiscoverySources = new[] { "censys" },
                            CtTemplateFormatErrors = new[] { "CensysApiUrlTemplate" },
                            CertificateChainSource = "aia-download",
                            CertificateChainSources = new List<string> { "aia-download" }
                        },
                        new() {
                            Host = "historical-chain-source.example.com",
                            ResolvedHost = "historical-chain-source.example.com",
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
                            WeakKey = true,
                            CtDiscoverySources = new[] { "internal-scan" },
                            CertificateChainSource = string.Empty,
                            CertificateChainSources = new List<string> { "cached-chain-bundle" }
                        }
                    }
                }
            };

            var filteredByCtSource = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: "crt.sh");
            Assert.Single(filteredByCtSource.Endpoints);
            Assert.Equal("crtsh-source.example.com", filteredByCtSource.Endpoints[0].Host);
            Assert.Contains("crt.sh", filteredByCtSource.Endpoints[0].CtDiscoverySources, StringComparer.OrdinalIgnoreCase);

            var filteredByTemplateError = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: "censysapi");
            Assert.Single(filteredByTemplateError.Endpoints);
            Assert.Equal("censys-source.example.com", filteredByTemplateError.Endpoints[0].Host);

            var filteredByPrimaryChainSource = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: null,
                chainSourceContains: "aia-download");
            Assert.Single(filteredByPrimaryChainSource.Endpoints);
            Assert.Equal("censys-source.example.com", filteredByPrimaryChainSource.Endpoints[0].Host);

            var filteredByHistoricalChainSource = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: null,
                chainSourceContains: "cached-chain");
            Assert.Single(filteredByHistoricalChainSource.Endpoints);
            Assert.Equal("historical-chain-source.example.com", filteredByHistoricalChainSource.Endpoints[0].Host);
            Assert.Equal(string.Empty, filteredByHistoricalChainSource.Endpoints[0].ChainSource);
            Assert.Contains("cached-chain-bundle", filteredByHistoricalChainSource.Endpoints[0].ChainSources, StringComparer.OrdinalIgnoreCase);

            var filteredByCtAndChain = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: "shodan",
                ctTemplateErrorContains: null,
                chainSourceContains: "tls-handshake");
            Assert.Single(filteredByCtAndChain.Endpoints);
            Assert.Equal("crtsh-source.example.com", filteredByCtAndChain.Endpoints[0].Host);

            var filteredByWhitespaceSourceFilters = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: "   ",
                ctTemplateErrorContains: "   ",
                chainSourceContains: "   ");
            // Whitespace-only source filters are treated as absent, so all three risk-bearing entries are returned.
            Assert.Equal(3, filteredByWhitespaceSourceFilters.Endpoints.Count);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByThumbprintEquals() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "thumbprint-a.example.com",
                            ResolvedHost = "thumbprint-a.example.com",
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
                            CertificateThumbprint = "AA11BB22CC33DD44EE55FF6677889900AABBCCDD",
                            WeakKey = true
                        },
                        new() {
                            Host = "thumbprint-b.example.com",
                            ResolvedHost = "thumbprint-b.example.com",
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
                            CertificateThumbprint = "11223344556677889900AABBCCDDEEFF00112233",
                            WeakKey = true
                        },
                        new() {
                            Host = "thumbprint-missing.example.com",
                            ResolvedHost = "thumbprint-missing.example.com",
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
                            WeakKey = true
                        }
                    }
                }
            };

            var filteredByThumbprint = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: null,
                chainSourceContains: null,
                thumbprintEquals: "aa11bb22cc33dd44ee55ff6677889900aabbccdd");
            Assert.Single(filteredByThumbprint.Endpoints);
            Assert.Equal("thumbprint-a.example.com", filteredByThumbprint.Endpoints[0].Host);
            Assert.Equal("AA11BB22CC33DD44EE55FF6677889900AABBCCDD", filteredByThumbprint.Endpoints[0].CertificateThumbprint);
            Assert.DoesNotContain(filteredByThumbprint.Endpoints, endpoint => string.Equals(endpoint.Host, "thumbprint-missing.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByMissingThumbprint = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: null,
                chainSourceContains: null,
                thumbprintEquals: "not-present");
            Assert.Empty(filteredByMissingThumbprint.Endpoints);

            var filteredByWhitespaceThumbprint = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: null,
                chainSourceContains: null,
                thumbprintEquals: "   ");
            Assert.Equal(3, filteredByWhitespaceThumbprint.Endpoints.Count);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsByRootThumbprintEquals() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "root-thumbprint-a.example.com",
                            ResolvedHost = "root-thumbprint-a.example.com",
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
                            CertificateRootThumbprint = "5A3F4D2C1B0099887766554433221100AABBCCDD",
                            WeakKey = true
                        },
                        new() {
                            Host = "root-thumbprint-b.example.com",
                            ResolvedHost = "root-thumbprint-b.example.com",
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
                            CertificateRootThumbprint = "00112233445566778899AABBCCDDEEFF00112233",
                            WeakKey = true
                        },
                        new() {
                            Host = "root-thumbprint-missing.example.com",
                            ResolvedHost = "root-thumbprint-missing.example.com",
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
                            WeakKey = true
                        }
                    }
                }
            };

            var filteredByRootThumbprint = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: null,
                chainSourceContains: null,
                thumbprintEquals: null,
                rootThumbprintEquals: "5a3f:4d2c1b00 99887766554433221100aabbccdd");
            Assert.Single(filteredByRootThumbprint.Endpoints);
            Assert.Equal("root-thumbprint-a.example.com", filteredByRootThumbprint.Endpoints[0].Host);
            Assert.Equal("5A3F4D2C1B0099887766554433221100AABBCCDD", filteredByRootThumbprint.Endpoints[0].CertificateRootThumbprint);
            Assert.DoesNotContain(filteredByRootThumbprint.Endpoints, endpoint => string.Equals(endpoint.Host, "root-thumbprint-missing.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByMissingRootThumbprint = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: null,
                chainSourceContains: null,
                thumbprintEquals: null,
                rootThumbprintEquals: "not-present");
            Assert.Empty(filteredByMissingRootThumbprint.Endpoints);

            var filteredByWhitespaceRootThumbprint = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: null,
                chainSourceContains: null,
                thumbprintEquals: null,
                rootThumbprintEquals: "   ");
            Assert.Equal(3, filteredByWhitespaceRootThumbprint.Endpoints.Count);
        }

        [Fact]
        public void BuildRiskFiltersReturnedEndpointsBySerialNumberEquals() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "serial-a.example.com",
                            ResolvedHost = "serial-a.example.com",
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
                            CertificateSerialNumber = "00AA11BB22CC33DD44EE55FF66778899",
                            WeakKey = true
                        },
                        new() {
                            Host = "serial-b.example.com",
                            ResolvedHost = "serial-b.example.com",
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
                            CertificateSerialNumber = "11223344556677889900AABBCCDDEEFF",
                            WeakKey = true
                        },
                        new() {
                            Host = "serial-missing.example.com",
                            ResolvedHost = "serial-missing.example.com",
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
                            WeakKey = true
                        }
                    }
                }
            };

            var filteredBySerialNumber = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: null,
                chainSourceContains: null,
                thumbprintEquals: null,
                serialNumberEquals: "00aa:11bb 22cc33dd44ee55ff66778899");
            Assert.Single(filteredBySerialNumber.Endpoints);
            Assert.Equal("serial-a.example.com", filteredBySerialNumber.Endpoints[0].Host);
            Assert.Equal("00AA11BB22CC33DD44EE55FF66778899", filteredBySerialNumber.Endpoints[0].CertificateSerialNumber);
            Assert.DoesNotContain(filteredBySerialNumber.Endpoints, endpoint => string.Equals(endpoint.Host, "serial-missing.example.com", StringComparison.OrdinalIgnoreCase));

            var filteredByMissingSerialNumber = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: null,
                chainSourceContains: null,
                thumbprintEquals: null,
                serialNumberEquals: "not-present");
            Assert.Empty(filteredByMissingSerialNumber.Endpoints);

            var filteredByWhitespaceSerialNumber = CertificateInventoryRiskAnalyzer.BuildRisk(
                snapshots,
                includeNoRisk: false,
                expiringWithinDays: 30,
                criticalExpiringWithinDays: 7,
                maxEndpoints: 100,
                minimumSeverity: null,
                reasonContains: null,
                issuerContains: null,
                authorityFamilyEquals: null,
                rootAuthorityFamilyEquals: null,
                ctSourceContains: null,
                ctTemplateErrorContains: null,
                chainSourceContains: null,
                thumbprintEquals: null,
                serialNumberEquals: "   ");
            Assert.Equal(3, filteredByWhitespaceSerialNumber.Endpoints.Count);
        }
    }
}
