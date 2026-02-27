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
    }
}
