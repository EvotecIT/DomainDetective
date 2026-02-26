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
            Assert.Empty(risk.Endpoints[0].Reasons);
        }
    }
}
