using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestCertificateMonitorInventory {
        [Fact]
        public async Task AnalyzePersistsInventorySnapshot() {
            var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try {
                using var cert = CreateSelfSignedWithEku(CertificateExtendedKeyUsageAnalyzer.ServerAuthenticationOid);
                var monitor = new CertificateMonitor {
                    CacheDirectory = tempDir,
                    PersistInventorySnapshots = true,
                    AnalysisOverride = async (host, port, logger, cancellationToken) => {
                        var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[]") };
                        await analysis.AnalyzeCertificate(cert, cancellationToken);
                        analysis.Url = host;
                        analysis.IsReachable = true;
                        return analysis;
                    }
                };

                await monitor.Analyze(new[] { "https://api.example.test", "https://portal.example.test" }, 443, showProgress: false);
                var snapshots = monitor.LoadInventorySnapshots();

                Assert.Single(snapshots);
                var snapshot = snapshots[0];
                Assert.Equal(443, snapshot.Port);
                Assert.Equal(2, snapshot.Entries.Count);
                Assert.All(snapshot.Entries, entry => {
                    Assert.True(entry.HasEnhancedKeyUsageExtension);
                    Assert.True(entry.AllowsServerAuthentication);
                    Assert.Contains(CertificateExtendedKeyUsageAnalyzer.ServerAuthenticationOid, entry.ExtendedKeyUsageOids);
                    Assert.Equal("HTTPS", entry.Service);
                    Assert.Equal(443, entry.Port);
                    Assert.Equal("https", entry.Scheme);
                    Assert.True(!string.IsNullOrWhiteSpace(entry.CertificateIssuerNormalized));
                    Assert.True(!string.IsNullOrWhiteSpace(entry.CertificateThumbprint));
                    Assert.True(!string.IsNullOrWhiteSpace(entry.CertificateSerialNumber));
                });
            } finally {
                if (Directory.Exists(tempDir)) {
                    Directory.Delete(tempDir, true);
                }
            }
        }

        [Fact]
        public async Task AnalyzeSkipsPersistenceWhenDisabled() {
            var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try {
                using var cert = CreateSelfSignedWithEku(CertificateExtendedKeyUsageAnalyzer.ClientAuthenticationOid);
                var monitor = new CertificateMonitor {
                    CacheDirectory = tempDir,
                    PersistInventorySnapshots = false,
                    AnalysisOverride = async (host, port, logger, cancellationToken) => {
                        var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[]") };
                        await analysis.AnalyzeCertificate(cert, cancellationToken);
                        analysis.Url = host;
                        analysis.IsReachable = true;
                        return analysis;
                    }
                };

                await monitor.Analyze(new[] { "https://client.example.test" }, 443, showProgress: false);
                var snapshots = monitor.LoadInventorySnapshots();
                Assert.Empty(snapshots);
            } finally {
                if (Directory.Exists(tempDir)) {
                    Directory.Delete(tempDir, true);
                }
            }
        }

        [Fact]
        public async Task BuildInventorySummaryReadsPersistedSnapshots() {
            var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try {
                using var cert = CreateSelfSignedWithEku(CertificateExtendedKeyUsageAnalyzer.ServerAuthenticationOid);
                var monitor = new CertificateMonitor {
                    CacheDirectory = tempDir,
                    PersistInventorySnapshots = true,
                    AnalysisOverride = async (host, port, logger, cancellationToken) => {
                        var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[]") };
                        await analysis.AnalyzeCertificate(cert, cancellationToken);
                        analysis.Url = host;
                        analysis.IsReachable = true;
                        return analysis;
                    }
                };

                await monitor.Analyze(new[] { "https://api.example.test:8443" }, 443, showProgress: false);
                var summary = monitor.BuildInventorySummary();

                Assert.Equal(1, summary.SnapshotCount);
                Assert.Equal(1, summary.UniqueEndpointCount);
                Assert.Equal(1, summary.ServiceCounts["HTTPS-Alt"]);
            } finally {
                if (Directory.Exists(tempDir)) {
                    Directory.Delete(tempDir, true);
                }
            }
        }

        [Fact]
        public async Task AnalyzeUsesPortFromInputUrlWhenSpecified() {
            var capturedPorts = new ConcurrentBag<int>();
            var capturedUrls = new ConcurrentBag<string>();
            var monitor = new CertificateMonitor {
                PersistInventorySnapshots = false,
                AnalysisOverride = (host, port, logger, cancellationToken) => {
                    capturedPorts.Add(port);
                    capturedUrls.Add(host);
                    return Task.FromResult(new CertificateAnalysis {
                        Url = host,
                        IsReachable = true
                    });
                }
            };

            await monitor.Analyze(new[] { "api.example.test:8443", "https://portal.example.test" }, 443, showProgress: false);

            Assert.Contains(8443, capturedPorts);
            Assert.Contains(443, capturedPorts);
            Assert.Contains("https://api.example.test:8443/", capturedUrls);
            Assert.Contains("https://portal.example.test/", capturedUrls);
        }

        private static X509Certificate2 CreateSelfSignedWithEku(string oidValue) {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=monitor.test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var oids = new OidCollection {
                new Oid(oidValue)
            };
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(oids, false));
            var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
            return new X509Certificate2(cert.Export(X509ContentType.Cert));
        }
    }
}
