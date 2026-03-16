using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using DomainDetective.Helpers;

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
                    Assert.Equal(CertificateAuthenticationProfileClassifier.ServerAuthOnly, entry.AuthenticationProfile);
                    Assert.Contains(CertificateExtendedKeyUsageAnalyzer.ServerAuthenticationOid, entry.ExtendedKeyUsageOids);
                    Assert.Contains("override", entry.CtDiscoverySources);
                    Assert.Empty(entry.CtTemplateFormatErrors);
                    Assert.Equal("HTTPS", entry.Service);
                    Assert.Equal(443, entry.Port);
                    Assert.Equal("https", entry.Scheme);
                    Assert.True(!string.IsNullOrWhiteSpace(entry.CertificateIssuerNormalized));
                    Assert.True(!string.IsNullOrWhiteSpace(entry.CertificateThumbprint));
                    Assert.True(!string.IsNullOrWhiteSpace(entry.CertificateSerialNumber));
                    Assert.True(!string.IsNullOrWhiteSpace(entry.CertificateRootSubject));
                    Assert.True(!string.IsNullOrWhiteSpace(entry.CertificateRootIssuer));
                    Assert.True(!string.IsNullOrWhiteSpace(entry.CertificateRootThumbprint));
                    Assert.True(!string.IsNullOrWhiteSpace(entry.CertificateRootIssuerNormalized));
                    Assert.False(string.IsNullOrWhiteSpace(entry.CertificateChainSource));
                    Assert.NotEmpty(entry.CertificateChainSources);
                    Assert.True(entry.CertificateChainLength >= 1);
                    Assert.True(entry.CertificateChainSubjects.Count >= 1);
                    Assert.True(entry.CertificateChainIssuers.Count >= 1);
                    Assert.True(entry.CertificateChainThumbprints.Count >= 1);
                });
            } finally {
                if (Directory.Exists(tempDir)) {
                    Directory.Delete(tempDir, true);
                }
            }
        }

        [Fact]
        public async Task AnalyzePersistsCtTemplateFormatErrorsInInventorySnapshot() {
            var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try {
                using var cert = CreateSelfSignedWithEku(CertificateExtendedKeyUsageAnalyzer.ServerAuthenticationOid);
                var monitor = new CertificateMonitor {
                    CacheDirectory = tempDir,
                    PersistInventorySnapshots = true,
                    AnalysisOverride = async (host, port, logger, cancellationToken) => {
                        var analysis = new CertificateAnalysis {
                            SkipRevocation = true,
                            EnableCensysCtSource = true,
                            CensysApiId = "id",
                            CensysApiSecret = "secret",
                            CensysCtApiUrlTemplate = string.Empty
                        };
                        analysis.CtLogApiTemplates.Clear();
                        await analysis.AnalyzeCertificate(cert, cancellationToken);
                        analysis.Url = host;
                        analysis.IsReachable = true;
                        return analysis;
                    }
                };

                await monitor.Analyze(new[] { "https://template-errors.example.test" }, 443, showProgress: false);
                var snapshots = monitor.LoadInventorySnapshots();

                Assert.Single(snapshots);
                Assert.Single(snapshots[0].Entries);
                var entry = snapshots[0].Entries[0];
                Assert.Contains(entry.CtTemplateFormatErrors, error =>
                    error.IndexOf("CensysApiUrlTemplate", StringComparison.OrdinalIgnoreCase) >= 0);
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
        public async Task ToInventoryEntry_TreatsLiveCertificateEvidenceAsReachable() {
            using var cert = CreateSelfSignedWithEku(CertificateExtendedKeyUsageAnalyzer.ServerAuthenticationOid);
            var analysis = new CertificateAnalysis {
                CtLogQueryOverride = _ => Task.FromResult("[]")
            };
            await analysis.AnalyzeCertificate(cert);
            analysis.Url = "https://edge.example.test/";
            analysis.IsReachable = false;
            typeof(CertificateAnalysis)
                .GetProperty("FailureReason", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic)!
                .SetValue(analysis, "The request was canceled due to timeout.");

            var entry = new CertificateMonitor.Entry {
                Host = "edge.example.test",
                Url = "https://edge.example.test/",
                ResolvedHost = "edge.example.test",
                Scheme = "https",
                Port = 443,
                Service = "HTTPS",
                ExpiryDate = cert.NotAfter,
                Valid = true,
                Expired = false,
                ChainComplete = false,
                Analysis = analysis
            };

            var snapshotEntry = CertificateMonitor.ToInventoryEntry(entry);

            Assert.True(snapshotEntry.IsReachable);
            Assert.Null(snapshotEntry.FailureReason);
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
        public async Task BuildInventoryRiskReadsPersistedSnapshots() {
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
                var risk = monitor.BuildInventoryRisk(includeNoRisk: true);

                Assert.Equal(1, risk.SnapshotCount);
                Assert.Equal(1, risk.EndpointCount);
                Assert.Single(risk.Endpoints);
            } finally {
                if (Directory.Exists(tempDir)) {
                    Directory.Delete(tempDir, true);
                }
            }
        }

        [Fact]
        public async Task BuildInventoryReuseReadsPersistedSnapshots() {
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

                await monitor.Analyze(new[] { "https://api.example.test:8443", "https://portal.example.test:8443" }, 443, showProgress: false);
                var reuse = monitor.BuildInventoryReuse(
                    includeSingleEndpointCertificates: true,
                    minEndpointCount: 1);

                Assert.Equal(1, reuse.SnapshotCount);
                Assert.Equal(2, reuse.EndpointCount);
                Assert.Single(reuse.Certificates);
                Assert.Equal(2, reuse.Certificates[0].EndpointCount);
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

        [Fact]
        public void LoadInventorySnapshots_AppliesUntilUtcAndMaxSnapshots() {
            var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try {
                var now = DateTimeOffset.UtcNow;
                WriteInventorySnapshot(tempDir, new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddDays(-3),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry>()
                });
                WriteInventorySnapshot(tempDir, new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddDays(-2),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry>()
                });
                WriteInventorySnapshot(tempDir, new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddDays(-1),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry>()
                });

                var monitor = new CertificateMonitor {
                    CacheDirectory = tempDir,
                    PersistInventorySnapshots = false
                };
                var snapshots = monitor.LoadInventorySnapshots(
                    sinceUtc: now.AddDays(-10),
                    untilUtc: now.AddDays(-1.5),
                    maxSnapshots: 1,
                    latestOnly: false);

                Assert.Single(snapshots);
                Assert.Equal(now.AddDays(-2).UtcDateTime.Date, snapshots[0].CapturedAtUtc.UtcDateTime.Date);
            } finally {
                if (Directory.Exists(tempDir)) {
                    Directory.Delete(tempDir, true);
                }
            }
        }

        [Fact]
        public void LoadInventorySnapshots_ReturnsLatestWhenRequested() {
            var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try {
                var now = DateTimeOffset.UtcNow;
                WriteInventorySnapshot(tempDir, new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddDays(-4),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry>()
                });
                WriteInventorySnapshot(tempDir, new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddDays(-2),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry>()
                });
                WriteInventorySnapshot(tempDir, new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-8),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry>()
                });

                var monitor = new CertificateMonitor {
                    CacheDirectory = tempDir,
                    PersistInventorySnapshots = false
                };
                var snapshots = monitor.LoadInventorySnapshots(
                    sinceUtc: now.AddDays(-3),
                    untilUtc: null,
                    maxSnapshots: 0,
                    latestOnly: true);

                Assert.Single(snapshots);
                Assert.Equal(now.AddHours(-8).UtcDateTime.Date, snapshots[0].CapturedAtUtc.UtcDateTime.Date);
            } finally {
                if (Directory.Exists(tempDir)) {
                    Directory.Delete(tempDir, true);
                }
            }
        }

        [Fact]
        public void BuildInventoryPolicyDriftAddsSinceUtcWarningsWhenRequestedSelectorsAreExcluded() {
            var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try {
                var now = DateTimeOffset.UtcNow;
                var historicalSnapshot = new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddDays(-10),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        BuildHealthyEntry(now, "api.example.test", "AA11223344556677889900AABBCCDDEEFF001122")
                    }
                };
                var latestSnapshot = new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddDays(-1),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        BuildHealthyEntry(now, "api.example.test", "AA11223344556677889900AABBCCDDEEFF001122")
                    }
                };
                WriteInventorySnapshot(tempDir, historicalSnapshot);
                WriteInventorySnapshot(tempDir, latestSnapshot);

                var monitor = new CertificateMonitor {
                    CacheDirectory = tempDir,
                    PersistInventorySnapshots = false
                };
                var sinceUtc = now.AddDays(-2);
                var requestedPrevious = now.AddDays(-5);
                var requestedCurrent = now.AddDays(-5);

                var drift = monitor.BuildInventoryPolicyDrift(
                    sinceUtc: sinceUtc,
                    baselineProfile: "Balanced",
                    previousCapturedAtUtc: requestedPrevious,
                    currentCapturedAtUtc: requestedCurrent,
                    changedOnly: false,
                    maxEndpoints: 100);

                Assert.Contains(drift.Warnings, warning =>
                    warning.Contains("Requested previous snapshot", StringComparison.OrdinalIgnoreCase) &&
                    warning.Contains("--since-utc", StringComparison.OrdinalIgnoreCase));
                Assert.Contains(drift.Warnings, warning =>
                    warning.Contains("Requested current snapshot", StringComparison.OrdinalIgnoreCase) &&
                    warning.Contains("--since-utc", StringComparison.OrdinalIgnoreCase));
                Assert.DoesNotContain(drift.Warnings, warning =>
                    warning.Contains("was not found", StringComparison.OrdinalIgnoreCase));
            } finally {
                if (Directory.Exists(tempDir)) {
                    Directory.Delete(tempDir, true);
                }
            }
        }

        [Fact]
        public void BuildInventoryPolicyDriftAddsSinceUtcWarningWhenOnlyPreviousSelectorIsExcluded() {
            var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try {
                var now = DateTimeOffset.UtcNow;
                WriteInventorySnapshot(tempDir, new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddDays(-10),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        BuildHealthyEntry(now, "api.example.test", "AA11223344556677889900AABBCCDDEEFF001123")
                    }
                });
                WriteInventorySnapshot(tempDir, new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddDays(-1.5),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        BuildHealthyEntry(now, "api.example.test", "AA11223344556677889900AABBCCDDEEFF001123")
                    }
                });
                WriteInventorySnapshot(tempDir, new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddDays(-1),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        BuildHealthyEntry(now, "api.example.test", "AA11223344556677889900AABBCCDDEEFF001123")
                    }
                });

                var monitor = new CertificateMonitor {
                    CacheDirectory = tempDir,
                    PersistInventorySnapshots = false
                };

                var drift = monitor.BuildInventoryPolicyDrift(
                    sinceUtc: now.AddDays(-2),
                    baselineProfile: "Balanced",
                    previousCapturedAtUtc: now.AddDays(-5),
                    currentCapturedAtUtc: now.AddDays(-1),
                    changedOnly: false,
                    maxEndpoints: 100);

                Assert.Contains(drift.Warnings, warning =>
                    warning.Contains("Requested previous snapshot", StringComparison.OrdinalIgnoreCase) &&
                    warning.Contains("--since-utc", StringComparison.OrdinalIgnoreCase));
                Assert.DoesNotContain(drift.Warnings, warning =>
                    warning.Contains("Requested current snapshot", StringComparison.OrdinalIgnoreCase) &&
                    warning.Contains("--since-utc", StringComparison.OrdinalIgnoreCase));
            } finally {
                if (Directory.Exists(tempDir)) {
                    Directory.Delete(tempDir, true);
                }
            }
        }

        [Fact]
        public void BuildInventoryPolicyDriftAddsSinceUtcWarningWhenOnlyCurrentSelectorIsExcluded() {
            var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try {
                var now = DateTimeOffset.UtcNow;
                WriteInventorySnapshot(tempDir, new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddDays(-10),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        BuildHealthyEntry(now, "api.example.test", "AA11223344556677889900AABBCCDDEEFF001124")
                    }
                });
                WriteInventorySnapshot(tempDir, new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddDays(-1.5),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        BuildHealthyEntry(now, "api.example.test", "AA11223344556677889900AABBCCDDEEFF001124")
                    }
                });
                WriteInventorySnapshot(tempDir, new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddDays(-1),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        BuildHealthyEntry(now, "api.example.test", "AA11223344556677889900AABBCCDDEEFF001124")
                    }
                });

                var monitor = new CertificateMonitor {
                    CacheDirectory = tempDir,
                    PersistInventorySnapshots = false
                };

                var drift = monitor.BuildInventoryPolicyDrift(
                    sinceUtc: now.AddDays(-2),
                    baselineProfile: "Balanced",
                    previousCapturedAtUtc: now.AddDays(-1.5),
                    currentCapturedAtUtc: now.AddDays(-5),
                    changedOnly: false,
                    maxEndpoints: 100);

                Assert.Contains(drift.Warnings, warning =>
                    warning.Contains("Requested current snapshot", StringComparison.OrdinalIgnoreCase) &&
                    warning.Contains("--since-utc", StringComparison.OrdinalIgnoreCase));
                Assert.DoesNotContain(drift.Warnings, warning =>
                    warning.Contains("Requested previous snapshot", StringComparison.OrdinalIgnoreCase) &&
                    warning.Contains("--since-utc", StringComparison.OrdinalIgnoreCase));
            } finally {
                if (Directory.Exists(tempDir)) {
                    Directory.Delete(tempDir, true);
                }
            }
        }

        [Fact]
        public void BuildInventoryPolicyDriftDoesNotAddSinceUtcWarningsWhenSelectorsAreWithinRange() {
            var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try {
                var now = DateTimeOffset.UtcNow;
                var snapshot1 = new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddDays(-3),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        BuildHealthyEntry(now, "api.example.test", "AA11223344556677889900AABBCCDDEEFF001125")
                    }
                };
                var snapshot2 = new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddDays(-1),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        BuildHealthyEntry(now, "api.example.test", "AA11223344556677889900AABBCCDDEEFF001125")
                    }
                };
                WriteInventorySnapshot(tempDir, snapshot1);
                WriteInventorySnapshot(tempDir, snapshot2);

                var monitor = new CertificateMonitor {
                    CacheDirectory = tempDir,
                    PersistInventorySnapshots = false
                };

                var drift = monitor.BuildInventoryPolicyDrift(
                    sinceUtc: now.AddDays(-4),
                    baselineProfile: "Balanced",
                    previousCapturedAtUtc: snapshot1.CapturedAtUtc,
                    currentCapturedAtUtc: snapshot2.CapturedAtUtc,
                    changedOnly: false,
                    maxEndpoints: 100);

                Assert.DoesNotContain(drift.Warnings, warning =>
                    warning.Contains("--since-utc", StringComparison.OrdinalIgnoreCase));
            } finally {
                if (Directory.Exists(tempDir)) {
                    Directory.Delete(tempDir, true);
                }
            }
        }

        [Fact]
        public void BuildInventoryDiffAddsSinceUtcWarningsWhenRequestedSelectorsAreExcluded() {
            var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try {
                var now = DateTimeOffset.UtcNow;
                WriteInventorySnapshot(tempDir, new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddDays(-10),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        BuildHealthyEntry(now, "diff.example.test", "BB11223344556677889900AABBCCDDEEFF001122")
                    }
                });
                WriteInventorySnapshot(tempDir, new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddDays(-1),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        BuildHealthyEntry(now, "diff.example.test", "BB11223344556677889900AABBCCDDEEFF001123")
                    }
                });

                var monitor = new CertificateMonitor {
                    CacheDirectory = tempDir,
                    PersistInventorySnapshots = false
                };
                var requestedSelector = now.AddDays(-5);

                var diff = monitor.BuildInventoryDiff(
                    sinceUtc: now.AddDays(-2),
                    previousCapturedAtUtc: requestedSelector,
                    currentCapturedAtUtc: requestedSelector,
                    includeUnchanged: false,
                    maxEndpoints: 100);

                Assert.Contains(diff.Warnings, warning =>
                    warning.Contains("Requested previous snapshot", StringComparison.OrdinalIgnoreCase) &&
                    warning.Contains("--since-utc", StringComparison.OrdinalIgnoreCase));
                Assert.Contains(diff.Warnings, warning =>
                    warning.Contains("Requested current snapshot", StringComparison.OrdinalIgnoreCase) &&
                    warning.Contains("--since-utc", StringComparison.OrdinalIgnoreCase));
                Assert.DoesNotContain(diff.Warnings, warning =>
                    warning.Contains("was not found", StringComparison.OrdinalIgnoreCase));
            } finally {
                if (Directory.Exists(tempDir)) {
                    Directory.Delete(tempDir, true);
                }
            }
        }

        [Fact]
        public void BuildInventoryDiffDoesNotAddSinceUtcWarningsWhenSelectorsAreWithinRange() {
            var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try {
                var now = DateTimeOffset.UtcNow;
                var snapshot1 = new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddDays(-3),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        BuildHealthyEntry(now, "diff.example.test", "BB11223344556677889900AABBCCDDEEFF001124")
                    }
                };
                var snapshot2 = new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddDays(-1),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        BuildHealthyEntry(now, "diff.example.test", "BB11223344556677889900AABBCCDDEEFF001125")
                    }
                };
                WriteInventorySnapshot(tempDir, snapshot1);
                WriteInventorySnapshot(tempDir, snapshot2);

                var monitor = new CertificateMonitor {
                    CacheDirectory = tempDir,
                    PersistInventorySnapshots = false
                };

                var diff = monitor.BuildInventoryDiff(
                    sinceUtc: now.AddDays(-4),
                    previousCapturedAtUtc: snapshot1.CapturedAtUtc,
                    currentCapturedAtUtc: snapshot2.CapturedAtUtc,
                    includeUnchanged: false,
                    maxEndpoints: 100);

                Assert.DoesNotContain(diff.Warnings, warning =>
                    warning.Contains("--since-utc", StringComparison.OrdinalIgnoreCase));
            } finally {
                if (Directory.Exists(tempDir)) {
                    Directory.Delete(tempDir, true);
                }
            }
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

        private static void WriteInventorySnapshot(string cacheDirectory, CertificateInventorySnapshot snapshot) {
            var inventoryDirectory = Path.Combine(cacheDirectory, "inventory");
            Directory.CreateDirectory(inventoryDirectory);
            var fileName = string.Format(
                "{0:yyyyMMddTHHmmssfffffffZ}_{1}.json",
                snapshot.CapturedAtUtc.UtcDateTime,
                snapshot.Port);
            var filePath = Path.Combine(inventoryDirectory, fileName);
            var json = JsonSerializer.Serialize(snapshot, JsonOptions.Default);
            File.WriteAllText(filePath, json, Encoding.UTF8);
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
