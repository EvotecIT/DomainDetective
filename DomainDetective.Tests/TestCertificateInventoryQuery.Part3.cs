using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;

namespace DomainDetective.Tests {
    public partial class TestCertificateInventoryQuery {
        [Fact]
        public void QueryInventoryEntriesLatestPerEndpointOnlyWorksWithUntilUtcWindow() {
            var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            var inventoryDir = Path.Combine(tempDir, "inventory");
            Directory.CreateDirectory(inventoryDir);
            try {
                var now = DateTimeOffset.UtcNow;
                var newestSnapshot = new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddMinutes(-5),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "api.example.com",
                            ResolvedHost = "api.example.com",
                            Service = "HTTPS",
                            Port = 443,
                            CertificateIssuerNormalized = "Newest CA",
                            SubjectAlternativeNames = new List<string> { "api.example.com" },
                            NotAfterUtc = now.AddDays(30),
                            Valid = true,
                            ChainComplete = true,
                            HostnameMatch = true,
                            IsReachable = true,
                            AllowsServerAuthentication = true,
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly
                        }
                    }
                };
                var middleSnapshot = new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddMinutes(-20),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "api.example.com",
                            ResolvedHost = "api.example.com",
                            Service = "HTTPS",
                            Port = 443,
                            CertificateIssuerNormalized = "Middle CA",
                            SubjectAlternativeNames = new List<string> { "api.example.com" },
                            NotAfterUtc = now.AddDays(20),
                            Valid = true,
                            ChainComplete = true,
                            HostnameMatch = true,
                            IsReachable = true,
                            AllowsServerAuthentication = true,
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly
                        }
                    }
                };
                var oldestSnapshot = new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddMinutes(-40),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "api.example.com",
                            ResolvedHost = "api.example.com",
                            Service = "HTTPS",
                            Port = 443,
                            CertificateIssuerNormalized = "Oldest CA",
                            SubjectAlternativeNames = new List<string> { "api.example.com" },
                            NotAfterUtc = now.AddDays(10),
                            Valid = true,
                            ChainComplete = true,
                            HostnameMatch = true,
                            IsReachable = true,
                            AllowsServerAuthentication = true,
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly
                        }
                    }
                };

                var newestFile = Path.Combine(inventoryDir, $"{newestSnapshot.CapturedAtUtc:yyyyMMddTHHmmssfffffffZ}_443.json");
                File.WriteAllText(newestFile, JsonSerializer.Serialize(newestSnapshot, JsonOptions.Default), Encoding.UTF8);
                var middleFile = Path.Combine(inventoryDir, $"{middleSnapshot.CapturedAtUtc:yyyyMMddTHHmmssfffffffZ}_443.json");
                File.WriteAllText(middleFile, JsonSerializer.Serialize(middleSnapshot, JsonOptions.Default), Encoding.UTF8);
                var oldestFile = Path.Combine(inventoryDir, $"{oldestSnapshot.CapturedAtUtc:yyyyMMddTHHmmssfffffffZ}_443.json");
                File.WriteAllText(oldestFile, JsonSerializer.Serialize(oldestSnapshot, JsonOptions.Default), Encoding.UTF8);

                var monitor = new CertificateMonitor {
                    CacheDirectory = tempDir
                };

                var latestWithUntil = monitor.QueryInventoryEntries(new CertificateInventoryQuery {
                    HostContains = "api.example.com",
                    LatestPerEndpointOnly = true,
                    UntilUtc = now.AddMinutes(-10),
                    MaxResults = 10
                });

                Assert.Equal(3, latestWithUntil.LoadedSnapshotCount);
                Assert.Equal(2, latestWithUntil.ScannedSnapshotCount);
                Assert.Equal(1, latestWithUntil.SkippedSnapshotCountByUntilUtc);
                Assert.Equal(2, latestWithUntil.ScannedEntryCount);
                Assert.Equal(1, latestWithUntil.SkippedByLatestPerEndpointCount);
                Assert.Equal(1, latestWithUntil.EvaluatedEntryCount);
                Assert.Equal(0, latestWithUntil.ExcludedByFiltersCount);
                Assert.Equal(1, latestWithUntil.MatchedEntryCount);
                Assert.Equal(1, latestWithUntil.MatchedUniqueEndpointCount);
                Assert.Equal(0, latestWithUntil.EntriesTruncatedByMaxResults);
                Assert.Equal(latestWithUntil.LoadedSnapshotCount, latestWithUntil.ScannedSnapshotCount + latestWithUntil.SkippedSnapshotCountByUntilUtc);
                Assert.Equal(latestWithUntil.ScannedEntryCount, latestWithUntil.SkippedByLatestPerEndpointCount + latestWithUntil.EvaluatedEntryCount);
                Assert.Equal(latestWithUntil.EvaluatedEntryCount, latestWithUntil.MatchedEntryCount + latestWithUntil.ExcludedByFiltersCount);
                var entry = Assert.Single(latestWithUntil.Entries);
                Assert.Equal("Middle CA", entry.Entry.CertificateIssuerNormalized);
            } finally {
                if (Directory.Exists(tempDir)) {
                    Directory.Delete(tempDir, true);
                }
            }
        }

        [Fact]
        public void QueryInventoryEntriesLatestPerEndpointOnlyTracksMultipleSkippedOlderEntries() {
            var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            var inventoryDir = Path.Combine(tempDir, "inventory");
            Directory.CreateDirectory(inventoryDir);
            try {
                var now = DateTimeOffset.UtcNow;
                var newestSnapshot = new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddMinutes(-5),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "api.example.com",
                            ResolvedHost = "api.example.com",
                            Service = "HTTPS",
                            Port = 443,
                            CertificateIssuerNormalized = "Newest CA",
                            SubjectAlternativeNames = new List<string> { "api.example.com" },
                            NotAfterUtc = now.AddDays(30),
                            Valid = true,
                            ChainComplete = true,
                            HostnameMatch = true,
                            IsReachable = true,
                            AllowsServerAuthentication = true,
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly
                        }
                    }
                };
                var middleSnapshot = new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddMinutes(-20),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "api.example.com",
                            ResolvedHost = "api.example.com",
                            Service = "HTTPS",
                            Port = 443,
                            CertificateIssuerNormalized = "Middle CA",
                            SubjectAlternativeNames = new List<string> { "api.example.com" },
                            NotAfterUtc = now.AddDays(20),
                            Valid = true,
                            ChainComplete = true,
                            HostnameMatch = true,
                            IsReachable = true,
                            AllowsServerAuthentication = true,
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly
                        }
                    }
                };
                var oldestSnapshot = new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddMinutes(-40),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "api.example.com",
                            ResolvedHost = "api.example.com",
                            Service = "HTTPS",
                            Port = 443,
                            CertificateIssuerNormalized = "Oldest CA",
                            SubjectAlternativeNames = new List<string> { "api.example.com" },
                            NotAfterUtc = now.AddDays(10),
                            Valid = true,
                            ChainComplete = true,
                            HostnameMatch = true,
                            IsReachable = true,
                            AllowsServerAuthentication = true,
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly
                        }
                    }
                };

                var newestFile = Path.Combine(inventoryDir, $"{newestSnapshot.CapturedAtUtc:yyyyMMddTHHmmssfffffffZ}_443.json");
                File.WriteAllText(newestFile, JsonSerializer.Serialize(newestSnapshot, JsonOptions.Default), Encoding.UTF8);
                var middleFile = Path.Combine(inventoryDir, $"{middleSnapshot.CapturedAtUtc:yyyyMMddTHHmmssfffffffZ}_443.json");
                File.WriteAllText(middleFile, JsonSerializer.Serialize(middleSnapshot, JsonOptions.Default), Encoding.UTF8);
                var oldestFile = Path.Combine(inventoryDir, $"{oldestSnapshot.CapturedAtUtc:yyyyMMddTHHmmssfffffffZ}_443.json");
                File.WriteAllText(oldestFile, JsonSerializer.Serialize(oldestSnapshot, JsonOptions.Default), Encoding.UTF8);

                var monitor = new CertificateMonitor {
                    CacheDirectory = tempDir
                };

                var latestOnly = monitor.QueryInventoryEntries(new CertificateInventoryQuery {
                    HostContains = "api.example.com",
                    LatestPerEndpointOnly = true,
                    MaxResults = 10
                });

                Assert.Equal(3, latestOnly.LoadedSnapshotCount);
                Assert.Equal(3, latestOnly.ScannedSnapshotCount);
                Assert.Equal(0, latestOnly.SkippedSnapshotCountByUntilUtc);
                Assert.Equal(3, latestOnly.ScannedEntryCount);
                Assert.Equal(1, latestOnly.MatchedEntryCount);
                Assert.Equal(1, latestOnly.MatchedUniqueEndpointCount);
                Assert.Equal(2, latestOnly.SkippedByLatestPerEndpointCount);
                Assert.Equal(1, latestOnly.EvaluatedEntryCount);
                Assert.Equal(0, latestOnly.ExcludedByFiltersCount);
                Assert.Equal(0, latestOnly.EntriesTruncatedByMaxResults);
                Assert.Equal(latestOnly.LoadedSnapshotCount, latestOnly.ScannedSnapshotCount + latestOnly.SkippedSnapshotCountByUntilUtc);
                Assert.Equal(latestOnly.ScannedEntryCount, latestOnly.SkippedByLatestPerEndpointCount + latestOnly.EvaluatedEntryCount);
                Assert.Equal(latestOnly.EvaluatedEntryCount, latestOnly.MatchedEntryCount + latestOnly.ExcludedByFiltersCount);
                Assert.Single(latestOnly.Entries);
                Assert.Equal("Newest CA", latestOnly.Entries[0].Entry.CertificateIssuerNormalized);
            } finally {
                if (Directory.Exists(tempDir)) {
                    Directory.Delete(tempDir, true);
                }
            }
        }
    }
}
