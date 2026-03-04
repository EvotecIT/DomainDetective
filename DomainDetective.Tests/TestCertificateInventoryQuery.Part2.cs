using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;

namespace DomainDetective.Tests {
    public partial class TestCertificateInventoryQuery {
        [Fact]
        public void QueryInventoryEntriesLatestPerEndpointOnlyUsesNewestObservation() {
            var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            var inventoryDir = Path.Combine(tempDir, "inventory");
            Directory.CreateDirectory(inventoryDir);
            try {
                var now = DateTimeOffset.UtcNow;
                var latestSnapshot = new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddMinutes(-5),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "api.example.com",
                            ResolvedHost = "api.example.com",
                            Service = "HTTPS",
                            Port = 443,
                            CertificateIssuerNormalized = "New CA",
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
                var olderSnapshot = new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddMinutes(-30),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "api.example.com",
                            ResolvedHost = "api.example.com",
                            Service = "HTTPS",
                            Port = 443,
                            CertificateIssuerNormalized = "Old CA",
                            SubjectAlternativeNames = new List<string> { "api.example.com" },
                            NotAfterUtc = now.AddDays(10),
                            Valid = true,
                            ChainComplete = true,
                            HostnameMatch = true,
                            IsReachable = true,
                            AllowsServerAuthentication = true,
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly
                        },
                        new() {
                            Host = "legacy.example.com",
                            ResolvedHost = "legacy.example.com",
                            Service = "HTTPS",
                            Port = 443,
                            CertificateIssuerNormalized = "Legacy CA",
                            SubjectAlternativeNames = new List<string> { "legacy.example.com" },
                            NotAfterUtc = now.AddDays(5),
                            Valid = true,
                            ChainComplete = true,
                            HostnameMatch = true,
                            IsReachable = true,
                            AllowsServerAuthentication = true,
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly
                        }
                    }
                };

                var latestFile = Path.Combine(inventoryDir, $"{latestSnapshot.CapturedAtUtc:yyyyMMddTHHmmssfffffffZ}_443.json");
                File.WriteAllText(latestFile, JsonSerializer.Serialize(latestSnapshot, JsonOptions.Default), Encoding.UTF8);
                var olderFile = Path.Combine(inventoryDir, $"{olderSnapshot.CapturedAtUtc:yyyyMMddTHHmmssfffffffZ}_443.json");
                File.WriteAllText(olderFile, JsonSerializer.Serialize(olderSnapshot, JsonOptions.Default), Encoding.UTF8);

                var monitor = new CertificateMonitor {
                    CacheDirectory = tempDir
                };

                var withoutLatestOnly = monitor.QueryInventoryEntries(new CertificateInventoryQuery {
                    IssuerContains = "old ca",
                    MaxResults = 10
                });
                Assert.Equal(2, withoutLatestOnly.LoadedSnapshotCount);
                Assert.Equal(2, withoutLatestOnly.ScannedSnapshotCount);
                Assert.Equal(0, withoutLatestOnly.SkippedSnapshotCountByUntilUtc);
                Assert.Equal(3, withoutLatestOnly.EvaluatedEntryCount);
                Assert.Equal(2, withoutLatestOnly.ExcludedByFiltersCount);
                Assert.Equal(1, withoutLatestOnly.MatchedEntryCount);
                Assert.Equal(0, withoutLatestOnly.EntriesTruncatedByMaxResults);
                Assert.Equal(withoutLatestOnly.LoadedSnapshotCount, withoutLatestOnly.ScannedSnapshotCount + withoutLatestOnly.SkippedSnapshotCountByUntilUtc);
                Assert.Equal(withoutLatestOnly.EvaluatedEntryCount, withoutLatestOnly.MatchedEntryCount + withoutLatestOnly.ExcludedByFiltersCount);
                Assert.Single(withoutLatestOnly.Entries);
                Assert.Equal("api.example.com", withoutLatestOnly.Entries[0].Entry.Host);

                var latestOnly = monitor.QueryInventoryEntries(new CertificateInventoryQuery {
                    HostContains = "example.com",
                    LatestPerEndpointOnly = true,
                    MaxResults = 10
                });
                Assert.Equal(2, latestOnly.LoadedSnapshotCount);
                Assert.Equal(2, latestOnly.ScannedSnapshotCount);
                Assert.Equal(0, latestOnly.SkippedSnapshotCountByUntilUtc);
                Assert.Equal(2, latestOnly.MatchedEntryCount);
                Assert.Equal(2, latestOnly.MatchedUniqueEndpointCount);
                Assert.Equal(1, latestOnly.SkippedByLatestPerEndpointCount);
                Assert.Equal(2, latestOnly.EvaluatedEntryCount);
                Assert.Equal(0, latestOnly.ExcludedByFiltersCount);
                Assert.Equal(0, latestOnly.EntriesTruncatedByMaxResults);
                Assert.Equal(latestOnly.LoadedSnapshotCount, latestOnly.ScannedSnapshotCount + latestOnly.SkippedSnapshotCountByUntilUtc);
                Assert.Equal(latestOnly.ScannedEntryCount, latestOnly.SkippedByLatestPerEndpointCount + latestOnly.EvaluatedEntryCount);
                Assert.Equal(latestOnly.EvaluatedEntryCount, latestOnly.MatchedEntryCount + latestOnly.ExcludedByFiltersCount);
                Assert.Equal(2, latestOnly.Entries.Count);
                Assert.Equal(1, latestOnly.MatchedIssuerCounts["New CA"]);
                Assert.Equal(1, latestOnly.MatchedIssuerCounts["Legacy CA"]);
                Assert.False(latestOnly.MatchedIssuerCounts.ContainsKey("Old CA"));

                var latestOnlyOldCa = monitor.QueryInventoryEntries(new CertificateInventoryQuery {
                    IssuerContains = "old ca",
                    LatestPerEndpointOnly = true,
                    MaxResults = 10
                });
                Assert.Equal(2, latestOnlyOldCa.LoadedSnapshotCount);
                Assert.Equal(2, latestOnlyOldCa.ScannedSnapshotCount);
                Assert.Equal(0, latestOnlyOldCa.SkippedSnapshotCountByUntilUtc);
                Assert.Equal(0, latestOnlyOldCa.MatchedEntryCount);
                Assert.Equal(1, latestOnlyOldCa.SkippedByLatestPerEndpointCount);
                Assert.Equal(2, latestOnlyOldCa.EvaluatedEntryCount);
                Assert.Equal(2, latestOnlyOldCa.ExcludedByFiltersCount);
                Assert.Equal(0, latestOnlyOldCa.EntriesTruncatedByMaxResults);
                Assert.Equal(latestOnlyOldCa.LoadedSnapshotCount, latestOnlyOldCa.ScannedSnapshotCount + latestOnlyOldCa.SkippedSnapshotCountByUntilUtc);
                Assert.Equal(latestOnlyOldCa.ScannedEntryCount, latestOnlyOldCa.SkippedByLatestPerEndpointCount + latestOnlyOldCa.EvaluatedEntryCount);
                Assert.Equal(latestOnlyOldCa.EvaluatedEntryCount, latestOnlyOldCa.MatchedEntryCount + latestOnlyOldCa.ExcludedByFiltersCount);
                Assert.Empty(latestOnlyOldCa.Entries);
            } finally {
                if (Directory.Exists(tempDir)) {
                    Directory.Delete(tempDir, true);
                }
            }
        }

        [Fact]
        public void QueryInventoryEntriesTracksSkippedSnapshotsByUntilUtc() {
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
                            Host = "newer.example.com",
                            ResolvedHost = "newer.example.com",
                            Service = "HTTPS",
                            Port = 443,
                            CertificateIssuerNormalized = "New CA",
                            SubjectAlternativeNames = new List<string> { "newer.example.com" },
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
                var olderSnapshot = new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddMinutes(-30),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "older.example.com",
                            ResolvedHost = "older.example.com",
                            Service = "HTTPS",
                            Port = 443,
                            CertificateIssuerNormalized = "Old CA",
                            SubjectAlternativeNames = new List<string> { "older.example.com" },
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
                var olderFile = Path.Combine(inventoryDir, $"{olderSnapshot.CapturedAtUtc:yyyyMMddTHHmmssfffffffZ}_443.json");
                File.WriteAllText(olderFile, JsonSerializer.Serialize(olderSnapshot, JsonOptions.Default), Encoding.UTF8);

                var monitor = new CertificateMonitor {
                    CacheDirectory = tempDir
                };

                var filteredByUntil = monitor.QueryInventoryEntries(new CertificateInventoryQuery {
                    HostContains = "example.com",
                    UntilUtc = now.AddMinutes(-10),
                    MaxResults = 10
                });

                Assert.Equal(2, filteredByUntil.LoadedSnapshotCount);
                Assert.Equal(1, filteredByUntil.ScannedSnapshotCount);
                Assert.Equal(1, filteredByUntil.SkippedSnapshotCountByUntilUtc);
                Assert.Equal(1, filteredByUntil.ScannedEntryCount);
                Assert.Equal(0, filteredByUntil.SkippedByLatestPerEndpointCount);
                Assert.Equal(1, filteredByUntil.EvaluatedEntryCount);
                Assert.Equal(0, filteredByUntil.ExcludedByFiltersCount);
                Assert.Equal(1, filteredByUntil.MatchedEntryCount);
                Assert.Equal(1, filteredByUntil.MatchedUniqueEndpointCount);
                Assert.Equal(0, filteredByUntil.EntriesTruncatedByMaxResults);
                Assert.Equal(filteredByUntil.LoadedSnapshotCount, filteredByUntil.ScannedSnapshotCount + filteredByUntil.SkippedSnapshotCountByUntilUtc);
                Assert.Equal(filteredByUntil.ScannedEntryCount, filteredByUntil.SkippedByLatestPerEndpointCount + filteredByUntil.EvaluatedEntryCount);
                Assert.Equal(filteredByUntil.EvaluatedEntryCount, filteredByUntil.MatchedEntryCount + filteredByUntil.ExcludedByFiltersCount);
                var entry = Assert.Single(filteredByUntil.Entries);
                Assert.Equal("older.example.com", entry.Entry.Host);
            } finally {
                if (Directory.Exists(tempDir)) {
                    Directory.Delete(tempDir, true);
                }
            }
        }

        [Fact]
        public void QueryInventoryEntriesUntilUtcCanExcludeAllSnapshots() {
            var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            var inventoryDir = Path.Combine(tempDir, "inventory");
            Directory.CreateDirectory(inventoryDir);
            try {
                var now = DateTimeOffset.UtcNow;
                var firstSnapshot = new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddMinutes(-5),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "first.example.com",
                            ResolvedHost = "first.example.com",
                            Service = "HTTPS",
                            Port = 443,
                            CertificateIssuerNormalized = "First CA",
                            SubjectAlternativeNames = new List<string> { "first.example.com" },
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
                var secondSnapshot = new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddMinutes(-15),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "second.example.com",
                            ResolvedHost = "second.example.com",
                            Service = "HTTPS",
                            Port = 443,
                            CertificateIssuerNormalized = "Second CA",
                            SubjectAlternativeNames = new List<string> { "second.example.com" },
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

                var firstFile = Path.Combine(inventoryDir, $"{firstSnapshot.CapturedAtUtc:yyyyMMddTHHmmssfffffffZ}_443.json");
                File.WriteAllText(firstFile, JsonSerializer.Serialize(firstSnapshot, JsonOptions.Default), Encoding.UTF8);
                var secondFile = Path.Combine(inventoryDir, $"{secondSnapshot.CapturedAtUtc:yyyyMMddTHHmmssfffffffZ}_443.json");
                File.WriteAllText(secondFile, JsonSerializer.Serialize(secondSnapshot, JsonOptions.Default), Encoding.UTF8);

                var monitor = new CertificateMonitor {
                    CacheDirectory = tempDir
                };

                var fullySkipped = monitor.QueryInventoryEntries(new CertificateInventoryQuery {
                    HostContains = "example.com",
                    UntilUtc = now.AddMinutes(-30),
                    MaxResults = 10
                });

                Assert.Equal(2, fullySkipped.LoadedSnapshotCount);
                Assert.Equal(0, fullySkipped.ScannedSnapshotCount);
                Assert.Equal(2, fullySkipped.SkippedSnapshotCountByUntilUtc);
                Assert.Equal(0, fullySkipped.ScannedEntryCount);
                Assert.Equal(0, fullySkipped.SkippedByLatestPerEndpointCount);
                Assert.Equal(0, fullySkipped.EvaluatedEntryCount);
                Assert.Equal(0, fullySkipped.ExcludedByFiltersCount);
                Assert.Equal(0, fullySkipped.MatchedEntryCount);
                Assert.Equal(0, fullySkipped.MatchedUniqueEndpointCount);
                Assert.Equal(0, fullySkipped.EntriesTruncatedByMaxResults);
                Assert.False(fullySkipped.Truncated);
                Assert.Equal(fullySkipped.LoadedSnapshotCount, fullySkipped.ScannedSnapshotCount + fullySkipped.SkippedSnapshotCountByUntilUtc);
                Assert.Equal(fullySkipped.ScannedEntryCount, fullySkipped.SkippedByLatestPerEndpointCount + fullySkipped.EvaluatedEntryCount);
                Assert.Equal(fullySkipped.EvaluatedEntryCount, fullySkipped.MatchedEntryCount + fullySkipped.ExcludedByFiltersCount);
                Assert.Empty(fullySkipped.Entries);
            } finally {
                if (Directory.Exists(tempDir)) {
                    Directory.Delete(tempDir, true);
                }
            }
        }

    }
}
