using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;

namespace DomainDetective.Tests {
    public class TestCertificateInventoryQuery {
        [Fact]
        public void QueryInventoryEntriesAppliesFiltersAndLimits() {
            var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            var inventoryDir = Path.Combine(tempDir, "inventory");
            Directory.CreateDirectory(inventoryDir);
            try {
                var now = DateTimeOffset.UtcNow;
                var snapshot = new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddMinutes(-10),
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        new() {
                            Host = "api.example.com",
                            ResolvedHost = "api.example.com",
                            Service = "HTTPS",
                            Port = 443,
                            CertificateIssuerNormalized = "DigiCert",
                            IsKnownCertificateAuthority = true,
                            NotAfterUtc = now.AddDays(8)
                        },
                        new() {
                            Host = "internal.example.com",
                            ResolvedHost = "internal.example.com",
                            Service = "Custom TLS",
                            Port = 8443,
                            CertificateIssuerNormalized = "Contoso PKI",
                            IsKnownCertificateAuthority = false,
                            NotAfterUtc = now.AddDays(50)
                        },
                        new() {
                            Host = "old.example.com",
                            ResolvedHost = "old.example.com",
                            Service = "HTTPS",
                            Port = 443,
                            CertificateIssuerNormalized = "DigiCert",
                            IsKnownCertificateAuthority = true,
                            NotAfterUtc = now.AddDays(-1)
                        }
                    }
                };
                var file = Path.Combine(inventoryDir, $"{snapshot.CapturedAtUtc:yyyyMMddTHHmmssfffffffZ}_443.json");
                File.WriteAllText(file, JsonSerializer.Serialize(snapshot, JsonOptions.Default), Encoding.UTF8);

                var monitor = new CertificateMonitor {
                    CacheDirectory = tempDir
                };

                var query = new CertificateInventoryQuery {
                    HostContains = "example.com",
                    ServiceEquals = "HTTPS",
                    IssuerContains = "digicert",
                    KnownAuthorityOnly = true,
                    ExpiringWithinDays = 30,
                    MaxResults = 10
                };
                var result = monitor.QueryInventoryEntries(query);

                Assert.Equal(1, result.ScannedSnapshotCount);
                Assert.Equal(3, result.ScannedEntryCount);
                Assert.Equal(1, result.MatchedEntryCount);
                Assert.Single(result.Entries);
                Assert.Equal("api.example.com", result.Entries[0].Entry.Host);

                var limited = monitor.QueryInventoryEntries(new CertificateInventoryQuery {
                    HostContains = "example.com",
                    MaxResults = 1
                });
                Assert.True(limited.Truncated);
                Assert.Single(limited.Entries);

                var expired = monitor.QueryInventoryEntries(new CertificateInventoryQuery {
                    ExpiredOnly = true,
                    MaxResults = 10
                });
                Assert.Equal(1, expired.MatchedEntryCount);
                Assert.Single(expired.Entries);
                Assert.Equal("old.example.com", expired.Entries[0].Entry.Host);
            } finally {
                if (Directory.Exists(tempDir)) {
                    Directory.Delete(tempDir, true);
                }
            }
        }
    }
}
