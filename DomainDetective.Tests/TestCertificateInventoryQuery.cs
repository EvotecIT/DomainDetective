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
                            CertificateSubject = "CN=api.example.com, O=Example Corp",
                            CertificateIssuerNormalized = "DigiCert",
                            CertificateThumbprint = "AA11BB22CC33DD44",
                            CertificateRootIssuerNormalized = "ISRG Root X1",
                            IsKnownCertificateAuthority = true,
                            SubjectAlternativeNames = new List<string> { "api.example.com", "api-int.example.com" },
                            NotAfterUtc = now.AddDays(8),
                            Valid = true,
                            ChainComplete = true,
                            HostnameMatch = true,
                            IsReachable = true,
                            PresentInCtLogs = true,
                            AllowsServerAuthentication = true,
                            AllowsClientAuthentication = false,
                            AllowsSecureEmail = false
                        },
                        new() {
                            Host = "internal.example.com",
                            ResolvedHost = "internal.example.com",
                            Service = "Custom TLS",
                            Port = 8443,
                            CertificateSubject = "CN=internal.example.com, O=Contoso Internal PKI",
                            CertificateIssuerNormalized = "Contoso PKI",
                            CertificateThumbprint = "EE55FF66",
                            CertificateRootIssuerNormalized = "Contoso Root CA",
                            IsKnownCertificateAuthority = false,
                            SubjectAlternativeNames = new List<string> { "internal.example.com", "mtls.example.com" },
                            NotAfterUtc = now.AddDays(50),
                            Valid = false,
                            ChainComplete = false,
                            HostnameMatch = false,
                            IsSelfSigned = true,
                            IsReachable = true,
                            PresentInCtLogs = false,
                            AllowsServerAuthentication = false,
                            AllowsClientAuthentication = true,
                            AllowsSecureEmail = false
                        },
                        new() {
                            Host = "old.example.com",
                            ResolvedHost = "old.example.com",
                            Service = "HTTPS",
                            Port = 443,
                            CertificateSubject = "CN=old.example.com, O=Example Legacy",
                            CertificateIssuerNormalized = "DigiCert",
                            CertificateThumbprint = "11223344AABB",
                            CertificateRootIssuerNormalized = "DigiCert Global Root G2",
                            IsKnownCertificateAuthority = true,
                            SubjectAlternativeNames = new List<string> { "old.example.com" },
                            NotAfterUtc = now.AddDays(-1),
                            Valid = false,
                            Expired = true,
                            ChainComplete = true,
                            HostnameMatch = true,
                            IsReachable = false,
                            PresentInCtLogs = true,
                            AllowsServerAuthentication = true,
                            AllowsClientAuthentication = false,
                            AllowsSecureEmail = false
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
                Assert.Equal(3, limited.MatchedEntryCount);
                Assert.True(limited.Truncated);
                Assert.Single(limited.Entries);

                var expired = monitor.QueryInventoryEntries(new CertificateInventoryQuery {
                    ExpiredOnly = true,
                    MaxResults = 10
                });
                Assert.Equal(1, expired.MatchedEntryCount);
                Assert.Single(expired.Entries);
                Assert.Equal("old.example.com", expired.Entries[0].Entry.Host);

                var subjectAndSan = monitor.QueryInventoryEntries(new CertificateInventoryQuery {
                    SubjectContains = "Example Corp",
                    SanContains = "api-int",
                    MaxResults = 10
                });
                Assert.Equal(1, subjectAndSan.MatchedEntryCount);
                Assert.Single(subjectAndSan.Entries);
                Assert.Equal("api.example.com", subjectAndSan.Entries[0].Entry.Host);

                var clientAuthRisk = monitor.QueryInventoryEntries(new CertificateInventoryQuery {
                    AllowsClientAuthOnly = true,
                    ChainCompleteOnly = false,
                    HostnameMatchOnly = false,
                    SelfSignedOnly = true,
                    MaxResults = 10
                });
                Assert.Equal(1, clientAuthRisk.MatchedEntryCount);
                Assert.Single(clientAuthRisk.Entries);
                Assert.Equal("internal.example.com", clientAuthRisk.Entries[0].Entry.Host);

                var validCt = monitor.QueryInventoryEntries(new CertificateInventoryQuery {
                    ValidOnly = true,
                    PresentInCtOnly = true,
                    AllowsServerAuthOnly = true,
                    MaxResults = 10
                });
                Assert.Equal(1, validCt.MatchedEntryCount);
                Assert.Single(validCt.Entries);
                Assert.Equal("api.example.com", validCt.Entries[0].Entry.Host);

                var unreachable = monitor.QueryInventoryEntries(new CertificateInventoryQuery {
                    ReachableOnly = false,
                    MaxResults = 10
                });
                Assert.Equal(1, unreachable.MatchedEntryCount);
                Assert.Single(unreachable.Entries);
                Assert.Equal("old.example.com", unreachable.Entries[0].Entry.Host);

                var rootFilter = monitor.QueryInventoryEntries(new CertificateInventoryQuery {
                    RootContains = "isrg",
                    MaxResults = 10
                });
                Assert.Equal(1, rootFilter.MatchedEntryCount);
                Assert.Single(rootFilter.Entries);
                Assert.Equal("api.example.com", rootFilter.Entries[0].Entry.Host);

                var thumbprintFilter = monitor.QueryInventoryEntries(new CertificateInventoryQuery {
                    ThumbprintEquals = "aa11:bb22 cc33dd44",
                    MaxResults = 10
                });
                Assert.Equal(1, thumbprintFilter.MatchedEntryCount);
                Assert.Single(thumbprintFilter.Entries);
                Assert.Equal("api.example.com", thumbprintFilter.Entries[0].Entry.Host);
            } finally {
                if (Directory.Exists(tempDir)) {
                    Directory.Delete(tempDir, true);
                }
            }
        }
    }
}
