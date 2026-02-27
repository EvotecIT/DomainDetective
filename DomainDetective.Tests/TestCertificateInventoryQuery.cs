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
                            CertificateAuthorityFamily = "DigiCert",
                            CertificateThumbprint = "AA11BB22CC33DD44",
                            CertificateRootIssuerNormalized = "ISRG Root X1",
                            CertificateRootAuthorityFamily = "LetsEncrypt",
                            IsKnownCertificateAuthority = true,
                            IsKnownRootCertificateAuthority = true,
                            SubjectAlternativeNames = new List<string> { "api.example.com", "api-int.example.com" },
                            CtDiscoverySources = new List<string> { "crt.sh", "shodan" },
                            CertificateChainSource = "tls-handshake",
                            CertificateChainSources = new List<string> { "tls-handshake", "local-build-online" },
                            NotAfterUtc = now.AddDays(8),
                            Valid = true,
                            ChainComplete = true,
                            HostnameMatch = true,
                            IsReachable = true,
                            PresentInCtLogs = true,
                            AllowsServerAuthentication = true,
                            AllowsClientAuthentication = false,
                            AllowsSecureEmail = false,
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly
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
                            IsKnownRootCertificateAuthority = false,
                            SubjectAlternativeNames = new List<string> { "internal.example.com", "mtls.example.com" },
                            CtDiscoverySources = new List<string>(),
                            CtTemplateFormatErrors = new List<string> { "CensysApiUrlTemplate: source enabled but template is empty." },
                            CertificateChainSource = "local-build-no-check",
                            CertificateChainSources = new List<string> { "local-build-no-check" },
                            NotAfterUtc = now.AddDays(50),
                            Valid = false,
                            ChainComplete = false,
                            HostnameMatch = false,
                            IsSelfSigned = true,
                            IsReachable = true,
                            PresentInCtLogs = false,
                            AllowsServerAuthentication = false,
                            AllowsClientAuthentication = true,
                            AllowsSecureEmail = false,
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ClientAuthOnly
                        },
                        new() {
                            Host = "old.example.com",
                            ResolvedHost = "old.example.com",
                            Service = "HTTPS",
                            Port = 443,
                            CertificateSubject = "CN=old.example.com, O=Example Legacy",
                            CertificateIssuerNormalized = "DigiCert",
                            CertificateAuthorityFamily = "DigiCert",
                            CertificateThumbprint = "11223344AABB",
                            CertificateRootIssuerNormalized = "DigiCert Global Root G2",
                            CertificateRootAuthorityFamily = "DigiCert",
                            IsKnownCertificateAuthority = true,
                            IsKnownRootCertificateAuthority = true,
                            SubjectAlternativeNames = new List<string> { "old.example.com" },
                            CtDiscoverySources = new List<string> { "crt.sh" },
                            CertificateChainSource = "tls-handshake",
                            NotAfterUtc = now.AddDays(-1),
                            Valid = false,
                            Expired = true,
                            ChainComplete = true,
                            HostnameMatch = true,
                            IsReachable = false,
                            PresentInCtLogs = true,
                            AllowsServerAuthentication = true,
                            AllowsClientAuthentication = false,
                            AllowsSecureEmail = false,
                            AuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly
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

                Assert.Equal(1, result.LoadedSnapshotCount);
                Assert.Equal(1, result.ScannedSnapshotCount);
                Assert.Equal(0, result.SkippedSnapshotCountByUntilUtc);
                Assert.Equal(3, result.ScannedEntryCount);
                Assert.Equal(3, result.EvaluatedEntryCount);
                Assert.Equal(2, result.ExcludedByFiltersCount);
                Assert.Equal(1, result.MatchedEntryCount);
                Assert.Equal(1, result.MatchedUniqueEndpointCount);
                Assert.Equal(0, result.SkippedByLatestPerEndpointCount);
                Assert.Equal(0, result.EntriesTruncatedByMaxResults);
                Assert.Equal(result.LoadedSnapshotCount, result.ScannedSnapshotCount + result.SkippedSnapshotCountByUntilUtc);
                Assert.Equal(result.ScannedEntryCount, result.SkippedByLatestPerEndpointCount + result.EvaluatedEntryCount);
                Assert.Equal(result.EvaluatedEntryCount, result.MatchedEntryCount + result.ExcludedByFiltersCount);
                Assert.Equal(result.MatchedEntryCount, result.Entries.Count + result.EntriesTruncatedByMaxResults);
                Assert.Single(result.Entries);
                Assert.Equal("api.example.com", result.Entries[0].Entry.Host);
                Assert.Equal(1, result.MatchedServiceCounts["HTTPS"]);
                Assert.Equal(1, result.MatchedIssuerCounts["DigiCert"]);
                Assert.Equal(1, result.MatchedRootIssuerCounts["ISRG Root X1"]);
                Assert.Equal(1, result.MatchedAuthenticationProfileCounts[CertificateAuthenticationProfileClassifier.ServerAuthOnly]);
                Assert.Equal(1, result.MatchedChainSourceCounts["tls-handshake"]);
                Assert.Equal(1, result.MatchedCtSourceCounts["crt.sh"]);
                Assert.Equal(1, result.MatchedCtSourceCounts["shodan"]);
                Assert.Empty(result.MatchedCtTemplateErrorCounts);

                var limited = monitor.QueryInventoryEntries(new CertificateInventoryQuery {
                    HostContains = "example.com",
                    MaxResults = 1
                });
                Assert.Equal(1, limited.LoadedSnapshotCount);
                Assert.Equal(1, limited.ScannedSnapshotCount);
                Assert.Equal(0, limited.SkippedSnapshotCountByUntilUtc);
                Assert.Equal(3, limited.EvaluatedEntryCount);
                Assert.Equal(0, limited.ExcludedByFiltersCount);
                Assert.Equal(3, limited.MatchedEntryCount);
                Assert.Equal(3, limited.MatchedUniqueEndpointCount);
                Assert.True(limited.Truncated);
                Assert.Equal(2, limited.EntriesTruncatedByMaxResults);
                Assert.Equal(limited.LoadedSnapshotCount, limited.ScannedSnapshotCount + limited.SkippedSnapshotCountByUntilUtc);
                Assert.Equal(limited.EvaluatedEntryCount, limited.MatchedEntryCount + limited.ExcludedByFiltersCount);
                Assert.Equal(limited.MatchedEntryCount, limited.Entries.Count + limited.EntriesTruncatedByMaxResults);
                Assert.Single(limited.Entries);
                Assert.Equal(2, limited.MatchedServiceCounts["HTTPS"]);
                Assert.Equal(1, limited.MatchedServiceCounts["Custom TLS"]);
                Assert.Equal(2, limited.MatchedIssuerCounts["DigiCert"]);
                Assert.Equal(1, limited.MatchedIssuerCounts["Contoso PKI"]);
                Assert.Equal(1, limited.MatchedRootIssuerCounts["ISRG Root X1"]);
                Assert.Equal(1, limited.MatchedRootIssuerCounts["Contoso Root CA"]);
                Assert.Equal(1, limited.MatchedRootIssuerCounts["DigiCert Global Root G2"]);
                Assert.Equal(2, limited.MatchedAuthenticationProfileCounts[CertificateAuthenticationProfileClassifier.ServerAuthOnly]);
                Assert.Equal(1, limited.MatchedAuthenticationProfileCounts[CertificateAuthenticationProfileClassifier.ClientAuthOnly]);
                Assert.Equal(2, limited.MatchedChainSourceCounts["tls-handshake"]);
                Assert.Equal(1, limited.MatchedChainSourceCounts["local-build-no-check"]);
                Assert.Equal(2, limited.MatchedCtSourceCounts["crt.sh"]);
                Assert.Equal(1, limited.MatchedCtSourceCounts["shodan"]);
                Assert.Equal(1, limited.MatchedCtSourceCounts["none"]);
                Assert.Equal(1, limited.MatchedCtTemplateErrorCounts["CensysApiUrlTemplate"]);

                var zeroCap = monitor.QueryInventoryEntries(new CertificateInventoryQuery {
                    HostContains = "example.com",
                    MaxResults = 0
                });
                Assert.Equal(1, zeroCap.LoadedSnapshotCount);
                Assert.Equal(1, zeroCap.ScannedSnapshotCount);
                Assert.Equal(0, zeroCap.SkippedSnapshotCountByUntilUtc);
                Assert.Equal(3, zeroCap.EvaluatedEntryCount);
                Assert.Equal(0, zeroCap.ExcludedByFiltersCount);
                Assert.Equal(3, zeroCap.MatchedEntryCount);
                Assert.Equal(3, zeroCap.EntriesTruncatedByMaxResults);
                Assert.True(zeroCap.Truncated);
                Assert.Empty(zeroCap.Entries);
                Assert.Equal(zeroCap.LoadedSnapshotCount, zeroCap.ScannedSnapshotCount + zeroCap.SkippedSnapshotCountByUntilUtc);
                Assert.Equal(zeroCap.EvaluatedEntryCount, zeroCap.MatchedEntryCount + zeroCap.ExcludedByFiltersCount);
                Assert.Equal(zeroCap.MatchedEntryCount, zeroCap.Entries.Count + zeroCap.EntriesTruncatedByMaxResults);

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

                var authProfileFilter = monitor.QueryInventoryEntries(new CertificateInventoryQuery {
                    AuthenticationProfileEquals = "ClientAuthOnly",
                    MaxResults = 10
                });
                Assert.Equal(1, authProfileFilter.MatchedEntryCount);
                Assert.Single(authProfileFilter.Entries);
                Assert.Equal("internal.example.com", authProfileFilter.Entries[0].Entry.Host);

                var ctSourceFilter = monitor.QueryInventoryEntries(new CertificateInventoryQuery {
                    CtSourceContains = "shod",
                    MaxResults = 10
                });
                Assert.Equal(1, ctSourceFilter.MatchedEntryCount);
                Assert.Single(ctSourceFilter.Entries);
                Assert.Equal("api.example.com", ctSourceFilter.Entries[0].Entry.Host);

                var ctTemplateErrorFilter = monitor.QueryInventoryEntries(new CertificateInventoryQuery {
                    CtTemplateErrorContains = "censysapiurltemplate",
                    MaxResults = 10
                });
                Assert.Equal(1, ctTemplateErrorFilter.MatchedEntryCount);
                Assert.Single(ctTemplateErrorFilter.Entries);
                Assert.Equal("internal.example.com", ctTemplateErrorFilter.Entries[0].Entry.Host);

                var chainSourceFilter = monitor.QueryInventoryEntries(new CertificateInventoryQuery {
                    ChainSourceContains = "handshake",
                    MaxResults = 10
                });
                Assert.Equal(2, chainSourceFilter.MatchedEntryCount);
                Assert.Equal(2, chainSourceFilter.Entries.Count);

                var familyFilter = monitor.QueryInventoryEntries(new CertificateInventoryQuery {
                    AuthorityFamilyEquals = "digicert",
                    RootAuthorityFamilyEquals = "digicert",
                    KnownRootAuthorityOnly = true,
                    MaxResults = 10
                });
                Assert.Equal(1, familyFilter.MatchedEntryCount);
                Assert.Single(familyFilter.Entries);
                Assert.Equal("old.example.com", familyFilter.Entries[0].Entry.Host);
            } finally {
                if (Directory.Exists(tempDir)) {
                    Directory.Delete(tempDir, true);
                }
            }
        }

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
