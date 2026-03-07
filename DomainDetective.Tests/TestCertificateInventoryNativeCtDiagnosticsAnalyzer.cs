using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Tests;

public class TestCertificateInventoryNativeCtDiagnosticsAnalyzer {
    [Fact]
    public void Query_FiltersByStateAndLagAfter() {
        var snapshots = new[] {
            new CertificateInventorySnapshot {
                CapturedAtUtc = new DateTimeOffset(2026, 3, 1, 10, 0, 0, TimeSpan.Zero),
                NativeCtLogDiagnostics = new List<NativeCtLogDiagnosticEntry> {
                    new NativeCtLogDiagnosticEntry {
                        Scope = "shared:example.com",
                        SharedIngestion = true,
                        State = "Failed",
                        LogUrl = "https://ct.example/log1/",
                        LagAfter = 20000,
                        Failure = "timeout"
                    },
                    new NativeCtLogDiagnosticEntry {
                        Scope = "shared:example.com",
                        SharedIngestion = true,
                        State = "Succeeded",
                        LogUrl = "https://ct.example/log2/",
                        LagAfter = 12
                    }
                }
            },
            new CertificateInventorySnapshot {
                CapturedAtUtc = new DateTimeOffset(2026, 2, 28, 10, 0, 0, TimeSpan.Zero),
                NativeCtLogDiagnostics = new List<NativeCtLogDiagnosticEntry> {
                    new NativeCtLogDiagnosticEntry {
                        Scope = "domain:example.com",
                        SharedIngestion = false,
                        State = "CircuitOpen",
                        LogUrl = "https://ct.example/log3/",
                        LagAfter = 5000
                    }
                }
            }
        };

        var query = new CertificateInventoryNativeCtDiagnosticsQuery {
            LagAfterMin = 10000,
            MaxResults = 100
        };
        query.States.Add("Failed");

        var result = CertificateInventoryNativeCtDiagnosticsAnalyzer.Query(snapshots, query);

        Assert.Equal(2, result.LoadedSnapshotCount);
        Assert.Equal(3, result.ScannedDiagnosticCount);
        Assert.Equal(1, result.MatchedDiagnosticCount);
        Assert.Equal(20000, result.MatchedLagAfterMax);
        Assert.Single(result.Entries);
        Assert.Equal("Failed", result.Entries[0].Entry.State);
        Assert.Equal(20000, result.Entries[0].Entry.LagAfter);
        Assert.True(result.MatchedByState.TryGetValue("Failed", out var failedCount));
        Assert.Equal(1, failedCount);
    }

    [Fact]
    public void Query_ParsesRawDiagnosticsWhenStructuredEntriesMissing() {
        var snapshot = new CertificateInventorySnapshot {
            CapturedAtUtc = new DateTimeOffset(2026, 3, 2, 11, 0, 0, TimeSpan.Zero),
            NativeCtLogDiagnosticsRaw = new List<string> {
                "scope=shared:example.com; state=Failed; log=https://ct.example/logA/; tree=1234; last=1200; lagBefore=34; lagAfter=33; circuitUntil=-; failure=request timeout",
                "scope=shared:example.com; state=Succeeded; log=https://ct.example/logB/; tree=2234; last=2233; lagBefore=1; lagAfter=0; circuitUntil=-; failure=-"
            }
        };

        var query = new CertificateInventoryNativeCtDiagnosticsQuery {
            FailureOnly = true,
            MaxResults = 100
        };

        var result = CertificateInventoryNativeCtDiagnosticsAnalyzer.Query(new[] { snapshot }, query);

        Assert.Equal(2, result.ScannedDiagnosticCount);
        Assert.Equal(1, result.MatchedDiagnosticCount);
        Assert.Single(result.Entries);
        var entry = result.Entries.Single().Entry;
        Assert.Equal("Failed", entry.State);
        Assert.Equal("https://ct.example/logA/", entry.LogUrl);
        Assert.Equal(33, entry.LagAfter);
        Assert.Equal("request timeout", entry.Failure);
    }

    [Fact]
    public void Query_LatestSnapshotOnlyLimitsScanToNewestAfterUntilFilter() {
        var snapshots = new[] {
            new CertificateInventorySnapshot {
                CapturedAtUtc = new DateTimeOffset(2026, 3, 3, 8, 0, 0, TimeSpan.Zero),
                NativeCtLogDiagnostics = new List<NativeCtLogDiagnosticEntry> {
                    new NativeCtLogDiagnosticEntry { Scope = "shared:a.com", State = "Succeeded", LogUrl = "https://ct.example/new/" }
                }
            },
            new CertificateInventorySnapshot {
                CapturedAtUtc = new DateTimeOffset(2026, 3, 2, 8, 0, 0, TimeSpan.Zero),
                NativeCtLogDiagnostics = new List<NativeCtLogDiagnosticEntry> {
                    new NativeCtLogDiagnosticEntry { Scope = "shared:a.com", State = "Failed", LogUrl = "https://ct.example/old/", Failure = "error" }
                }
            }
        };

        var query = new CertificateInventoryNativeCtDiagnosticsQuery {
            UntilUtc = new DateTimeOffset(2026, 3, 2, 12, 0, 0, TimeSpan.Zero),
            LatestSnapshotOnly = true,
            MaxResults = 100
        };

        var result = CertificateInventoryNativeCtDiagnosticsAnalyzer.Query(snapshots, query);

        Assert.Equal(2, result.LoadedSnapshotCount);
        Assert.Equal(1, result.SkippedSnapshotCountByUntilUtc);
        Assert.Equal(1, result.ScannedSnapshotCount);
        Assert.Single(result.Entries);
        Assert.Equal("https://ct.example/old/", result.Entries[0].Entry.LogUrl);
    }

    [Fact]
    public void Query_TracksMaxLagAfterAcrossAllMatchedRows_WhenResultsTruncated() {
        var snapshot = new CertificateInventorySnapshot {
            CapturedAtUtc = new DateTimeOffset(2026, 3, 3, 9, 0, 0, TimeSpan.Zero),
            NativeCtLogDiagnostics = new List<NativeCtLogDiagnosticEntry> {
                new NativeCtLogDiagnosticEntry { Scope = "shared:test", State = "Failed", LogUrl = "https://ct.example/a/", LagAfter = 150 },
                new NativeCtLogDiagnosticEntry { Scope = "shared:test", State = "Failed", LogUrl = "https://ct.example/b/", LagAfter = 12500 }
            }
        };

        var query = new CertificateInventoryNativeCtDiagnosticsQuery {
            MaxResults = 1
        };

        var result = CertificateInventoryNativeCtDiagnosticsAnalyzer.Query(new[] { snapshot }, query);

        Assert.Equal(2, result.MatchedDiagnosticCount);
        Assert.True(result.Truncated);
        Assert.Single(result.Entries);
        Assert.Equal(12500, result.MatchedLagAfterMax);
    }
}
