using System;
using System.Collections.Generic;

namespace DomainDetective.Tests;

public class TestCertificateInventoryNativeCtDiagnosticsHealthAnalyzer {
    [Fact]
    public void Build_ComputesLatestStatusAndLastBreach() {
        var snapshots = new[] {
            new CertificateInventorySnapshot {
                CapturedAtUtc = new DateTimeOffset(2026, 3, 3, 12, 0, 0, TimeSpan.Zero),
                NativeCtLogDiagnostics = new List<NativeCtLogDiagnosticEntry> {
                    new NativeCtLogDiagnosticEntry { State = "Succeeded", LogUrl = "https://ct.example/a/", LagAfter = 10 }
                }
            },
            new CertificateInventorySnapshot {
                CapturedAtUtc = new DateTimeOffset(2026, 3, 2, 12, 0, 0, TimeSpan.Zero),
                NativeCtLogDiagnostics = new List<NativeCtLogDiagnosticEntry> {
                    new NativeCtLogDiagnosticEntry { State = "Failed", LogUrl = "https://ct.example/b/", LagAfter = 7000 }
                }
            }
        };

        var query = new CertificateInventoryNativeCtDiagnosticsHealthQuery {
            MaxSnapshots = 10,
            AlertThresholds = new CertificateInventoryNativeCtDiagnosticsAlertThresholds {
                MaxFailedDiagnostics = 0,
                MaxLagAfter = 5000
            }
        };

        var summary = CertificateInventoryNativeCtDiagnosticsHealthAnalyzer.Build(snapshots, query);

        Assert.Equal(2, summary.LoadedSnapshotCount);
        Assert.Equal(2, summary.ReturnedSnapshotCount);
        Assert.Equal(1, summary.BreachedSnapshotCount);
        Assert.Equal("Healthy", summary.LatestStatus);
        Assert.Equal(new DateTimeOffset(2026, 3, 2, 12, 0, 0, TimeSpan.Zero), summary.LastBreachCapturedAtUtc);
    }

    [Fact]
    public void Build_ParsesRawDiagnosticsAndMarksBreached() {
        var snapshots = new[] {
            new CertificateInventorySnapshot {
                CapturedAtUtc = new DateTimeOffset(2026, 3, 4, 10, 0, 0, TimeSpan.Zero),
                NativeCtLogDiagnosticsRaw = new List<string> {
                    "scope=shared:example.com; state=Failed; log=https://ct.example/logA/; lagAfter=33",
                    "scope=shared:example.com; state=Succeeded; log=https://ct.example/logB/; lagAfter=1"
                }
            }
        };

        var query = new CertificateInventoryNativeCtDiagnosticsHealthQuery {
            AlertThresholds = new CertificateInventoryNativeCtDiagnosticsAlertThresholds {
                MaxFailedDiagnostics = 0
            }
        };

        var summary = CertificateInventoryNativeCtDiagnosticsHealthAnalyzer.Build(snapshots, query);

        Assert.Single(summary.Snapshots);
        Assert.Equal("Breached", summary.Snapshots[0].Status);
        Assert.True(summary.Snapshots[0].ThresholdBreached);
        Assert.Equal(2, summary.Snapshots[0].DiagnosticCount);
        Assert.Equal(1, summary.Snapshots[0].FailedCount);
    }

    [Fact]
    public void Build_LatestOnlyAndUntilFilterReturnNewestEligibleSnapshot() {
        var snapshots = new[] {
            new CertificateInventorySnapshot {
                CapturedAtUtc = new DateTimeOffset(2026, 3, 5, 10, 0, 0, TimeSpan.Zero),
                NativeCtLogDiagnostics = new List<NativeCtLogDiagnosticEntry> {
                    new NativeCtLogDiagnosticEntry { State = "Succeeded", LogUrl = "https://ct.example/new/" }
                }
            },
            new CertificateInventorySnapshot {
                CapturedAtUtc = new DateTimeOffset(2026, 3, 4, 10, 0, 0, TimeSpan.Zero),
                NativeCtLogDiagnostics = new List<NativeCtLogDiagnosticEntry> {
                    new NativeCtLogDiagnosticEntry { State = "Failed", LogUrl = "https://ct.example/old/" }
                }
            }
        };

        var query = new CertificateInventoryNativeCtDiagnosticsHealthQuery {
            UntilUtc = new DateTimeOffset(2026, 3, 4, 23, 0, 0, TimeSpan.Zero),
            LatestSnapshotOnly = true,
            MaxSnapshots = 10
        };

        var summary = CertificateInventoryNativeCtDiagnosticsHealthAnalyzer.Build(snapshots, query);

        Assert.Equal(2, summary.LoadedSnapshotCount);
        Assert.Equal(1, summary.ExcludedByUntilCount);
        Assert.Equal(1, summary.ReturnedSnapshotCount);
        Assert.Equal(new DateTimeOffset(2026, 3, 4, 10, 0, 0, TimeSpan.Zero), summary.Snapshots[0].CapturedAtUtc);
    }
}
