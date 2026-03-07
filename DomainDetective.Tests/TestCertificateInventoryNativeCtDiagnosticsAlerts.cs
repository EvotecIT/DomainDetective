using System;
using System.Collections.Generic;

namespace DomainDetective.Tests;

public class TestCertificateInventoryNativeCtDiagnosticsAlerts {
    [Fact]
    public void Evaluate_ReturnsBreaches_WhenThresholdsExceeded() {
        var result = new CertificateInventoryNativeCtDiagnosticsResult {
            MatchedLagAfterMax = 12000
        };
        result.MatchedByState["Failed"] = 3;
        result.MatchedByState["CircuitOpen"] = 2;

        var thresholds = new CertificateInventoryNativeCtDiagnosticsAlertThresholds {
            MaxFailedDiagnostics = 1,
            MaxCircuitOpenDiagnostics = 0,
            MaxLagAfter = 5000
        };

        var evaluation = CertificateInventoryNativeCtDiagnosticsAlerts.Evaluate(result, thresholds);

        Assert.True(evaluation.HasBreach);
        Assert.True(evaluation.FailedDiagnosticsThresholdBreached);
        Assert.True(evaluation.CircuitOpenDiagnosticsThresholdBreached);
        Assert.True(evaluation.LagAfterThresholdBreached);
        Assert.Equal(3, evaluation.BreachMessages.Count);
    }

    [Fact]
    public void Evaluate_ReturnsNoBreach_WhenThresholdsMet() {
        var result = new CertificateInventoryNativeCtDiagnosticsResult {
            MatchedLagAfterMax = 900
        };
        result.MatchedByState["Failed"] = 1;
        result.MatchedByState["CircuitOpen"] = 0;

        var thresholds = new CertificateInventoryNativeCtDiagnosticsAlertThresholds {
            MaxFailedDiagnostics = 1,
            MaxCircuitOpenDiagnostics = 0,
            MaxLagAfter = 1000
        };

        var evaluation = CertificateInventoryNativeCtDiagnosticsAlerts.Evaluate(result, thresholds);

        Assert.False(evaluation.HasBreach);
        Assert.Empty(evaluation.BreachMessages);
    }

    [Fact]
    public void Evaluate_InfersCircuitOpenFromTimestamp_WhenStateMissing() {
        var result = new CertificateInventoryNativeCtDiagnosticsResult();
        result.Entries.Add(new CertificateInventoryNativeCtDiagnosticObservedEntry {
            CapturedAtUtc = new DateTimeOffset(2026, 3, 3, 10, 0, 0, TimeSpan.Zero),
            Entry = new NativeCtLogDiagnosticEntry {
                State = "Succeeded",
                LogUrl = "https://ct.example/log/",
                CircuitOpenUntilUtc = new DateTimeOffset(2026, 3, 3, 11, 0, 0, TimeSpan.Zero)
            }
        });

        var thresholds = new CertificateInventoryNativeCtDiagnosticsAlertThresholds {
            MaxCircuitOpenDiagnostics = 0
        };

        var evaluation = CertificateInventoryNativeCtDiagnosticsAlerts.Evaluate(
            result,
            thresholds,
            new DateTimeOffset(2026, 3, 3, 10, 30, 0, TimeSpan.Zero));

        Assert.True(evaluation.HasBreach);
        Assert.True(evaluation.CircuitOpenDiagnosticsThresholdBreached);
        Assert.Equal(1, evaluation.CircuitOpenDiagnostics);
    }
}
