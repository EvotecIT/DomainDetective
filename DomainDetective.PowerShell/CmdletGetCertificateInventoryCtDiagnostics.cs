using System;
using System.Management.Automation;

namespace DomainDetective.PowerShell;

/// <summary>Queries persisted native CT ingestion diagnostics captured with certificate inventory snapshots.</summary>
/// <para>Use this cmdlet to inspect CT ingestion health over time (for example failed logs, open circuits, or high lag after processing).</para>
/// <example>
///   <summary>Query failed native CT diagnostics from the last 7 days</summary>
///   <code>Get-DDCertificateInventoryCtDiagnostics -SinceUtc (Get-Date).ToUniversalTime().AddDays(-7) -State Failed</code>
/// </example>
/// <example>
///   <summary>Find circuit-open native CT diagnostics with high lag</summary>
///   <code>Get-DDCertificateInventoryCtDiagnostics -State CircuitOpen -LagAfterMin 10000</code>
/// </example>
/// <example>
///   <summary>Enforce alert thresholds and fail when breached</summary>
///   <code>Get-DDCertificateInventoryCtDiagnostics -LatestOnly -MaxFailed 0 -MaxCircuitOpen 0 -MaxLagAfter 5000 -FailOnThresholdBreach</code>
/// </example>
[Cmdlet(VerbsCommon.Get, "DDCertificateInventoryCtDiagnostics")]
[OutputType(typeof(CertificateInventoryNativeCtDiagnosticsResult))]
public sealed class CmdletGetCertificateInventoryCtDiagnostics : PSCmdlet {
    /// <summary>Certificate monitor cache directory containing the inventory folder.</summary>
    [Parameter(Mandatory = false)]
    public string? CacheDirectory { get; set; }

    /// <summary>Only include snapshots captured since this UTC date/time.</summary>
    [Parameter(Mandatory = false)]
    public DateTime? SinceUtc { get; set; }

    /// <summary>Only include snapshots captured up to this UTC date/time.</summary>
    [Parameter(Mandatory = false)]
    public DateTime? UntilUtc { get; set; }

    /// <summary>Only evaluate the latest snapshot after date filtering.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter LatestOnly { get; set; }

    /// <summary>Optional state filter(s): Succeeded, Failed, CircuitOpen, Unknown.</summary>
    [Parameter(Mandatory = false)]
    [ValidateSet("Succeeded", "Failed", "CircuitOpen", "Unknown")]
    public string[] State { get; set; } = Array.Empty<string>();

    /// <summary>Optional contains filter applied to CT log URL.</summary>
    [Parameter(Mandatory = false)]
    public string? LogUrlContains { get; set; }

    /// <summary>Optional contains filter applied to diagnostic scope.</summary>
    [Parameter(Mandatory = false)]
    public string? ScopeContains { get; set; }

    /// <summary>Only return diagnostics currently marked as circuit open.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter CircuitOpenOnly { get; set; }

    /// <summary>Only return diagnostics that include failure messages.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter FailureOnly { get; set; }

    /// <summary>Optional minimum LagBefore value.</summary>
    [Parameter(Mandatory = false)]
    public long? LagBeforeMin { get; set; }

    /// <summary>Optional maximum LagBefore value.</summary>
    [Parameter(Mandatory = false)]
    public long? LagBeforeMax { get; set; }

    /// <summary>Optional minimum LagAfter value.</summary>
    [Parameter(Mandatory = false)]
    public long? LagAfterMin { get; set; }

    /// <summary>Optional maximum LagAfter value.</summary>
    [Parameter(Mandatory = false)]
    public long? LagAfterMax { get; set; }

    /// <summary>Maximum number of entries returned.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int MaxResults { get; set; } = 2000;

    /// <summary>Alert threshold: maximum allowed diagnostics in Failed state.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MaxFailed { get; set; }

    /// <summary>Alert threshold: maximum allowed diagnostics in CircuitOpen state.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MaxCircuitOpen { get; set; }

    /// <summary>Alert threshold: maximum allowed LagAfter value across matched diagnostics.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, long.MaxValue)]
    public long? MaxLagAfter { get; set; }

    /// <summary>When set, the cmdlet throws a terminating error if any configured threshold is breached.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter FailOnThresholdBreach { get; set; }

    /// <summary>Executes the cmdlet.</summary>
    protected override void ProcessRecord() {
        var sinceUtc = CertificateInventoryCmdletHelpers.ToUtc(SinceUtc);
        var untilUtc = CertificateInventoryCmdletHelpers.ToUtc(UntilUtc);
        if (sinceUtc.HasValue && untilUtc.HasValue && sinceUtc.Value > untilUtc.Value) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-SinceUtc must be less than or equal to -UntilUtc."),
                "InvalidNativeCtDiagnosticsDateRange",
                ErrorCategory.InvalidArgument,
                SinceUtc));
            return;
        }
        if (LagBeforeMin.HasValue && LagBeforeMax.HasValue && LagBeforeMin.Value > LagBeforeMax.Value) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-LagBeforeMin must be less than or equal to -LagBeforeMax."),
                "InvalidNativeCtLagBeforeRange",
                ErrorCategory.InvalidArgument,
                LagBeforeMin));
            return;
        }
        if (LagAfterMin.HasValue && LagAfterMax.HasValue && LagAfterMin.Value > LagAfterMax.Value) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-LagAfterMin must be less than or equal to -LagAfterMax."),
                "InvalidNativeCtLagAfterRange",
                ErrorCategory.InvalidArgument,
                LagAfterMin));
            return;
        }

        var monitor = new CertificateMonitor {
            CacheDirectory = CertificateInventoryCmdletHelpers.ResolveCacheDirectory(CacheDirectory),
            PersistInventorySnapshots = false
        };

        var query = new CertificateInventoryNativeCtDiagnosticsQuery {
            SinceUtc = sinceUtc,
            UntilUtc = untilUtc,
            LatestSnapshotOnly = LatestOnly.IsPresent,
            LogUrlContains = LogUrlContains,
            ScopeContains = ScopeContains,
            CircuitOpenOnly = CircuitOpenOnly.IsPresent,
            FailureOnly = FailureOnly.IsPresent,
            LagBeforeMin = LagBeforeMin,
            LagBeforeMax = LagBeforeMax,
            LagAfterMin = LagAfterMin,
            LagAfterMax = LagAfterMax,
            MaxResults = MaxResults
        };
        if (State != null && State.Length > 0) {
            foreach (var state in State) {
                if (!string.IsNullOrWhiteSpace(state)) {
                    query.States.Add(state.Trim());
                }
            }
        }

        var result = monitor.QueryInventoryNativeCtDiagnostics(query);
        var thresholds = BuildAlertThresholds();
        if (thresholds != null) {
            var evaluation = CertificateInventoryNativeCtDiagnosticsAlerts.Evaluate(result, thresholds);
            result.AlertEvaluation = evaluation;
            if (evaluation.HasBreach) {
                foreach (var message in evaluation.BreachMessages) {
                    WriteWarning($"Threshold breached: {message}");
                }

                if (FailOnThresholdBreach.IsPresent) {
                    ThrowTerminatingError(new ErrorRecord(
                        new InvalidOperationException($"Native CT diagnostic threshold breached: {string.Join(" ", evaluation.BreachMessages)}"),
                        "NativeCtDiagnosticsThresholdBreached",
                        ErrorCategory.InvalidResult,
                        result));
                    return;
                }
            }
        }

        WriteObject(result);
    }

    private CertificateInventoryNativeCtDiagnosticsAlertThresholds? BuildAlertThresholds() {
        if (!MaxFailed.HasValue && !MaxCircuitOpen.HasValue && !MaxLagAfter.HasValue) {
            return null;
        }

        return new CertificateInventoryNativeCtDiagnosticsAlertThresholds {
            MaxFailedDiagnostics = MaxFailed,
            MaxCircuitOpenDiagnostics = MaxCircuitOpen,
            MaxLagAfter = MaxLagAfter
        };
    }
}
