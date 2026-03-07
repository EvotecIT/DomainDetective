using System;
using System.Management.Automation;

namespace DomainDetective.PowerShell;

/// <summary>Builds CT diagnostics health timeline from persisted certificate inventory snapshots.</summary>
/// <para>Returns per-snapshot CT status with threshold evaluation and last breach metadata so monitoring/reporting layers can render status panels and trends.</para>
/// <example>
///   <summary>Get CT health for the last 30 days</summary>
///   <code>Get-DDCertificateInventoryCtHealth -SinceUtc (Get-Date).ToUniversalTime().AddDays(-30) -MaxSnapshots 60</code>
/// </example>
/// <example>
///   <summary>Apply thresholds and fail when latest snapshot is breached</summary>
///   <code>Get-DDCertificateInventoryCtHealth -LatestOnly -MaxFailed 0 -MaxCircuitOpen 0 -MaxLagAfter 5000 -FailOnThresholdBreach</code>
/// </example>
/// <example>
///   <summary>Fail when any returned snapshot is breached</summary>
///   <code>Get-DDCertificateInventoryCtHealth -SinceUtc (Get-Date).ToUniversalTime().AddDays(-7) -FailOnAnyBreach -MaxFailed 0 -FailOnThresholdBreach</code>
/// </example>
[Cmdlet(VerbsCommon.Get, "DDCertificateInventoryCtHealth")]
[OutputType(typeof(CertificateInventoryNativeCtDiagnosticsHealthSummary))]
public sealed class CmdletGetCertificateInventoryCtHealth : PSCmdlet {
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

    /// <summary>Maximum timeline rows returned.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int MaxSnapshots { get; set; } = 60;

    /// <summary>Alert threshold: maximum allowed diagnostics in Failed state.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MaxFailed { get; set; }

    /// <summary>Alert threshold: maximum allowed diagnostics in CircuitOpen state.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MaxCircuitOpen { get; set; }

    /// <summary>Alert threshold: maximum allowed LagAfter value across diagnostics.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, long.MaxValue)]
    public long? MaxLagAfter { get; set; }

    /// <summary>When set, fail if any returned snapshot breaches thresholds (otherwise latest snapshot only).</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter FailOnAnyBreach { get; set; }

    /// <summary>When set, throw a terminating error when threshold breach condition is met.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter FailOnThresholdBreach { get; set; }

    /// <summary>Executes the cmdlet.</summary>
    protected override void ProcessRecord() {
        var sinceUtc = CertificateInventoryCmdletHelpers.ToUtc(SinceUtc);
        var untilUtc = CertificateInventoryCmdletHelpers.ToUtc(UntilUtc);
        if (sinceUtc.HasValue && untilUtc.HasValue && sinceUtc.Value > untilUtc.Value) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-SinceUtc must be less than or equal to -UntilUtc."),
                "InvalidCtHealthDateRange",
                ErrorCategory.InvalidArgument,
                SinceUtc));
            return;
        }

        var monitor = new CertificateMonitor {
            CacheDirectory = CertificateInventoryCmdletHelpers.ResolveCacheDirectory(CacheDirectory),
            PersistInventorySnapshots = false
        };
        var query = new CertificateInventoryNativeCtDiagnosticsHealthQuery {
            SinceUtc = sinceUtc,
            UntilUtc = untilUtc,
            LatestSnapshotOnly = LatestOnly.IsPresent,
            MaxSnapshots = MaxSnapshots,
            AlertThresholds = new CertificateInventoryNativeCtDiagnosticsAlertThresholds {
                MaxFailedDiagnostics = MaxFailed,
                MaxCircuitOpenDiagnostics = MaxCircuitOpen,
                MaxLagAfter = MaxLagAfter
            }
        };
        var health = monitor.BuildInventoryNativeCtDiagnosticsHealth(query);

        var breached = FailOnAnyBreach.IsPresent
            ? health.BreachedSnapshotCount > 0
            : health.Snapshots.Count > 0 && health.Snapshots[0].ThresholdBreached;
        if (breached) {
            foreach (var message in health.LatestBreachMessages) {
                WriteWarning($"Threshold breached: {message}");
            }

            if (FailOnThresholdBreach.IsPresent) {
                ThrowTerminatingError(new ErrorRecord(
                    new InvalidOperationException("Native CT health threshold breach detected."),
                    "NativeCtHealthThresholdBreached",
                    ErrorCategory.InvalidResult,
                    health));
                return;
            }
        }

        WriteObject(health);
    }
}
