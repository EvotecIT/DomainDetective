using System;
using System.Management.Automation;

namespace DomainDetective.PowerShell;

/// <summary>Compares two persisted certificate inventory snapshots and returns endpoint deltas.</summary>
/// <para>When snapshot timestamps are not specified, the cmdlet compares the latest snapshot with the one before it.</para>
/// <example>
///   <summary>Compare latest two snapshots</summary>
///   <code>Get-DDCertificateInventoryDiff</code>
/// </example>
/// <example>
///   <summary>Compare a specific window and include unchanged rows</summary>
///   <code>Get-DDCertificateInventoryDiff -PreviousUtc (Get-Date).ToUniversalTime().AddDays(-7) -CurrentUtc (Get-Date).ToUniversalTime() -IncludeUnchanged</code>
/// </example>
[Cmdlet(VerbsCommon.Get, "DDCertificateInventoryDiff")]
[Alias("Get-CertificateInventoryDiff")]
[OutputType(typeof(CertificateInventoryDiffSummary))]
public sealed class CmdletGetCertificateInventoryDiff : PSCmdlet {
    /// <summary>Certificate monitor cache directory containing the inventory folder.</summary>
    [Parameter(Mandatory = false)]
    public string? CacheDirectory { get; set; }

    /// <summary>Only include snapshots captured since this UTC date/time.</summary>
    [Parameter(Mandatory = false)]
    public DateTime? SinceUtc { get; set; }

    /// <summary>Timestamp selector for the previous snapshot.</summary>
    [Parameter(Mandatory = false)]
    public DateTime? PreviousUtc { get; set; }

    /// <summary>Timestamp selector for the current snapshot.</summary>
    [Parameter(Mandatory = false)]
    public DateTime? CurrentUtc { get; set; }

    /// <summary>Include unchanged endpoints in result rows.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter IncludeUnchanged { get; set; }

    /// <summary>Maximum endpoint rows returned.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int MaxEndpoints { get; set; } = 500;

    /// <summary>Executes the cmdlet.</summary>
    protected override void ProcessRecord() {
        var monitor = new CertificateMonitor {
            CacheDirectory = CertificateInventoryCmdletHelpers.ResolveCacheDirectory(CacheDirectory),
            PersistInventorySnapshots = false
        };

        var since = CertificateInventoryCmdletHelpers.ToUtc(SinceUtc);

        var previous = CertificateInventoryCmdletHelpers.ToUtc(PreviousUtc);

        var current = CertificateInventoryCmdletHelpers.ToUtc(CurrentUtc);

        var diff = monitor.BuildInventoryDiff(
            sinceUtc: since,
            previousCapturedAtUtc: previous,
            currentCapturedAtUtc: current,
            includeUnchanged: IncludeUnchanged.IsPresent,
            maxEndpoints: MaxEndpoints);
        WriteObject(diff);
    }
}
