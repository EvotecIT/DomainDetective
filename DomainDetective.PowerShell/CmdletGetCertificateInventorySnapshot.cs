using System;
using System.Collections.Generic;
using System.Management.Automation;

namespace DomainDetective.PowerShell;

/// <summary>Reads persisted certificate inventory snapshots from local storage.</summary>
/// <para>Returns raw snapshot objects so you can inspect or post-process captured endpoint certificate data directly.</para>
/// <example>
///   <summary>Read the latest snapshot</summary>
///   <code>Get-DDCertificateInventorySnapshot -Latest</code>
/// </example>
/// <example>
///   <summary>Read snapshot metadata only for the last 7 days</summary>
///   <code>Get-DDCertificateInventorySnapshot -SinceUtc (Get-Date).ToUniversalTime().AddDays(-7) -WithoutEntries</code>
/// </example>
[Cmdlet(VerbsCommon.Get, "DDCertificateInventorySnapshot")]
[OutputType(typeof(CertificateInventorySnapshot))]
public sealed class CmdletGetCertificateInventorySnapshot : PSCmdlet {
    /// <summary>Certificate monitor cache directory containing the inventory folder.</summary>
    [Parameter(Mandatory = false)]
    public string? CacheDirectory { get; set; }

    /// <summary>Only include snapshots captured since this UTC date/time.</summary>
    [Parameter(Mandatory = false)]
    public DateTime? SinceUtc { get; set; }

    /// <summary>Only include snapshots captured up to this UTC date/time.</summary>
    [Parameter(Mandatory = false)]
    public DateTime? UntilUtc { get; set; }

    /// <summary>Maximum number of snapshots returned (latest N). Use 0 for unlimited.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int MaxSnapshots { get; set; } = 200;

    /// <summary>Return only the latest snapshot after applying filters.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter Latest { get; set; }

    /// <summary>When set, strips endpoint entries and returns snapshot metadata only.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter WithoutEntries { get; set; }

    /// <summary>Executes the cmdlet.</summary>
    protected override void ProcessRecord() {
        var sinceUtc = CertificateInventoryCmdletHelpers.ToUtc(SinceUtc);
        var untilUtc = CertificateInventoryCmdletHelpers.ToUtc(UntilUtc);
        if (sinceUtc.HasValue && untilUtc.HasValue && sinceUtc.Value > untilUtc.Value) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("-SinceUtc must be less than or equal to -UntilUtc."),
                "InvalidSnapshotDateRange",
                ErrorCategory.InvalidArgument,
                SinceUtc));
            return;
        }

        var monitor = new CertificateMonitor {
            CacheDirectory = CertificateInventoryCmdletHelpers.ResolveCacheDirectory(CacheDirectory),
            PersistInventorySnapshots = false
        };

        var snapshots = monitor.LoadInventorySnapshots(
            sinceUtc: sinceUtc,
            untilUtc: untilUtc,
            maxSnapshots: MaxSnapshots,
            latestOnly: Latest.IsPresent);

        if (!WithoutEntries.IsPresent) {
            WriteObject(snapshots, true);
            return;
        }

        var metadataOnly = new List<CertificateInventorySnapshot>(snapshots.Count);
        foreach (var snapshot in snapshots) {
            metadataOnly.Add(new CertificateInventorySnapshot {
                CapturedAtUtc = snapshot.CapturedAtUtc,
                Port = snapshot.Port,
                Entries = new List<CertificateInventoryEntry>()
            });
        }
        WriteObject(metadataOnly, true);
    }
}
