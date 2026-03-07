using System;
using System.Management.Automation;

namespace DomainDetective.PowerShell;

/// <summary>Builds a certificate inventory summary from persisted monitor snapshots.</summary>
/// <para>Loads stored certificate inventory snapshots and returns aggregate metrics including issuer/service distribution and expiring endpoints.</para>
/// <example>
///   <summary>Build summary for the last 30 days</summary>
///   <code>Get-DDCertificateInventorySummary -SinceUtc (Get-Date).ToUniversalTime().AddDays(-30)</code>
/// </example>
[Cmdlet(VerbsCommon.Get, "DDCertificateInventorySummary")]
[Alias("Get-CertificateInventorySummary")]
[OutputType(typeof(CertificateInventorySummary))]
public sealed class CmdletGetCertificateInventorySummary : PSCmdlet {
    /// <summary>Certificate monitor cache directory containing the inventory folder.</summary>
    [Parameter(Mandatory = false)]
    public string? CacheDirectory { get; set; }

    /// <summary>Only include snapshots captured since this UTC date/time.</summary>
    [Parameter(Mandatory = false)]
    public DateTime? SinceUtc { get; set; }

    /// <summary>Expiring-soon window in days.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int ExpiringWithinDays { get; set; } = 30;

    /// <summary>Maximum number of expiring endpoints returned in summary details.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int MaxExpiringEndpoints { get; set; } = 200;

    /// <summary>Executes the cmdlet.</summary>
    protected override void ProcessRecord() {
        var monitor = new CertificateMonitor {
            CacheDirectory = CertificateInventoryCmdletHelpers.ResolveCacheDirectory(CacheDirectory),
            PersistInventorySnapshots = false
        };

        var since = CertificateInventoryCmdletHelpers.ToUtc(SinceUtc);

        var summary = monitor.BuildInventorySummary(
            sinceUtc: since,
            expiringWithinDays: ExpiringWithinDays,
            maxExpiringEndpoints: MaxExpiringEndpoints);
        WriteObject(summary);
    }
}
