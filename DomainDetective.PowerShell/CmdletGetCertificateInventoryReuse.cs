using System;
using System.Management.Automation;

namespace DomainDetective.PowerShell;

/// <summary>Builds certificate reuse and endpoint assignment mapping from persisted inventory snapshots.</summary>
/// <para>Groups latest endpoint observations by certificate identity to show where each certificate is assigned and whether it spans multiple services.</para>
/// <example>
///   <summary>Show reused certificates from the last 30 days</summary>
///   <code>Get-DDCertificateInventoryReuse -SinceUtc (Get-Date).ToUniversalTime().AddDays(-30)</code>
/// </example>
/// <example>
///   <summary>Include singleton certificates for full assignment inventory</summary>
///   <code>Get-DDCertificateInventoryReuse -IncludeSingletons -MinEndpoints 1</code>
/// </example>
[Cmdlet(VerbsCommon.Get, "DDCertificateInventoryReuse")]
[Alias("Get-CertificateInventoryReuse")]
[OutputType(typeof(CertificateInventoryReuseSummary))]
public sealed class CmdletGetCertificateInventoryReuse : PSCmdlet {
    /// <summary>Certificate monitor cache directory containing the inventory folder.</summary>
    [Parameter(Mandatory = false)]
    public string? CacheDirectory { get; set; }

    /// <summary>Only include snapshots captured since this UTC date/time.</summary>
    [Parameter(Mandatory = false)]
    public DateTime? SinceUtc { get; set; }

    /// <summary>Include certificates assigned to only one endpoint.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter IncludeSingletons { get; set; }

    /// <summary>Minimum endpoint count required per certificate row.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(1, int.MaxValue)]
    public int MinEndpoints { get; set; } = 2;

    /// <summary>Maximum certificate rows returned.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int MaxCertificates { get; set; } = 300;

    /// <summary>Maximum endpoint references returned per certificate row.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int MaxEndpointsPerCertificate { get; set; } = 30;

    /// <summary>Executes the cmdlet.</summary>
    protected override void ProcessRecord() {
        var monitor = new CertificateMonitor {
            CacheDirectory = CertificateInventoryCmdletHelpers.ResolveCacheDirectory(CacheDirectory),
            PersistInventorySnapshots = false
        };

        var since = CertificateInventoryCmdletHelpers.ToUtc(SinceUtc);

        var reuse = monitor.BuildInventoryReuse(
            sinceUtc: since,
            includeSingleEndpointCertificates: IncludeSingletons.IsPresent,
            minEndpointCount: MinEndpoints,
            maxCertificates: MaxCertificates,
            maxEndpointsPerCertificate: MaxEndpointsPerCertificate);
        WriteObject(reuse);
    }
}
