using System;
using System.IO;
using System.Management.Automation;

namespace DomainDetective.PowerShell;

/// <summary>Builds endpoint-level certificate policy drift between two persisted inventory snapshots.</summary>
/// <para>Compares baseline-policy compliance between snapshots and reports added/resolved violation codes per endpoint.</para>
/// <example>
///   <summary>Compare latest two snapshots with balanced baseline</summary>
///   <code>Get-DDCertificateInventoryPolicyDrift -ChangedOnly</code>
/// </example>
/// <example>
///   <summary>Compare selected snapshot timestamps with strict baseline</summary>
///   <code>Get-DDCertificateInventoryPolicyDrift -BaselineProfile Strict -PreviousUtc (Get-Date).ToUniversalTime().AddDays(-7) -CurrentUtc (Get-Date).ToUniversalTime()</code>
/// </example>
[Cmdlet(VerbsCommon.Get, "DDCertificateInventoryPolicyDrift")]
[Alias("Get-CertificateInventoryPolicyDrift")]
[OutputType(typeof(CertificateInventoryPolicyDriftSummary))]
public sealed class CmdletGetCertificateInventoryPolicyDrift : PSCmdlet {
    /// <summary>Certificate monitor cache directory containing the inventory folder.</summary>
    [Parameter(Mandatory = false)]
    public string? CacheDirectory { get; set; }

    /// <summary>Only include snapshots captured since this UTC date/time.</summary>
    [Parameter(Mandatory = false)]
    public DateTime? SinceUtc { get; set; }

    /// <summary>Optional previous snapshot selector (latest snapshot at or before this UTC time).</summary>
    [Parameter(Mandatory = false)]
    public DateTime? PreviousUtc { get; set; }

    /// <summary>Optional current snapshot selector (latest snapshot at or before this UTC time).</summary>
    [Parameter(Mandatory = false)]
    public DateTime? CurrentUtc { get; set; }

    /// <summary>Policy baseline profile to evaluate (Strict, Balanced, Legacy).</summary>
    [Parameter(Mandatory = false)]
    [ValidateSet("Strict", "Balanced", "Legacy")]
    public string BaselineProfile { get; set; } = "Balanced";

    /// <summary>Only return endpoint rows with detected policy drift.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter ChangedOnly { get; set; }

    /// <summary>Maximum endpoint rows returned.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int MaxEndpoints { get; set; } = 300;

    /// <summary>Executes the cmdlet.</summary>
    protected override void ProcessRecord() {
        if (!CertificateInventoryPolicyAnalyzer.TryResolveBaselineProfile(BaselineProfile, out var normalizedProfile)) {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException($"-BaselineProfile must be one of: {CertificateInventoryPolicyAnalyzer.BaselineProfileAcceptedValues}.", nameof(BaselineProfile)),
                "InvalidBaselineProfile",
                ErrorCategory.InvalidArgument,
                BaselineProfile));
            return;
        }

        var monitor = new CertificateMonitor {
            CacheDirectory = ResolveCacheDirectory(CacheDirectory),
            PersistInventorySnapshots = false
        };

        var summary = monitor.BuildInventoryPolicyDrift(
            sinceUtc: ToUtc(SinceUtc),
            baselineProfile: normalizedProfile,
            previousCapturedAtUtc: ToUtc(PreviousUtc),
            currentCapturedAtUtc: ToUtc(CurrentUtc),
            changedOnly: ChangedOnly.IsPresent,
            maxEndpoints: MaxEndpoints);
        WriteObject(summary);
    }

    private static DateTimeOffset? ToUtc(DateTime? value) {
        if (!value.HasValue) {
            return null;
        }

        var dt = value.Value;
        if (dt.Kind == DateTimeKind.Unspecified) {
            dt = DateTime.SpecifyKind(dt, DateTimeKind.Utc);
        }

        return dt.ToUniversalTime();
    }

    private static string ResolveCacheDirectory(string? configured) {
        if (!string.IsNullOrWhiteSpace(configured)) {
            return configured!;
        }

        return Path.Combine(Path.GetTempPath(), "DomainDetective", "cert-monitor");
    }
}
