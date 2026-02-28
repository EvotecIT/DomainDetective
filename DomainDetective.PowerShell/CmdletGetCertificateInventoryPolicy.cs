using System;
using System.IO;
using System.Management.Automation;

namespace DomainDetective.PowerShell;

/// <summary>Evaluates certificate inventory snapshots against baseline policy profiles.</summary>
/// <para>Builds endpoint policy posture with explicit violation codes using Strict, Balanced, or Legacy profiles.</para>
/// <example>
///   <summary>Evaluate the default balanced profile for the last 30 days</summary>
///   <code>Get-DDCertificateInventoryPolicy -SinceUtc (Get-Date).ToUniversalTime().AddDays(-30)</code>
/// </example>
/// <example>
///   <summary>Run strict baseline and include compliant endpoints</summary>
///   <code>Get-DDCertificateInventoryPolicy -BaselineProfile Strict -IncludeCompliant -MaxEndpoints 500</code>
/// </example>
[Cmdlet(VerbsCommon.Get, "DDCertificateInventoryPolicy")]
[Alias("Get-CertificateInventoryPolicy")]
[OutputType(typeof(CertificateInventoryPolicySummary))]
public sealed class CmdletGetCertificateInventoryPolicy : PSCmdlet {
    /// <summary>Certificate monitor cache directory containing the inventory folder.</summary>
    [Parameter(Mandatory = false)]
    public string? CacheDirectory { get; set; }

    /// <summary>Only include snapshots captured since this UTC date/time.</summary>
    [Parameter(Mandatory = false)]
    public DateTime? SinceUtc { get; set; }

    /// <summary>Policy baseline profile to evaluate (Strict, Balanced, Legacy).</summary>
    [Parameter(Mandatory = false)]
    [ValidateSet("Strict", "Balanced", "Legacy")]
    public string BaselineProfile { get; set; } = "Balanced";

    /// <summary>Include endpoints with no policy violations.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter IncludeCompliant { get; set; }

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

        DateTimeOffset? since = null;
        if (SinceUtc.HasValue) {
            since = new DateTimeOffset(DateTime.SpecifyKind(SinceUtc.Value, DateTimeKind.Utc));
        }

        var policy = monitor.BuildInventoryPolicy(
            sinceUtc: since,
            baselineProfile: normalizedProfile,
            includeCompliant: IncludeCompliant.IsPresent,
            maxEndpoints: MaxEndpoints);
        WriteObject(policy);
    }

    private static string ResolveCacheDirectory(string? configured) {
        if (!string.IsNullOrWhiteSpace(configured)) {
            return configured!;
        }

        return Path.Combine(Path.GetTempPath(), "DomainDetective", "cert-monitor");
    }
}
