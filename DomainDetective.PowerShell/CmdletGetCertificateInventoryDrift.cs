using System;
using System.Collections.Generic;
using System.IO;
using System.Management.Automation;

namespace DomainDetective.PowerShell;

/// <summary>Builds endpoint-level certificate drift from persisted inventory snapshots.</summary>
/// <para>Detects certificate rotation and issuer/expiry/service/auth-profile/chain-source drift between observations for each endpoint, including severity and change-kind classification with optional minimum-severity filtering.</para>
/// <example>
///   <summary>Show only changed endpoints from the last 14 days</summary>
///   <code>Get-DDCertificateInventoryDrift -SinceUtc (Get-Date).ToUniversalTime().AddDays(-14) -ChangedOnly</code>
/// </example>
/// <example>
///   <summary>Show only medium and high severity drift rows</summary>
///   <code>Get-DDCertificateInventoryDrift -MinimumSeverity Medium</code>
/// </example>
/// <example>
///   <summary>Show only certificate and auth-profile drift kinds</summary>
///   <code>Get-DDCertificateInventoryDrift -ChangeKind Certificate,AuthProfile</code>
/// </example>
[Cmdlet(VerbsCommon.Get, "DDCertificateInventoryDrift")]
[Alias("Get-CertificateInventoryDrift")]
[OutputType(typeof(CertificateInventoryDriftSummary))]
public sealed class CmdletGetCertificateInventoryDrift : PSCmdlet {
    /// <summary>Certificate monitor cache directory containing the inventory folder.</summary>
    [Parameter(Mandatory = false)]
    public string? CacheDirectory { get; set; }

    /// <summary>Only include snapshots captured since this UTC date/time.</summary>
    [Parameter(Mandatory = false)]
    public DateTime? SinceUtc { get; set; }

    /// <summary>Only return endpoints where drift was observed.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter ChangedOnly { get; set; }

    /// <summary>Maximum endpoint rows returned.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int MaxEndpoints { get; set; } = 200;

    /// <summary>Optional minimum drift severity filter (None is equivalent to omitting this parameter).</summary>
    [Parameter(Mandatory = false)]
    [ValidateSet("None", "Low", "Medium", "High")]
    public string? MinimumSeverity { get; set; }

    /// <summary>Optional list of required drift change kinds.</summary>
    [Parameter(Mandatory = false)]
    [ValidateSet("Certificate", "Issuer", "Expiry", "Service", "AuthProfile", "ChainSource")]
    public string[]? ChangeKind { get; set; }

    /// <summary>Executes the cmdlet.</summary>
    protected override void ProcessRecord() {
        var monitor = new CertificateMonitor {
            CacheDirectory = ResolveCacheDirectory(CacheDirectory),
            PersistInventorySnapshots = false
        };

        DateTimeOffset? since = null;
        if (SinceUtc.HasValue) {
            since = new DateTimeOffset(DateTime.SpecifyKind(SinceUtc.Value, DateTimeKind.Utc));
        }

        List<string>? requiredChangeKinds = null;
        if (ChangeKind != null && ChangeKind.Length > 0) {
            requiredChangeKinds = new List<string>(ChangeKind.Length);
            var dedupe = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var value in ChangeKind) {
                if (!CertificateInventoryDriftAnalyzer.TryNormalizeChangeKind(value, out var normalized) || string.IsNullOrWhiteSpace(normalized)) {
                    throw new PSArgumentException("ChangeKind contains an unsupported value.");
                }

                var normalizedValue = normalized!;
                if (dedupe.Add(normalizedValue)) {
                    requiredChangeKinds.Add(normalizedValue);
                }
            }
        }

        var summary = monitor.BuildInventoryDrift(
            sinceUtc: since,
            changedOnly: ChangedOnly.IsPresent,
            maxEndpoints: MaxEndpoints,
            minimumSeverity: MinimumSeverity,
            requiredChangeKinds: requiredChangeKinds);
        WriteObject(summary);
    }

    private static string ResolveCacheDirectory(string? configured) {
        if (!string.IsNullOrWhiteSpace(configured)) {
            return configured!;
        }

        return Path.Combine(Path.GetTempPath(), "DomainDetective", "cert-monitor");
    }
}
