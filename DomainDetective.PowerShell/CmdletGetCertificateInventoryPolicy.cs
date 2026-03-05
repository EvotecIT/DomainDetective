using System;
using System.Management.Automation;
using DomainDetective.Definitions;
using DomainDetective.DesiredState;

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
/// <example>
///   <summary>Apply policy overrides from a JSON file</summary>
///   <code>Get-DDCertificateInventoryPolicy -BaselineProfile Balanced -PolicyOverridesPath .\policy-overrides.json</code>
/// </example>
/// <example>
///   <summary>Resolve certificate policy from desired state configuration</summary>
///   <code>Get-DDCertificateInventoryPolicy -DesiredStatePath .\desired-state.json -DesiredStateDomain example.com</code>
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

    /// <summary>Optional JSON file path with policy override rules.</summary>
    [Parameter(Mandatory = false)]
    public string? PolicyOverridesPath { get; set; }

    /// <summary>Optional desired state configuration path used to resolve certificate inventory policy settings.</summary>
    [Parameter(Mandatory = false)]
    public string? DesiredStatePath { get; set; }

    /// <summary>Domain/subject used to resolve desired state overrides when -DesiredStatePath is provided.</summary>
    [Parameter(Mandatory = false)]
    public string? DesiredStateDomain { get; set; }

    /// <summary>Optional mail classification used when resolving desired state overrides.</summary>
    [Parameter(Mandatory = false)]
    public MailDomainClassificationCategory? MailClassification { get; set; }

    /// <summary>Executes the cmdlet.</summary>
    protected override void ProcessRecord() {
        CertificateInventoryPolicyOverrides? policyOverrides = null;
        string normalizedProfile = BaselineProfile;
        bool includeCompliant = IncludeCompliant.IsPresent;
        int maxEndpoints = MaxEndpoints;

        if (!string.IsNullOrWhiteSpace(DesiredStatePath)) {
            if (string.IsNullOrWhiteSpace(DesiredStateDomain)) {
                ThrowTerminatingError(new ErrorRecord(
                    new ArgumentException("-DesiredStateDomain is required when -DesiredStatePath is used.", nameof(DesiredStateDomain)),
                    "DesiredStateDomainRequired",
                    ErrorCategory.InvalidArgument,
                    DesiredStatePath));
                return;
            }

            DesiredStateConfiguration configuration;
            try {
                configuration = DesiredStateConfiguration.Load(DesiredStatePath!);
            } catch (Exception ex) {
                ThrowTerminatingError(new ErrorRecord(
                    ex,
                    "DesiredStateLoadFailed",
                    ErrorCategory.InvalidData,
                    DesiredStatePath));
                return;
            }

            ResolvedDesiredStateCertificateInventoryPolicy resolved;
            try {
                resolved = DesiredStateCertificateInventoryPolicyResolver.Resolve(
                    DesiredStateDomain!,
                    configuration,
                    MailClassification,
                    DesiredStatePath);
            } catch (Exception ex) {
                ThrowTerminatingError(new ErrorRecord(
                    ex,
                    "DesiredStateCertificateInventoryResolveFailed",
                    ErrorCategory.InvalidData,
                    DesiredStatePath));
                return;
            }

            if (!resolved.Enabled) {
                WriteVerbose("Certificate inventory desired state is disabled for the resolved profile.");
                return;
            }

            normalizedProfile = resolved.BaselineProfile;
            includeCompliant = resolved.IncludeCompliant;
            maxEndpoints = resolved.MaxEndpoints;
            policyOverrides = resolved.PolicyOverrides;
        } else {
            if (!CertificateInventoryPolicyAnalyzer.TryResolveBaselineProfile(BaselineProfile, out normalizedProfile)) {
                ThrowTerminatingError(new ErrorRecord(
                    new ArgumentException($"-BaselineProfile must be one of: {CertificateInventoryPolicyAnalyzer.BaselineProfileAcceptedValues}.", nameof(BaselineProfile)),
                    "InvalidBaselineProfile",
                    ErrorCategory.InvalidArgument,
                    BaselineProfile));
                return;
            }

            if (!string.IsNullOrWhiteSpace(PolicyOverridesPath)) {
                try {
                    policyOverrides = CertificateInventoryPolicyOverrides.Load(PolicyOverridesPath!);
                } catch (Exception ex) {
                    ThrowTerminatingError(new ErrorRecord(
                        ex,
                        "PolicyOverridesLoadFailed",
                        ErrorCategory.InvalidData,
                        PolicyOverridesPath));
                    return;
                }
            }
        }

        var monitor = new CertificateMonitor {
            CacheDirectory = CertificateInventoryCmdletHelpers.ResolveCacheDirectory(CacheDirectory),
            PersistInventorySnapshots = false
        };

        var policy = monitor.BuildInventoryPolicy(
            sinceUtc: CertificateInventoryCmdletHelpers.ToUtc(SinceUtc),
            baselineProfile: normalizedProfile,
            includeCompliant: includeCompliant,
            maxEndpoints: maxEndpoints,
            policyOverrides: policyOverrides);
        WriteObject(policy);
    }
}
