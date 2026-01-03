using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a DKIM desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Require two selectors and a minimum key length</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateDkim -Enabled $true -RequiredSelectors selector1,selector2 -MinKeyBits 2048</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateDkim")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateDkim : PSCmdlet {
    /// <para>Enable/disable the DKIM desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, requires at least one DKIM selector to be analyzed.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAtLeastOneSelector { get; set; }

    /// <para>When true, requires DKIM records to start with v=DKIM1.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireStartsCorrectly { get; set; }

    /// <para>When true, requires DKIM records to contain a non-empty p= public key.</para>
    [Parameter(Mandatory = false)]
    public bool? RequirePublicKey { get; set; }

    /// <para>When true, requires DKIM public keys to be parseable/valid.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireValidPublicKey { get; set; }

    /// <para>When true, requires DKIM key type to be recognized (rsa/ed25519).</para>
    [Parameter(Mandatory = false)]
    public bool? RequireValidKeyType { get; set; }

    /// <para>Selectors that must exist and publish DKIM records (organization-specific).</para>
    [Parameter(Mandatory = false)]
    public string[]? RequiredSelectors { get; set; }

    /// <para>Minimum accepted key length in bits for selectors.</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, 16384)]
    public int? MinKeyBits { get; set; }

    /// <para>When true, disallows weak RSA keys (under 2048 bits).</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowWeakKeys { get; set; }

    /// <para>Maximum allowed key age in days when a creation date can be inferred.</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MaxKeyAgeDays { get; set; }

    /// <para>When true, disallows deprecated DKIM tags/values.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowDeprecatedTags { get; set; }

    /// <para>When true, disallows invalid DKIM flags.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowInvalidFlags { get; set; }

    /// <para>When true, disallows unknown canonicalization modes.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowUnknownCanonicalizationModes { get; set; }

    /// <para>When true, disallows invalid canonicalization strings (when c= is present).</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowInvalidCanonicalization { get; set; }

    /// <para>Allowed domain suffixes for selector CNAME targets (vendor-hosted DKIM).</para>
    [Parameter(Mandatory = false)]
    public string[]? AllowedCnameTargetSuffixes { get; set; }

    /// <summary>Creates a DKIM policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            Dkim = new DesiredStateDkimPolicy {
                Enabled = Enabled,
                RequireAtLeastOneSelector = RequireAtLeastOneSelector,
                RequireStartsCorrectly = RequireStartsCorrectly,
                RequirePublicKey = RequirePublicKey,
                RequireValidPublicKey = RequireValidPublicKey,
                RequireValidKeyType = RequireValidKeyType,
                RequiredSelectors = RequiredSelectors,
                MinKeyBits = MinKeyBits,
                DisallowWeakKeys = DisallowWeakKeys,
                MaxKeyAgeDays = MaxKeyAgeDays,
                DisallowDeprecatedTags = DisallowDeprecatedTags,
                DisallowInvalidFlags = DisallowInvalidFlags,
                DisallowUnknownCanonicalizationModes = DisallowUnknownCanonicalizationModes,
                DisallowInvalidCanonicalization = DisallowInvalidCanonicalization,
                AllowedCnameTargetSuffixes = AllowedCnameTargetSuffixes
            }
        };

        WriteObject(profile);
    }
}
