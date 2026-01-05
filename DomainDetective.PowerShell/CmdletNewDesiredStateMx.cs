using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates an MX desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Require MX and allow only vendor-specific targets</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateMx -Enabled $true -RequireRecord $true -DisallowNullMx $true -AllowedHostSuffixes protection.outlook.com</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateMx")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateMx : PSCmdlet {
    /// <para>Enable/disable the MX desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, require an MX record to exist.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireRecord { get; set; }

    /// <para>When true, require a null-MX record (RFC 7505).</para>
    [Parameter(Mandatory = false)]
    public bool? RequireNullMx { get; set; }

    /// <para>When true, disallow a null-MX record (RFC 7505).</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowNullMx { get; set; }

    /// <para>When true, requires backup servers (lower priority numbers and redundancy).</para>
    [Parameter(Mandatory = false)]
    public bool? RequireBackupServers { get; set; }

    /// <para>When true, requires IPv6 support for MX targets.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireIpv6Supported { get; set; }

    /// <para>Allowed host suffixes for MX targets (e.g., protection.outlook.com).</para>
    [Parameter(Mandatory = false)]
    public string[]? AllowedHostSuffixes { get; set; }

    /// <para>When true, disallows MX targets that resolve to CNAME.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowCnameTargets { get; set; }

    /// <para>When true, disallows MX targets that are raw IP addresses.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowIpTargets { get; set; }

    /// <para>When true, disallows MX targets that do not exist.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowNonExistentTargets { get; set; }

    /// <para>When true, disallows MX targets that have no A/AAAA addresses.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowNoAddressTargets { get; set; }

    /// <para>When true, disallows MX targets that resolve to localhost.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowLocalhostTargets { get; set; }

    /// <para>When true, requires MX TTL uniformity across authoritative name servers.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireTtlUniform { get; set; }

    /// <para>When true, requires RRSet consistency across authoritative name servers.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireRrsetConsistentAcrossNs { get; set; }

    /// <para>When true, requires target address consistency across authoritative name servers.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireTargetAddressConsistentAcrossNs { get; set; }

    /// <summary>Creates an MX policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var allowedHostSuffixes = DesiredStateCmdletValidation.NormalizeDomainSuffixes(this, nameof(AllowedHostSuffixes), AllowedHostSuffixes);

        var profile = new DesiredStateProfile {
            Mx = new DesiredStateMxPolicy {
                Enabled = Enabled,
                RequireRecord = RequireRecord,
                RequireNullMx = RequireNullMx,
                DisallowNullMx = DisallowNullMx,
                RequireBackupServers = RequireBackupServers,
                RequireIpv6Supported = RequireIpv6Supported,
                AllowedHostSuffixes = allowedHostSuffixes,
                DisallowCnameTargets = DisallowCnameTargets,
                DisallowIpTargets = DisallowIpTargets,
                DisallowNonExistentTargets = DisallowNonExistentTargets,
                DisallowNoAddressTargets = DisallowNoAddressTargets,
                DisallowLocalhostTargets = DisallowLocalhostTargets,
                RequireTtlUniform = RequireTtlUniform,
                RequireRrsetConsistentAcrossNs = RequireRrsetConsistentAcrossNs,
                RequireTargetAddressConsistentAcrossNs = RequireTargetAddressConsistentAcrossNs
            }
        };

        WriteObject(profile);
    }
}
