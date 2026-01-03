using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates an MTA-STS desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Require enforce mode and a minimum max_age</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateMtasts -Enabled $true -RequireRecord $true -RequireEnforce $true -MinMaxAge 86400</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateMtasts")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateMtasts : PSCmdlet {
    /// <para>Enable/disable the MTA-STS desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, require an MTA-STS DNS record to exist.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireRecord { get; set; }

    /// <para>When true, requires the _mta-sts TXT record to be syntactically valid (v=STSv1; id=...).</para>
    [Parameter(Mandatory = false)]
    public bool? RequireDnsRecordValid { get; set; }

    /// <para>When true, requires the HTTPS policy file to be fetched successfully.</para>
    [Parameter(Mandatory = false)]
    public bool? RequirePolicyPresent { get; set; }

    /// <para>When true, requires the HTTPS policy file to be valid and consistent with the DNS bootstrap record.</para>
    [Parameter(Mandatory = false)]
    public bool? RequirePolicyValid { get; set; }

    /// <para>When true, disallows duplicate fields in either the DNS record or the policy file.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowDuplicateFields { get; set; }

    /// <para>When true, require MTA-STS policy mode to be enforce.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireEnforce { get; set; }

    /// <para>Minimum accepted max_age value (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MinMaxAge { get; set; }

    /// <para>When true, require policy MX patterns to align with discovered MX targets.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireMxAligned { get; set; }

    /// <summary>Creates an MTA-STS policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            Mtasts = new DesiredStateMtastsPolicy {
                Enabled = Enabled,
                RequireRecord = RequireRecord,
                RequireDnsRecordValid = RequireDnsRecordValid,
                RequirePolicyPresent = RequirePolicyPresent,
                RequirePolicyValid = RequirePolicyValid,
                DisallowDuplicateFields = DisallowDuplicateFields,
                RequireEnforce = RequireEnforce,
                MinMaxAge = MinMaxAge,
                RequireMxAligned = RequireMxAligned
            }
        };

        WriteObject(profile);
    }
}
