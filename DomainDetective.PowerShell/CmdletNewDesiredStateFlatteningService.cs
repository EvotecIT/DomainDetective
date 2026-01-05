using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a flattening service desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
[Cmdlet(VerbsCommon.New, "DDDesiredStateFlatteningService")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateFlatteningService : PSCmdlet {
    /// <para>Enable/disable the flattening service desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, requires the apex to publish a CNAME record.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireCnameRecord { get; set; }

    /// <para>When true, disallows an apex CNAME record.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowCnameRecord { get; set; }

    /// <para>When true, requires the apex CNAME to point to a known flattening service.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireFlatteningService { get; set; }

    /// <para>When true, disallows the use of a known flattening service.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowFlatteningService { get; set; }

    /// <para>Allowed CNAME target suffixes (vendor-specific baselining).</para>
    [Parameter(Mandatory = false)]
    public string[]? AllowedTargetSuffixes { get; set; }

    /// <summary>Creates a flattening service policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var allowedTargetSuffixes = DesiredStateCmdletValidation.NormalizeDomainSuffixes(this, nameof(AllowedTargetSuffixes), AllowedTargetSuffixes);

        var profile = new DesiredStateProfile {
            FlatteningService = new DesiredStateFlatteningServicePolicy {
                Enabled = Enabled,
                RequireCnameRecord = RequireCnameRecord,
                DisallowCnameRecord = DisallowCnameRecord,
                RequireFlatteningService = RequireFlatteningService,      
                DisallowFlatteningService = DisallowFlatteningService,    
                AllowedTargetSuffixes = allowedTargetSuffixes
            }
        };

        WriteObject(profile);
    }
}
