using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates an SMTP AUTH desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
/// <example>
///   <summary>Require STARTTLS with AUTH and disallow legacy mechanisms</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateSmtpAuth -Enabled $true -RequireStartTlsCapabilityWhenAuth $true -DisallowedMechanisms NTLM,CRAM-MD5</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateSmtpAuth")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateSmtpAuth : PSCmdlet {
    /// <para>Enable/disable the SMTP AUTH desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, require at least one SMTP AUTH result to be present.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <para>When true, disallows any SMTP AUTH advertisement on any server.</para>
    [Parameter(Mandatory = false)]
    public bool? DisallowAuthAdvertisement { get; set; }

    /// <para>When specified, all advertised mechanisms must be within this allow list.</para>
    [Parameter(Mandatory = false)]
    public string[]? AllowedMechanisms { get; set; }

    /// <para>When specified, none of the advertised mechanisms may be present.</para>
    [Parameter(Mandatory = false)]
    public string[]? DisallowedMechanisms { get; set; }

    /// <para>When specified, requires at least one of the mechanisms to be present per server advertising AUTH.</para>
    [Parameter(Mandatory = false)]
    public string[]? RequiredMechanismsAnyOf { get; set; }

    /// <para>When true, requires STARTTLS capability to be advertised alongside AUTH.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireStartTlsCapabilityWhenAuth { get; set; }

    /// <summary>Creates an SMTP AUTH policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            SmtpAuth = new DesiredStateSmtpAuthPolicy {
                Enabled = Enabled,
                RequireAtLeastOneResult = RequireAtLeastOneResult,
                DisallowAuthAdvertisement = DisallowAuthAdvertisement,
                AllowedMechanisms = AllowedMechanisms,
                DisallowedMechanisms = DisallowedMechanisms,
                RequiredMechanismsAnyOf = RequiredMechanismsAnyOf,
                RequireStartTlsCapabilityWhenAuth = RequireStartTlsCapabilityWhenAuth
            }
        };

        WriteObject(profile);
    }
}

