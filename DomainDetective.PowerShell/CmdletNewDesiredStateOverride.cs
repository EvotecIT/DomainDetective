using System;
using System.Collections.Generic;
using System.Management.Automation;
using DomainDetective.Definitions;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a desired state override (domain and/or classification specific).</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or added to an existing configuration.</para>
/// <example>
///   <summary>Override desired state for parked subdomains</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateOverride -DomainPatterns '*.example.com' -Classifications Parked { New-DDDesiredStateSpf -RequireDenyAll $true; New-DDDesiredStateDmarc -RequireRua $false }</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateOverride")]
[OutputType(typeof(DesiredStateOverride))]
public sealed class CmdletNewDesiredStateOverride : PSCmdlet {
    /// <para>Wildcard domain patterns to match (e.g., *.example.com).</para>
    [Parameter(Mandatory = false)]
    public string[]? DomainPatterns { get; set; }

    /// <para>Mail domain classifications to match (e.g., Sending, Receiving, Parked).</para>
    [Parameter(Mandatory = false)]
    public MailDomainClassificationCategory[]? Classifications { get; set; }

    /// <para>Optional explicit profile fragment to apply to the override.</para>
    [Parameter(Mandatory = false)]
    public DesiredStateProfile? Profile { get; set; }

    /// <para>Optional script block that returns desired state profile fragments to be applied to the override.</para>
    [Parameter(Mandatory = false, Position = 0)]
    public ScriptBlock? ScriptBlock { get; set; }

    /// <summary>Creates an override object that matches on domain patterns and/or classifications.</summary>
    protected override void ProcessRecord() {
        var ov = new DesiredStateOverride {
            Match = new DesiredStateMatch {
                DomainPatterns = DomainPatterns,
                Classifications = Classifications
            },
            Profile = new DesiredStateProfile()
        };

        if (Profile != null) {
            ov.Profile.Apply(Profile);
        }

        if (ScriptBlock != null) {
            var outputs = ScriptBlock.Invoke();
            ApplyDslOutputs(ov.Profile, outputs);
        }

        ov.Profile.Normalize();
        WriteObject(ov);
    }

    private void ApplyDslOutputs(DesiredStateProfile profile, ICollection<PSObject> outputs) {
        if (outputs == null || outputs.Count == 0) return;

        foreach (var ps in outputs) {
            if (ps == null) continue;
            var o = ps.BaseObject;
            if (o == null) continue;

            if (o is DesiredStateProfile fragment) {
                profile.Apply(fragment);
                continue;
            }

            WriteError(new ErrorRecord(
                new InvalidOperationException($"Unsupported object type '{o.GetType().FullName}' returned from New-DDDesiredStateOverride script block."),
                "DesiredStateOverrideDslUnsupportedOutput",
                ErrorCategory.InvalidData,
                o));
        }
    }
}
