using System;
using System.Collections;
using System.Collections.Generic;
using System.Management.Automation;
using DomainDetective.Definitions;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates an assessment policy desired state fragment.</summary>
/// <para>This policy can suppress or re-severity built-in assessment codes to match organization intent.</para>
/// <example>
///   <summary>Suppress a noisy code and downgrade another to Info</summary>
///   <prefix>PS&gt; </prefix>
///   <code>New-DDDesiredStateAssessmentPolicy -SuppressCodes DMARC.Alignment.Mismatch -SeverityOverrides @{ 'DNSSEC.ChainInvalid' = 'Info' }</code>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredStateAssessmentPolicy")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateAssessmentPolicy : PSCmdlet {
    /// <para>Assessment codes to suppress.</para>
    [Parameter(Mandatory = false)]
    public string[]? SuppressCodes { get; set; }

    /// <para>Assessment severity overrides as a hashtable: @{ 'CODE' = 'Warning' }.</para>
    [Parameter(Mandatory = false)]
    public Hashtable? SeverityOverrides { get; set; }

    /// <summary>Creates an assessment policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var overrides = ConvertOverrides(SeverityOverrides);

        var profile = new DesiredStateProfile {
            AssessmentPolicy = new DesiredStateAssessmentPolicy {
                SuppressCodes = SuppressCodes,
                SeverityOverrides = overrides
            }
        };

        WriteObject(profile);
    }

    private static Dictionary<string, AssessmentSeverity>? ConvertOverrides(Hashtable? input) {
        if (input == null || input.Count == 0) return null;

        var result = new Dictionary<string, AssessmentSeverity>(StringComparer.OrdinalIgnoreCase);
        foreach (DictionaryEntry entry in input) {
            if (entry.Key == null) continue;
            var key = entry.Key as string;
            if (key == null) continue;
            key = key.Trim();
            if (key.Length == 0) continue;

            if (entry.Value == null) continue;

            if (entry.Value is AssessmentSeverity severity) {
                result[key] = severity;
                continue;
            }

            if (entry.Value is string s && Enum.TryParse<AssessmentSeverity>(s, ignoreCase: true, out var parsed)) {
                result[key] = parsed;
                continue;
            }

            if (entry.Value is int i && Enum.IsDefined(typeof(AssessmentSeverity), i)) {
                result[key] = (AssessmentSeverity)i;
                continue;
            }

            throw new PSArgumentException($"Unsupported value '{entry.Value}' for SeverityOverrides['{key}']. Expected AssessmentSeverity (or name).");
        }

        return result.Count > 0 ? result : null;
    }
}
