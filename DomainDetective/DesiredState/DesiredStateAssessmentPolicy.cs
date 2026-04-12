using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state assessment policy functionality.</summary>
public sealed class DesiredStateAssessmentPolicy {
    /// <summary>Gets or sets the suppress codes value.</summary>
    [JsonPropertyName("suppressCodes")]
    public string[]? SuppressCodes { get; set; }

    /// <summary>Gets or sets the severity overrides value.</summary>
    [JsonPropertyName("severityOverrides")]
    public Dictionary<string, AssessmentSeverity>? SeverityOverrides { get; set; }

    /// <summary>Executes the clone operation.</summary>
    public DesiredStateAssessmentPolicy Clone() {
        return new DesiredStateAssessmentPolicy {
            SuppressCodes = SuppressCodes?.ToArray(),
            SeverityOverrides = SeverityOverrides != null
                ? new Dictionary<string, AssessmentSeverity>(SeverityOverrides, StringComparer.OrdinalIgnoreCase)
                : null
        };
    }

    /// <summary>Executes the apply operation.</summary>
    public void Apply(DesiredStateAssessmentPolicy? overlay) {
        if (overlay == null) return;
        if (overlay.SuppressCodes != null) {
            SuppressCodes = overlay.SuppressCodes.ToArray();
        }
        if (overlay.SeverityOverrides != null) {
            SeverityOverrides = new Dictionary<string, AssessmentSeverity>(overlay.SeverityOverrides, StringComparer.OrdinalIgnoreCase);
        }
    }
}
