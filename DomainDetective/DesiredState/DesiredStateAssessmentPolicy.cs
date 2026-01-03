using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateAssessmentPolicy {
    [JsonPropertyName("suppressCodes")]
    public string[]? SuppressCodes { get; set; }

    [JsonPropertyName("severityOverrides")]
    public Dictionary<string, AssessmentSeverity>? SeverityOverrides { get; set; }

    public DesiredStateAssessmentPolicy Clone() {
        return new DesiredStateAssessmentPolicy {
            SuppressCodes = SuppressCodes?.ToArray(),
            SeverityOverrides = SeverityOverrides != null
                ? new Dictionary<string, AssessmentSeverity>(SeverityOverrides, StringComparer.OrdinalIgnoreCase)
                : null
        };
    }

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
