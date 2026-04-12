using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state best practice settings functionality.</summary>
public sealed class DesiredStateBestPracticeSettings {
    /// <summary>Gets or sets the checks value.</summary>
    [JsonPropertyName("checks")]
    public HealthCheckType[]? Checks { get; set; }

    /// <summary>Gets or sets the include active mail probes value.</summary>
    [JsonPropertyName("includeActiveMailProbes")]
    public bool IncludeActiveMailProbes { get; set; }

    /// <summary>Executes the resolve checks operation.</summary>
    public HealthCheckType[] ResolveChecks() {
        var set = new HashSet<HealthCheckType>();

        if (Checks != null) {
            foreach (var check in Checks) {
                set.Add(check);
            }
        } else {
            foreach (var check in DesiredStateBestPractices.RecommendedChecks) {
                set.Add(check);
            }
        }

        if (IncludeActiveMailProbes) {
            foreach (var check in DesiredStateBestPractices.ActiveMailChecks) {
                set.Add(check);
            }
        }

        return set.Count == 0 ? Array.Empty<HealthCheckType>() : set.ToArray();
    }
}
