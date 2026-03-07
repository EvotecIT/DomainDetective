using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateBestPracticeSettings {
    [JsonPropertyName("checks")]
    public HealthCheckType[]? Checks { get; set; }

    [JsonPropertyName("includeActiveMailProbes")]
    public bool IncludeActiveMailProbes { get; set; }

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
