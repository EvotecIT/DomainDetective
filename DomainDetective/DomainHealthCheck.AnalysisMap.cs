using System;
using System.Collections.Generic;

namespace DomainDetective;

public partial class DomainHealthCheck {
    /// <summary>
    ///     Creates a dictionary mapping each <see cref="HealthCheckType"/> to
    ///     the corresponding analysis result instance.
    /// </summary>
    /// <returns>
    ///     Read-only dictionary of health check results.
    /// </returns>
    public IReadOnlyDictionary<HealthCheckType, object?> GetAnalysisMap()
    {
        var map = new Dictionary<HealthCheckType, object?>(
            Enum.GetValues(typeof(HealthCheckType)).Length);

        foreach (HealthCheckType check in Enum.GetValues(typeof(HealthCheckType)))
        {
            var property = GetType().GetProperty($"{check}Analysis");
            map[check] = property?.GetValue(this);
        }

        return map;
    }
}
