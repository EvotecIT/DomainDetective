using System;
using System.Collections.Generic;
using System.Reflection;

namespace DomainDetective
{
    public partial class DomainHealthCheck {
        private static readonly IReadOnlyDictionary<HealthCheckType, PropertyInfo?> AnalysisPropertyMap;

    static DomainHealthCheck()
    {
        var map = new Dictionary<HealthCheckType, PropertyInfo?>();
        foreach (HealthCheckType check in Enum.GetValues(typeof(HealthCheckType)))
        {
            var property = typeof(DomainHealthCheck).GetProperty($"{check}Analysis");
            map[check] = property;
        }

        AnalysisPropertyMap = map;
    }
    /// <summary>
    ///     Creates a dictionary mapping each <see cref="HealthCheckType"/> to
    ///     the corresponding analysis result instance.
    /// </summary>
    /// <returns>
    ///     Read-only dictionary of health check results.
    /// </returns>
    public IReadOnlyDictionary<HealthCheckType, object?> GetAnalysisMap()
    {
        var map = new Dictionary<HealthCheckType, object?>(AnalysisPropertyMap.Count);

        foreach (var kvp in AnalysisPropertyMap)
        {
            map[kvp.Key] = kvp.Value?.GetValue(this);
        }

        return map;
    }
}
}
