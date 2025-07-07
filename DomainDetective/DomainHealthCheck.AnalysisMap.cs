using System;
using System.Collections.Generic;
using System.Reflection;

namespace DomainDetective
{
    /// <summary>
    /// Provides helper methods mapping health check types to results.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public partial class DomainHealthCheck {
        private static readonly IReadOnlyDictionary<HealthCheckType, PropertyInfo?> AnalysisPropertyMap;

    static DomainHealthCheck()
    {
        Dictionary<HealthCheckType, PropertyInfo?> map = new();
        foreach (HealthCheckType check in Enum.GetValues(typeof(HealthCheckType)))
        {
            PropertyInfo? property = typeof(DomainHealthCheck).GetProperty($"{check}Analysis");
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
        Dictionary<HealthCheckType, object?> map = new(AnalysisPropertyMap.Count);

        foreach (KeyValuePair<HealthCheckType, PropertyInfo?> kvp in AnalysisPropertyMap)
        {
            map[kvp.Key] = kvp.Value?.GetValue(this);
        }

        return map;
    }
}
}
