using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace DomainDetective.Views;

public static partial class Converters {
    private static readonly ConcurrentDictionary<Type, MethodInfo?> AnalysisConverters = new();

    /// <summary>
    /// Converts the results of a verification run into view objects, one or more per check, ready for the report
    /// renderers (<c>AssessmentHtmlReport</c>, Word, Excel, Markdown and JSON).
    /// </summary>
    /// <param name="health">Health check that ran.</param>
    /// <param name="checks">Checks to convert. Defaults to the checks the last <c>Verify</c> call ran.</param>
    /// <param name="errors">Optional collection that receives execution and conversion failures. Execution failures retain assessment evidence instead of unfinished analysis results.</param>
    /// <returns>View objects in check order.</returns>
    public static IReadOnlyList<object> ConvertChecks(DomainHealthCheck health, IEnumerable<HealthCheckType>? checks = null, ICollection<string>? errors = null) {
        if (health == null) throw new ArgumentNullException(nameof(health));
        var items = new List<object>();
        var converted = new HashSet<object>(ReferenceEqualityComparer.Instance);
        foreach (HealthCheckType check in (checks ?? health.LastVerifiedChecks).Distinct()) {
            Assessment? failure = health.GetCheckFailure(check);
            if (failure != null) {
                errors?.Add(failure.Message);
                items.Add(new CheckFailureInfo(check, failure));
                continue;
            }
            try {
                foreach (object view in ConvertCheck(health, check, converted)) items.Add(view);
            } catch (Exception ex) when (ex is not OutOfMemoryException) {
                Exception cause = ex is TargetInvocationException { InnerException: { } inner } ? inner : ex;
                errors?.Add($"{check}: {cause.GetType().Name}: {cause.Message}");
            }
        }
        return items;
    }

    /// <summary>Analysis area (Mail, DNS, Web, ...) a check belongs to.</summary>
    /// <param name="check">Health check.</param>
    /// <returns>The area.</returns>
    public static AnalysisArea AreaFor(HealthCheckType check) => AreaForKind(check);

    private static IEnumerable<object> ConvertCheck(DomainHealthCheck health, HealthCheckType check, HashSet<object> converted) {
        switch (check) {
            case HealthCheckType.DNSPROPAGATION:
                // One view per record type, as the renderers expect.
                return health.DnsPropagationSet?.Items.Select(static item => (object)Convert(item)) ?? Enumerable.Empty<object>();
            case HealthCheckType.MESSAGEHEADER:
                // Message header analysis describes one message, not the domain; it is reported on its own.
                return Enumerable.Empty<object>();
            case HealthCheckType.HTTP when string.IsNullOrWhiteSpace(health.HttpAnalysis.Subject):
            case HealthCheckType.IPENRICHMENT when string.IsNullOrWhiteSpace(health.IpEnrichmentAnalysis.Subject):
            case HealthCheckType.AGENTREADINESS when string.IsNullOrWhiteSpace(health.AgentReadinessAnalysis.Subject):
            case HealthCheckType.SITEMAP when string.IsNullOrWhiteSpace(health.SitemapAnalysis.Subject):
                // These analyses only name a subject once they reached the site; an empty one did not run.
                return Enumerable.Empty<object>();
        }

        object? analysis = health.GetAnalysisFor(check);
        // Several checks share one analysis (NS and DELEGATION); convert it once.
        if (analysis == null || !converted.Add(analysis)) return Enumerable.Empty<object>();
        // Some checks keep a finished view rather than an analysis (WEBSITE combines HTTP and certificate results).
        if (analysis.GetType().Namespace == typeof(Converters).Namespace) return new[] { analysis };
        MethodInfo? converter = AnalysisConverters.GetOrAdd(analysis.GetType(), FindAnalysisConverter);
        if (converter == null) throw new NotSupportedException($"No report view exists for {analysis.GetType().Name}.");

        object? result = converter.Invoke(null, BuildArguments(converter, analysis));
        return result switch {
            null => Enumerable.Empty<object>(),
            string => new[] { result },
            IEnumerable sequence => sequence.Cast<object?>().Where(static v => v != null).Cast<object>().ToList(),
            _ => new[] { result }
        };
    }

    private static MethodInfo? FindAnalysisConverter(Type analysisType) {
        return typeof(Converters).GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Where(static m => m.Name == nameof(Convert) && !m.IsGenericMethodDefinition)
            .Where(m => {
                ParameterInfo[] parameters = m.GetParameters();
                return parameters.Length > 0 && parameters[0].ParameterType.IsAssignableFrom(analysisType) &&
                       parameters[0].ParameterType != typeof(object) && parameters.Skip(1).All(static p => p.HasDefaultValue);
            })
            .OrderByDescending(m => m.GetParameters()[0].ParameterType == analysisType)
            .ThenBy(static m => m.GetParameters().Length)
            .FirstOrDefault();
    }

    private static object?[] BuildArguments(MethodInfo converter, object analysis) {
        ParameterInfo[] parameters = converter.GetParameters();
        var arguments = new object?[parameters.Length];
        arguments[0] = analysis;
        for (int i = 1; i < parameters.Length; i++) arguments[i] = parameters[i].DefaultValue;
        return arguments;
    }

    private sealed class ReferenceEqualityComparer : IEqualityComparer<object> {
        public static readonly ReferenceEqualityComparer Instance = new();
        public new bool Equals(object? x, object? y) => ReferenceEquals(x, y);
        public int GetHashCode(object obj) => System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(obj);
    }
}
