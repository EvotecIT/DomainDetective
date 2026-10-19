using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using DomainDetective.Narratives;

namespace DomainDetective.Reports;

/// <summary>
/// Finds the narrative builder for a check result. Some views carry a ready narrative; for the others the matching
/// <c>XxxNarrative.Build(analysis[, assessments])</c> in <c>DomainDetective.Narratives</c> is located by the analysis type.
/// </summary>
internal static class DomainAssessmentNarratives {
    private static readonly ConcurrentDictionary<Type, MethodInfo?> Builders = new();

    private static readonly Lazy<MethodInfo[]> Candidates = new(static () => LoadableTypes(typeof(NarrativeSections).Assembly)
        .Where(static t => t.IsClass && t.IsAbstract && t.IsSealed && t.Namespace == typeof(NarrativeSections).Namespace)
        .SelectMany(static t => t.GetMethods(BindingFlags.Public | BindingFlags.Static))
        .Where(static m => m.Name == "Build" && typeof(NarrativeSections).IsAssignableFrom(m.ReturnType) && m.GetParameters().Length > 0)
        .ToArray());

    // Types that load; a missing optional dependency must not take narratives away from every other check.
    private static IEnumerable<Type> LoadableTypes(Assembly assembly) {
        try {
            return assembly.GetTypes();
        } catch (ReflectionTypeLoadException ex) {
            return ex.Types.Where(static t => t != null)!;
        }
    }

    public static NarrativeSections? Resolve(object view, DomainAssessmentViewReader reader) {
        NarrativeSections? ready = reader.Narrative(view);
        if (HasContent(ready)) return ready;

        object? raw = reader.Raw(view);
        if (raw == null) return null;
        MethodInfo? builder = Builders.GetOrAdd(raw.GetType(), FindBuilder);
        if (builder == null) return null;

        ParameterInfo[] parameters = builder.GetParameters();
        var arguments = new object?[parameters.Length];
        arguments[0] = raw;
        for (int i = 1; i < parameters.Length; i++) {
            if (parameters[i].ParameterType.IsAssignableFrom(typeof(List<Assessment>))) {
                arguments[i] = reader.Assessments(view).ToList();
            } else {
                arguments[i] = parameters[i].HasDefaultValue ? parameters[i].DefaultValue : null;
            }
        }

        try {
            NarrativeSections? built = builder.Invoke(null, arguments) as NarrativeSections;
            return HasContent(built) ? built : null;
        } catch (TargetInvocationException) {
            // A narrative is a nice-to-have; a builder that cannot handle partial data must not break the report.
            return null;
        }
    }

    private static MethodInfo? FindBuilder(Type rawType) {
        // Prefer the overload that also takes assessments, so negatives and remediations reflect this run.
        return Candidates.Value
            .Where(m => m.GetParameters()[0].ParameterType.IsAssignableFrom(rawType))
            .Where(static m => m.GetParameters().Skip(1).All(static p => p.HasDefaultValue || p.ParameterType.IsAssignableFrom(typeof(List<Assessment>))))
            .OrderByDescending(m => m.GetParameters()[0].ParameterType == rawType)
            .ThenByDescending(static m => m.GetParameters().Any(static p => p.ParameterType.IsAssignableFrom(typeof(List<Assessment>))))
            .FirstOrDefault();
    }

    private static bool HasContent(NarrativeSections? narrative)
        => narrative != null && (!string.IsNullOrWhiteSpace(narrative.Introduction) || !string.IsNullOrWhiteSpace(narrative.WhyItMatters) ||
                                 narrative.Remediations.Count > 0 || narrative.Negatives.Count > 0 || narrative.Details.Count > 0);
}
