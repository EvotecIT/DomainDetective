using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

public sealed class RecommendationView {
    public string Code { get; init; } = string.Empty;
    public RecommendationAdvice Advice { get; init; } = new RecommendationAdvice();
    public AssessmentSeverity MaxSeverity { get; init; }
    public string Category { get; init; } = string.Empty;
    public IReadOnlyCollection<string> Targets { get; init; } = Array.Empty<string>();
    public IReadOnlyList<Assessment> Instances { get; init; } = Array.Empty<Assessment>();
}

/// <summary>
/// Provides helpers to convert Assessments into actionable recommendation views.
/// Lives in the core library for reuse by CLI, PowerShell and reports.
/// </summary>
public static class RecommendationEngine {
    /// <summary>
    /// Returns unique recommendations (by code) for a set of assessments.
    /// Falls back to assessment message for unmapped codes.
    /// </summary>
    public static IReadOnlyList<RecommendationAdvice> From(IEnumerable<Assessment> assessments) {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var list = new List<RecommendationAdvice>();
        foreach (var a in assessments) {
            var code = a.Code ?? string.Empty;
            if (code.Length == 0) {
                // Skip uncoded assessments from uniqueness, but still include as-is
                list.Add(RecommendationCatalog.For(a));
                continue;
            }
            if (set.Add(code)) {
                list.Add(RecommendationCatalog.For(a));
            }
        }
        return list;
    }

    /// <summary>
    /// Groups assessments by code and returns a summary view of each recommendation
    /// with severity, category and instance targets.
    /// </summary>
    public static IReadOnlyList<RecommendationView> GroupByCode(IEnumerable<Assessment> assessments) {
        var groups = assessments
            .GroupBy(a => a.Code ?? string.Empty, StringComparer.OrdinalIgnoreCase);
        var result = new List<RecommendationView>();
        foreach (var g in groups) {
            var instances = g.ToList();
            var first = instances[0];
            var advice = RecommendationCatalog.For(first);
            var maxSeverity = instances.Max(a => a.Severity);
            var category = first.Category ?? string.Empty;
            var targets = instances
                .Select(a => a.Target)
                .Where(t => !string.IsNullOrWhiteSpace(t))
                .Select(t => t!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            result.Add(new RecommendationView {
                Code = g.Key,
                Advice = advice,
                MaxSeverity = maxSeverity,
                Category = category,
                Targets = targets,
                Instances = instances
            });
        }
        return result
            .OrderByDescending(r => r.MaxSeverity)
            .ThenBy(r => r.Category)
            .ThenBy(r => r.Code)
            .ToList();
    }
}

