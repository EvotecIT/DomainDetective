using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;
using DomainDetective.Definitions;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateAssessmentSplit {
    public DesiredStateAssessmentSplit(
        IReadOnlyList<Assessment> desired,
        IReadOnlyList<Assessment> bestPractices) {
        DesiredAssessments = desired ?? Array.Empty<Assessment>();
        BestPracticeAssessments = bestPractices ?? Array.Empty<Assessment>();
    }

    public IReadOnlyList<Assessment> DesiredAssessments { get; }
    public IReadOnlyList<Assessment> BestPracticeAssessments { get; }

    public int DesiredInfoCount => DesiredAssessments.Count(a => a?.Severity == AssessmentSeverity.Info);
    public int DesiredWarningCount => DesiredAssessments.Count(a => a?.Severity == AssessmentSeverity.Warning);
    public int DesiredErrorCount => DesiredAssessments.Count(a => a?.Severity == AssessmentSeverity.Error);

    public int BestPracticeInfoCount => BestPracticeAssessments.Count(a => a?.Severity == AssessmentSeverity.Info);
    public int BestPracticeWarningCount => BestPracticeAssessments.Count(a => a?.Severity == AssessmentSeverity.Warning);
    public int BestPracticeErrorCount => BestPracticeAssessments.Count(a => a?.Severity == AssessmentSeverity.Error);

    public bool Conforms => DesiredAssessments.All(a => a == null || a.Severity == AssessmentSeverity.Info);
}

public static class DesiredStateAssessmentSplitter {
    private const string DesiredStateCategory = "DesiredState";

    public static DesiredStateAssessmentSplit Split(
        DesiredStateAnalysis analysis,
        DesiredStateProfile? profile,
        DesiredStateMode mode) {
        if (analysis == null) {
            throw new ArgumentNullException(nameof(analysis));
        }

        var desired = new List<Assessment>();
        var best = new List<Assessment>();
        var assessments = analysis.Assessments ?? new List<Assessment>();

        HashSet<HealthCheckType>? specifiedChecks = null;
        if (mode == DesiredStateMode.BestPracticesForUnspecified && profile != null) {
            var required = DesiredStateConfiguration.GetRequiredChecks(profile);
            specifiedChecks = new HashSet<HealthCheckType>(required);
        }

        foreach (var a in assessments) {
            if (a == null) continue;
            if (string.Equals(a.Category, DesiredStateCategory, StringComparison.OrdinalIgnoreCase)) {
                desired.Add(a);
                continue;
            }

            switch (mode) {
                case DesiredStateMode.BaselineOnly:
                    break;
                case DesiredStateMode.HybridSplit:
                    best.Add(a);
                    break;
                case DesiredStateMode.BestPracticesForUnspecified:
                    if (!IsFromSpecifiedCheck(a, specifiedChecks)) {
                        best.Add(a);
                    }
                    break;
            }
        }

        return new DesiredStateAssessmentSplit(desired, best);
    }

    private static bool IsFromSpecifiedCheck(Assessment assessment, HashSet<HealthCheckType>? specifiedChecks) {
        if (specifiedChecks == null || specifiedChecks.Count == 0) {
            return false;
        }

        if (!TryMapCategoryToCheck(assessment.Category, out var check)) {
            return false;
        }

        return specifiedChecks.Contains(check);
    }

    private static bool TryMapCategoryToCheck(string? category, out HealthCheckType check) {
        check = default;
        if (string.IsNullOrWhiteSpace(category)) {
            return false;
        }

        if (Enum.TryParse(category, true, out check)) {
            return true;
        }

        var normalized = new string(category.Trim()
            .Where(c => !char.IsWhiteSpace(c) && c != '-' && c != '_')
            .ToArray());
        if (normalized.Length == 0) {
            return false;
        }

        return Enum.TryParse(normalized, true, out check);
    }
}
