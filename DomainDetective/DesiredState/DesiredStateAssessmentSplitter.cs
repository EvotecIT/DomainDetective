using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;
using DomainDetective.Definitions;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state assessment split functionality.</summary>
public sealed class DesiredStateAssessmentSplit {
    /// <summary>Initializes a new instance of the DesiredStateAssessmentSplit class.</summary>
    public DesiredStateAssessmentSplit(
        IReadOnlyList<Assessment> desired,
        IReadOnlyList<Assessment> bestPractices) {
        DesiredAssessments = desired ?? Array.Empty<Assessment>();
        BestPracticeAssessments = bestPractices ?? Array.Empty<Assessment>();
    }

    /// <summary>Gets the desired assessments value.</summary>
    public IReadOnlyList<Assessment> DesiredAssessments { get; }
    /// <summary>Gets the best practice assessments value.</summary>
    public IReadOnlyList<Assessment> BestPracticeAssessments { get; }

    /// <summary>Represents the desired info count value.</summary>
    public int DesiredInfoCount => DesiredAssessments.Count(a => a?.Severity == AssessmentSeverity.Info);
    /// <summary>Represents the desired warning count value.</summary>
    public int DesiredWarningCount => DesiredAssessments.Count(a => a?.Severity == AssessmentSeverity.Warning);
    /// <summary>Represents the desired error count value.</summary>
    public int DesiredErrorCount => DesiredAssessments.Count(a => a?.Severity == AssessmentSeverity.Error);

    /// <summary>Represents the best practice info count value.</summary>
    public int BestPracticeInfoCount => BestPracticeAssessments.Count(a => a?.Severity == AssessmentSeverity.Info);
    /// <summary>Represents the best practice warning count value.</summary>
    public int BestPracticeWarningCount => BestPracticeAssessments.Count(a => a?.Severity == AssessmentSeverity.Warning);
    /// <summary>Represents the best practice error count value.</summary>
    public int BestPracticeErrorCount => BestPracticeAssessments.Count(a => a?.Severity == AssessmentSeverity.Error);

    /// <summary>Represents the conforms value.</summary>
    public bool Conforms => DesiredAssessments.All(a => a == null || a.Severity == AssessmentSeverity.Info);
}

/// <summary>Provides desired state assessment splitter functionality.</summary>
public static class DesiredStateAssessmentSplitter {
    private const string DesiredStateCategory = "DesiredState";

    /// <summary>Executes the split operation.</summary>
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

        var normalized = new string(category!.Trim()
            .Where(c => !char.IsWhiteSpace(c) && c != '-' && c != '_')
            .ToArray());
        if (normalized.Length == 0) {
            return false;
        }

        return Enum.TryParse(normalized, true, out check);
    }
}
