using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Toolbox.Components.Tools.Overview;

internal static class OverviewAssessmentPresentation {
    public static IReadOnlyList<DomainOverviewDetailCardView> BuildSummaryCards(IReadOnlyList<DomainDetective.Assessment>? assessments) {
        if (assessments == null || assessments.Count == 0) {
            return Array.Empty<DomainOverviewDetailCardView>();
        }

        return new[] {
            BuildSeverityCard(assessments),
            BuildCategoryCard(assessments),
            BuildCoverageCard(assessments)
        };
    }

    public static IReadOnlyList<string> BuildPreviewLines(IReadOnlyList<DomainDetective.Assessment>? assessments, int count = 5) {
        if (assessments == null || assessments.Count == 0) {
            return Array.Empty<string>();
        }

        return assessments
            .OrderByDescending(static assessment => GetSeverityWeight(assessment.Severity))
            .ThenBy(static assessment => string.IsNullOrWhiteSpace(assessment.Category) ? "General" : assessment.Category, StringComparer.OrdinalIgnoreCase)
            .ThenBy(static assessment => assessment.Code, StringComparer.OrdinalIgnoreCase)
            .Take(count)
            .Select(static assessment => BuildAssessmentSample(assessment))
            .ToArray();
    }

    private static DomainOverviewDetailCardView BuildSeverityCard(IReadOnlyList<DomainDetective.Assessment> assessments) {
        var errors = assessments.Count(static assessment => assessment.Severity == DomainDetective.AssessmentSeverity.Error);
        var warnings = assessments.Count(static assessment => assessment.Severity == DomainDetective.AssessmentSeverity.Warning);
        var infos = assessments.Count(static assessment => assessment.Severity == DomainDetective.AssessmentSeverity.Info);

        var samples = BuildPreviewLines(assessments, 3);

        return new DomainOverviewDetailCardView {
            Title = "Severity mix",
            ValueLabel = assessments.Count + " finding(s)",
            Summary = "DD assessments are grouped here by severity so the overview shows how much of the current result is error-driven, warning-driven, or informational.",
            Tags = new[] {
                "Errors: " + errors,
                "Warnings: " + warnings,
                "Info: " + infos
            },
            Samples = samples
        };
    }

    private static DomainOverviewDetailCardView BuildCategoryCard(IReadOnlyList<DomainDetective.Assessment> assessments) {
        var grouped = assessments
            .GroupBy(static assessment => string.IsNullOrWhiteSpace(assessment.Category) ? "General" : assessment.Category, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(static group => group.Count())
            .ThenBy(static group => group.Key, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var samples = grouped
            .Take(4)
            .Select(static group => $"{group.Key}: {group.Count()} finding(s)")
            .ToArray();

        return new DomainOverviewDetailCardView {
            Title = "Primary categories",
            ValueLabel = grouped.Length + " category(ies)",
            Summary = "These categories produced the most DD findings in the current overview and usually point to the main posture themes worth reviewing first.",
            Tags = grouped
                .Take(3)
                .Select(static group => group.Key)
                .ToArray(),
            Samples = samples
        };
    }

    private static DomainOverviewDetailCardView BuildCoverageCard(IReadOnlyList<DomainDetective.Assessment> assessments) {
        var sources = assessments
            .Select(static assessment => assessment.Source)
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var targets = assessments
            .Select(static assessment => assessment.Target)
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var samples = new List<string>();
        samples.AddRange(sources.Take(2).Select(static value => "Source: " + value));
        samples.AddRange(targets.Take(2).Select(static value => "Target: " + value));

        return new DomainOverviewDetailCardView {
            Title = "Assessment coverage",
            ValueLabel = targets.Length > 0 ? targets.Length + " target(s)" : "Overview-wide",
            Summary = "This shows how broadly the DD findings are distributed across concrete sources and targets instead of appearing only as generic summary messages.",
            Tags = new[] {
                "Sources: " + sources.Length,
                "Targets: " + targets.Length
            },
            Samples = samples.Take(4).ToArray()
        };
    }

    private static int GetSeverityWeight(DomainDetective.AssessmentSeverity severity) {
        return severity switch {
            DomainDetective.AssessmentSeverity.Error => 3,
            DomainDetective.AssessmentSeverity.Warning => 2,
            DomainDetective.AssessmentSeverity.Info => 1,
            _ => 0
        };
    }

    private static string BuildAssessmentSample(DomainDetective.Assessment assessment) {
        var category = string.IsNullOrWhiteSpace(assessment.Category) ? "General" : assessment.Category;
        var message = string.IsNullOrWhiteSpace(assessment.Message) ? "Assessment emitted without detail." : assessment.Message.Trim();
        if (message.Length > 140) {
            message = message[..137] + "...";
        }

        return $"{category}: {message}";
    }
}
