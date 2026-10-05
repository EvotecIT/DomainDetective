using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Reports;

/// <summary>Preserves assessments from completed checks that do not have a dedicated composition section.</summary>
public sealed class AssessmentEvidenceInfo {
    /// <summary>Run subject used for grouping; individual finding targets remain intact.</summary>
    public string Subject { get; }
    /// <summary>Complete additional findings, prioritized by severity.</summary>
    public IReadOnlyList<Assessment> Assessments { get; }
    /// <summary>Actionable catalog advice for these findings.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; }
    /// <summary>Number of warnings.</summary>
    public int WarningCount => Assessments.Count(a => a.Severity == AssessmentSeverity.Warning);
    /// <summary>Number of errors.</summary>
    public int ErrorCount => Assessments.Count(a => a.Severity == AssessmentSeverity.Error);
    /// <summary>Creates a format-independent additional-assessment section.</summary>
    public AssessmentEvidenceInfo(string subject, IEnumerable<Assessment> assessments) {
        Subject = subject ?? throw new ArgumentNullException(nameof(subject));
        Assessments = (assessments ?? throw new ArgumentNullException(nameof(assessments))).OrderByDescending(a => a.Severity).ToArray();
        Recommendations = RecommendationEngine.FromProblems(Assessments);
    }

    private AssessmentEvidenceInfo(string subject, IEnumerable<Assessment> assessments, IEnumerable<RecommendationAdvice> recommendations) : this(subject, assessments) {
        Recommendations = recommendations.GroupBy(action => new { action.Code, action.Title, action.Why, action.How, action.Verify }).Select(group => group.First()).ToArray();
    }

    /// <summary>Collects complete findings and supplied advice independently of format-specific technical section coverage.</summary>
    public static IReadOnlyList<AssessmentEvidenceInfo> Collect(IReadOnlyList<object> items) {
        if (items == null) { throw new ArgumentNullException(nameof(items)); }
        var groups = new Dictionary<string, (List<Assessment> Findings, List<RecommendationAdvice> Actions)>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in CompositionUtilities.Flatten(items)) {
            var subject = item.GetType().GetProperty("Subject")?.GetValue(item) as string;
            if (string.IsNullOrWhiteSpace(subject)) { continue; }
            var findings = item.GetType().GetProperty("Assessments")?.GetValue(item) as IEnumerable<Assessment> ?? Array.Empty<Assessment>();
            var actions = item.GetType().GetProperty("Recommendations")?.GetValue(item) as IEnumerable<RecommendationAdvice> ?? RecommendationEngine.FromProblems(findings);
            if (!groups.TryGetValue(subject!, out var group)) { groups[subject!] = group = (new List<Assessment>(), new List<RecommendationAdvice>()); }
            group.Findings.AddRange(findings);
            group.Actions.AddRange(actions);
        }
        return groups.Where(pair => pair.Value.Findings.Count > 0 || pair.Value.Actions.Count > 0)
            .Select(pair => new AssessmentEvidenceInfo(pair.Key, pair.Value.Findings.Distinct(), pair.Value.Actions)).ToArray();
    }
}
