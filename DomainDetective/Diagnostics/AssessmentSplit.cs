using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

public static class AssessmentSplit
{
    /// <summary>
    /// Splits assessments into positive (Info), negative (Warning), and remediation (Error) titles grouped by code.
    /// </summary>
    public static void SplitTitles(IEnumerable<Assessment> assessments, out List<string> positives, out List<string> negatives, out List<string> remediations)
    {
        positives = new List<string>();
        negatives = new List<string>();
        remediations = new List<string>();
        if (assessments == null) return;
        var grouped = RecommendationEngine.GroupByCode(assessments);
        foreach (var g in grouped)
        {
            var adviceTitle = g.Advice?.Title;
            var title = string.IsNullOrWhiteSpace(adviceTitle) ? (g.Instances.FirstOrDefault()?.Message ?? g.Code ?? string.Empty) : adviceTitle;
            if (g.MaxSeverity == AssessmentSeverity.Info)
            {
                positives.Add(title ?? string.Empty);
            }
            else if (g.MaxSeverity == AssessmentSeverity.Warning)
            {
                negatives.Add(title ?? string.Empty);
            }
            else
            {
                remediations.Add(title ?? string.Empty);
            }
        }
        positives = positives.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        negatives = negatives.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        remediations = remediations.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }
}
