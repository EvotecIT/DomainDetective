using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

public static class AssessmentSplit
{
    /// <summary>
    /// Splits assessments into positives (Info), negatives (Warning), and remediations (Error) titles, grouped by code.
    /// </summary>
    public static (List<string> positives, List<string> negatives, List<string> remediations) SplitTitles(
        IEnumerable<Assessment>? assessments)
    {
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();
        if (assessments == null)
        {
            return (positives, negatives, remediations);
        }
        var grouped = RecommendationEngine.GroupByCode(assessments);
        foreach (var g in grouped)
        {
            var adviceTitle = g.Advice?.Title;
            var title = string.IsNullOrWhiteSpace(adviceTitle)
                ? (g.Instances.FirstOrDefault()?.Message ?? g.Code ?? string.Empty)
                : adviceTitle;
            if (g.MaxSeverity == AssessmentSeverity.Info)
            {
                positives.Add(title ?? string.Empty);
            }
            else if (g.MaxSeverity == AssessmentSeverity.Warning)
            {
                negatives.Add(title ?? string.Empty);
            }
            else if (g.MaxSeverity == AssessmentSeverity.Error)
            {
                remediations.Add(title ?? string.Empty);
            }
        }
        positives = positives.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        negatives = negatives.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        remediations = remediations.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        return (positives, negatives, remediations);
    }
}

