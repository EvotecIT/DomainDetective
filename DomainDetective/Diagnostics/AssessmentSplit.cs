using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

public static class AssessmentSplit
{
    /// <summary>
    /// Splits assessments into positive posture titles (Info) and remediation titles (Warning/Error), grouped by code.
    /// </summary>
    public static void SplitTitles(IEnumerable<Assessment> assessments, out List<string> positives, out List<string> remediations)
    {
        positives = new List<string>();
        remediations = new List<string>();
        if (assessments == null) return;
        var grouped = RecommendationEngine.GroupByCode(assessments);
        foreach (var g in grouped)
        {
            var title = string.IsNullOrWhiteSpace(g.Advice?.Title) ? (g.Instances.FirstOrDefault()?.Message ?? g.Code) : g.Advice.Title;
            if (g.MaxSeverity == AssessmentSeverity.Info) positives.Add(title);
            else remediations.Add(title);
        }
        positives = positives.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        remediations = remediations.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }
}

