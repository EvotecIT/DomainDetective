using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static RpkiInfo Convert(RPKIAnalysis analysis)
    {
        var assessments = analysis.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);
        var total = analysis.Results?.Count ?? 0;
        var valid = analysis.Results?.Count(r => r.Valid) ?? 0;
        return new RpkiInfo
        {
            Check = HealthCheckType.RPKI,
            Area = AreaForKind(HealthCheckType.RPKI),
            Subject = analysis.Subject,
            TotalChecked = total,
            ValidCount = valid,
            AllValid = analysis.AllValid,
            Results = analysis.Results ?? new List<RPKIResult>(),
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"valid {valid}/{total}",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

/// <summary>Provides rpki info functionality.</summary>
public class RpkiInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the total checked value.</summary>
    public int TotalChecked { get; set; }
    /// <summary>Gets or sets the valid count value.</summary>
    public int ValidCount { get; set; }
    /// <summary>Gets or sets the all valid value.</summary>
    public bool AllValid { get; set; }
    /// <summary>Gets or sets the results value.</summary>
    public IReadOnlyList<RPKIResult> Results { get; set; } = null!;
    /// <summary>Gets or sets the assessments value.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = null!;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = null!;
    /// <summary>Gets or sets the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    /// <summary>Gets or sets the positives value.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    /// <summary>Gets or sets the references value.</summary>
    public IReadOnlyList<string> References { get; set; } = null!;
    /// <summary>Gets or sets the raw value.</summary>
    public RPKIAnalysis Raw { get; set; } = null!;
}
