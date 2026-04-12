using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static FcrDnsInfo Convert(FCrDnsAnalysis analysis)
    {
        // FCrDnsAnalysis does not expose assessments; derive a simple status
        var assessments = new List<Assessment>();
        var total = analysis.Results?.Count ?? 0;
        var valid = analysis.Results?.Count(r => r.ForwardConfirmed) ?? 0;
        string status = total == valid ? "OK" : (valid > 0 ? "Warning" : "Error");
        int warn = (total > valid && valid > 0) ? 1 : 0;
        int err = (valid == 0 && total > 0) ? 1 : 0;
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);
        return new FcrDnsInfo
        {
            Check = HealthCheckType.FCRDNS,
            Area = AreaForKind(HealthCheckType.FCRDNS),
            Subject = analysis.Subject,
            TotalChecked = total,
            ForwardConfirmed = valid,
            Results = analysis.Results ?? new List<FCrDnsAnalysis.FCrDnsResult>(),
            Assessments = assessments,
            Status = status,
            WarningCount = warn,
            ErrorCount = err,
            Summary = $"{valid}/{total} forward-confirmed",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

/// <summary>Provides fcr dns info functionality.</summary>
public class FcrDnsInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the total checked value.</summary>
    public int TotalChecked { get; set; }
    /// <summary>Gets or sets the forward confirmed value.</summary>
    public int ForwardConfirmed { get; set; }
    /// <summary>Gets or sets the results value.</summary>
    public IReadOnlyList<FCrDnsAnalysis.FCrDnsResult> Results { get; set; } = null!;
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
    public FCrDnsAnalysis Raw { get; set; } = null!;
}
