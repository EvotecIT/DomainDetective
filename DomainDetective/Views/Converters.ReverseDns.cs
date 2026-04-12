using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static ReverseDnsInfo Convert(ReverseDnsAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        var total = analysis.Results?.Count ?? 0;
        var valid = analysis.Results?.Count(r => r.IsValid) ?? 0;
        return new ReverseDnsInfo
        {
            Check = HealthCheckType.REVERSEDNS,
            Area = AreaForKind(HealthCheckType.REVERSEDNS),
            Subject = analysis.Subject,
            ResultsCount = total,
            ValidCount = valid,
            AllValid = analysis.AllValid,
            Results = analysis.Results ?? new List<ReverseDnsAnalysis.ReverseDnsResult>(),
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"{valid}/{total} PTR match; FCrDNS {(analysis.Results?.Count(r => r.FcrDnsValid) ?? 0)}/{total}",
            Recommendations = recs,
            Positives = positives,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc1912" },
            Raw = analysis
        };
    }
}

/// <summary>Provides reverse dns info functionality.</summary>
public class ReverseDnsInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the results count value.</summary>
    public int ResultsCount { get; set; }
    /// <summary>Gets or sets the valid count value.</summary>
    public int ValidCount { get; set; }
    /// <summary>Gets or sets the all valid value.</summary>
    public bool AllValid { get; set; }
    /// <summary>Gets or sets the results value.</summary>
    public IReadOnlyList<ReverseDnsAnalysis.ReverseDnsResult> Results { get; set; } = null!;
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
    public ReverseDnsAnalysis Raw { get; set; } = null!;
}
