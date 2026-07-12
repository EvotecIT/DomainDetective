using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static OpenResolverInfo Convert(OpenResolverAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        var openCount = analysis.ServerDetails?.Values.Count(v => v.Status == OpenResolverStatus.Open) ?? 0;
        var failedCount = analysis.ServerDetails?.Values.Count(v => v.Status == OpenResolverStatus.Failed || v.Status == OpenResolverStatus.Unknown) ?? 0;
        var total = analysis.ServerDetails?.Count ?? 0;
        return new OpenResolverInfo
        {
            Check = HealthCheckType.OPENRESOLVER,
            Area = AreaForKind(HealthCheckType.OPENRESOLVER),
            Subject = analysis.Subject,
            TotalChecked = total,
            OpenResolvers = openCount,
            FailedChecks = failedCount,
            Details = analysis.ServerDetails ?? new Dictionary<string, OpenResolverResult>(),
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"open {openCount}/{total}, failed {failedCount}",
            Recommendations = recs,
            Positives = positives,
            References = new [] { "https://www.us-cert.gov/ncas/alerts/TA13-088A" },
            Raw = analysis
        };
    }
}

/// <summary>Provides open resolver info functionality.</summary>
public class OpenResolverInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the total checked value.</summary>
    public int TotalChecked { get; set; }
    /// <summary>Gets or sets the open resolvers value.</summary>
    public int OpenResolvers { get; set; }
    /// <summary>Gets or sets the number of failed or inconclusive probes.</summary>
    public int FailedChecks { get; set; }
    /// <summary>Gets or sets the details value.</summary>
    public IReadOnlyDictionary<string, OpenResolverResult> Details { get; set; } = null!;
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
    public OpenResolverAnalysis Raw { get; set; } = null!;
}
