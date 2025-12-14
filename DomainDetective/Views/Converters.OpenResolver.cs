using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static OpenResolverInfo Convert(OpenResolverAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        var openCount = analysis.ServerDetails?.Values.Count(v => v.IsOpenResolver) ?? 0;
        var total = analysis.ServerDetails?.Count ?? 0;
        return new OpenResolverInfo
        {
            Check = HealthCheckType.OPENRESOLVER,
            Area = AreaForKind(HealthCheckType.OPENRESOLVER),
            Subject = analysis.Subject,
            TotalChecked = total,
            OpenResolvers = openCount,
            Details = analysis.ServerDetails ?? new Dictionary<string, OpenResolverResult>(),
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"open {openCount}/{total}",
            Recommendations = recs,
            Positives = positives,
            References = new [] { "https://www.us-cert.gov/ncas/alerts/TA13-088A" },
            Raw = analysis
        };
    }
}

public class OpenResolverInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public int TotalChecked { get; set; }
    public int OpenResolvers { get; set; }
    public IReadOnlyDictionary<string, OpenResolverResult> Details { get; set; } = null!;
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public OpenResolverAnalysis Raw { get; set; } = null!;
}
