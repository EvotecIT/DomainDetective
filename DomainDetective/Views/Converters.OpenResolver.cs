using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static OpenResolverInfo Convert(OpenResolverAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(analysis.Assessments);
        var openCount = analysis.ServerDetails?.Values.Count(v => v.IsOpenResolver) ?? 0;
        var total = analysis.ServerDetails?.Count ?? 0;
        return new OpenResolverInfo
        {
            Check = HealthCheckType.OPENRESOLVER,
            Area = AreaForKind(HealthCheckType.OPENRESOLVER),
            Subject = analysis.Subject,
            TotalChecked = total,
            OpenResolvers = openCount,
            Details = analysis.ServerDetails,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"open {openCount}/{total}",
            Recommendations = recs,
            References = new [] { "https://www.us-cert.gov/ncas/alerts/TA13-088A" },
            Raw = analysis
        };
    }
}

public class OpenResolverInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public int TotalChecked { get; set; }
    public int OpenResolvers { get; set; }
    public IReadOnlyDictionary<string, OpenResolverResult> Details { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public OpenResolverAnalysis Raw { get; set; }
}
