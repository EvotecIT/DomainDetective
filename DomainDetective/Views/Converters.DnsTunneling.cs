using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static DnsTunnelingInfo Convert(DnsTunnelingAnalysis analysis)
    {
        var assessments = analysis.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);
        return new DnsTunnelingInfo
        {
            Check = HealthCheckType.DNSTUNNELING,
            Area = AreaForKind(HealthCheckType.DNSTUNNELING),
            Subject = analysis.Subject,
            Alerts = analysis.Alerts,
            AlertCount = analysis.Alerts?.Count ?? 0,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"alerts {analysis.Alerts?.Count ?? 0}",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

public class DnsTunnelingInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public int AlertCount { get; set; }
    public IReadOnlyList<DnsTunnelingAlert> Alerts { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public DnsTunnelingAnalysis Raw { get; set; }
}
