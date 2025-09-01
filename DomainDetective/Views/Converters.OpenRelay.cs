using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static OpenRelayInfo Convert(OpenRelayAnalysis analysis)
    {
        var assessments = analysis.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(assessments);
        var total = analysis.ServerResults?.Count ?? 0;
        var allows = analysis.ServerResults?.Count(kv => kv.Value?.Status == OpenRelayStatus.AllowsRelay) ?? 0;
        return new OpenRelayInfo
        {
            Check = HealthCheckType.OPENRELAY,
            Area = AreaForKind(HealthCheckType.OPENRELAY),
            Subject = null,
            TotalChecked = total,
            OpenAllowed = allows,
            Results = analysis.ServerResults,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"allows {allows}/{total}",
            Recommendations = recs,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

public class OpenRelayInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public int TotalChecked { get; set; }
    public int OpenAllowed { get; set; }
    public IReadOnlyDictionary<string, OpenRelayAnalysis.OpenRelayResult> Results { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public OpenRelayAnalysis Raw { get; set; }
}
