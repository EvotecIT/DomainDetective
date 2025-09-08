using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static MailLatencyInfo Convert(MailLatencyAnalysis analysis)
    {
        // No explicit assessments emitted; treat failures as warnings based on results
        var assessments = new List<Assessment>();
        int warn = 0;
        foreach (var kv in analysis.ServerResults) {
            if (!kv.Value.ConnectSuccess) warn++;
        }
        string status = warn > 0 ? "Warning" : "OK";
        string subject = null;
        if (analysis.ServerResults != null && analysis.ServerResults.Count == 1)
        {
            foreach (var key in analysis.ServerResults.Keys) { subject = key; break; }
        }
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);
        return new MailLatencyInfo
        {
            Check = HealthCheckType.MAILLATENCY,
            Area = AreaForKind(HealthCheckType.MAILLATENCY),
            Subject = subject,
            Servers = analysis.ServerResults,
            AverageConnectMs = analysis.ServerResults.Count == 0 ? 0 : (int)analysis.ServerResults.Values.Average(v => v.ConnectTime.TotalMilliseconds),
            AverageBannerMs = analysis.ServerResults.Count == 0 ? 0 : (int)analysis.ServerResults.Values.Average(v => v.BannerTime.TotalMilliseconds),
            Assessments = assessments,
            Status = status,
            WarningCount = warn,
            ErrorCount = 0,
            Summary = $"avg conn { (analysis.ServerResults.Count==0?0:(int)analysis.ServerResults.Values.Average(v => v.ConnectTime.TotalMilliseconds)) } ms; avg banner { (analysis.ServerResults.Count==0?0:(int)analysis.ServerResults.Values.Average(v => v.BannerTime.TotalMilliseconds)) } ms",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

public class MailLatencyInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public int AverageConnectMs { get; set; }
    public int AverageBannerMs { get; set; }
    public IReadOnlyDictionary<string, MailLatencyAnalysis.LatencyResult> Servers { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public MailLatencyAnalysis Raw { get; set; }
}
