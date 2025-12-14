using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static MailLatencyInfo Convert(MailLatencyAnalysis analysis)
    {
        // No explicit assessments emitted; treat failures as warnings based on results
        var assessments = new List<Assessment>();
        var serverResults = analysis.ServerResults;
        int warn = 0;
        foreach (var kv in serverResults) {
            if (!kv.Value.ConnectSuccess) warn++;
        }
        string status = warn > 0 ? "Warning" : "OK";
        string? subject = null;
        if (serverResults.Count == 1)
        {
            foreach (var key in serverResults.Keys) { subject = key; break; }
        }
        var averageConnectMs = serverResults.Count == 0 ? 0 : (int)serverResults.Values.Average(v => v.ConnectTime.TotalMilliseconds);
        var averageBannerMs = serverResults.Count == 0 ? 0 : (int)serverResults.Values.Average(v => v.BannerTime.TotalMilliseconds);
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);
        return new MailLatencyInfo
        {
            Check = HealthCheckType.MAILLATENCY,
            Area = AreaForKind(HealthCheckType.MAILLATENCY),
            Subject = subject,
            Servers = serverResults,
            AverageConnectMs = averageConnectMs,
            AverageBannerMs = averageBannerMs,
            Assessments = assessments,
            Status = status,
            WarningCount = warn,
            ErrorCount = 0,
            Summary = $"avg conn {averageConnectMs} ms; avg banner {averageBannerMs} ms",
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
    public string? Subject { get; set; }
    public int AverageConnectMs { get; set; }
    public int AverageBannerMs { get; set; }
    public IReadOnlyDictionary<string, MailLatencyAnalysis.LatencyResult> Servers { get; set; } = null!;
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public MailLatencyAnalysis Raw { get; set; } = null!;
}
