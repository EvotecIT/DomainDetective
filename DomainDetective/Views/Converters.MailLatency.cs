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
        return new MailLatencyInfo
        {
            Check = "LATENCY",
            Subject = null,
            Servers = analysis.ServerResults,
            AverageConnectMs = analysis.ServerResults.Count == 0 ? 0 : (int)analysis.ServerResults.Values.Average(v => v.ConnectTime.TotalMilliseconds),
            AverageBannerMs = analysis.ServerResults.Count == 0 ? 0 : (int)analysis.ServerResults.Values.Average(v => v.BannerTime.TotalMilliseconds),
            Assessments = assessments,
            Status = status,
            WarningCount = warn,
            ErrorCount = 0,
            Recommendations = RecommendationEngine.From(assessments),
            References = BuildReferences(System.Array.Empty<StandardReference>(), RecommendationEngine.From(assessments)),
            Raw = analysis
        };
    }
}

public class MailLatencyInfo
{
    public string Check { get; set; }
    public string Subject { get; set; }
    public int AverageConnectMs { get; set; }
    public int AverageBannerMs { get; set; }
    public IReadOnlyDictionary<string, MailLatencyAnalysis.LatencyResult> Servers { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public MailLatencyAnalysis Raw { get; set; }
}

