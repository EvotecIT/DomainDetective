using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
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

/// <summary>Provides mail latency info functionality.</summary>
public class MailLatencyInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the average connect ms value.</summary>
    public int AverageConnectMs { get; set; }
    /// <summary>Gets or sets the average banner ms value.</summary>
    public int AverageBannerMs { get; set; }
    /// <summary>Gets or sets the servers value.</summary>
    public IReadOnlyDictionary<string, MailLatencyAnalysis.LatencyResult> Servers { get; set; } = null!;
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
    public MailLatencyAnalysis Raw { get; set; } = null!;
}
