using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static HttpInfo Convert(HttpAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(analysis.Assessments);
        return new HttpInfo
        {
            Check = "HTTP",
            Subject = analysis.Subject,
            Url = analysis.Subject,
            IsReachable = analysis.IsReachable,
            StatusCode = analysis.StatusCode,
            ResponseTime = analysis.ResponseTime,
            HstsPresent = analysis.HstsPresent,
            HstsPreloaded = analysis.HstsPreloaded,
            HstsPreloadEligible = analysis.HstsPreloadEligible,
            Http2Supported = analysis.Http2Supported,
            Http3Supported = analysis.Http3Supported,
            MissingSecurityHeaders = analysis.MissingSecurityHeaders,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Recommendations = recs,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

public class HttpInfo
{
    public string Check { get; set; }
    public string Subject { get; set; }
    public string Url { get; set; }
    public bool IsReachable { get; set; }
    public int? StatusCode { get; set; }
    public System.TimeSpan ResponseTime { get; set; }
    public bool HstsPresent { get; set; }
    public bool HstsPreloaded { get; set; }
    public bool HstsPreloadEligible { get; set; }
    public bool Http2Supported { get; set; }
    public bool Http3Supported { get; set; }
    public IReadOnlyCollection<string> MissingSecurityHeaders { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public HttpAnalysis Raw { get; set; }
}

